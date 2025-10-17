# -*- coding: utf-8 -*-
"""
PDF 레닥션 엔진 (PyMuPDF)
- routes_redaction.py 와 완전 호환:
  detect_boxes_from_patterns(pdf_bytes, patterns: List[PatternItem]) -> List[Box]
  apply_redaction(pdf_bytes, boxes: List[Box], fill: Literal["black","white"]) -> bytes

핵심 포인트
- 이메일: '@'만 남기고 나머지(로컬파트·도메인·점 포함) 전부 가림
  * PyMuPDF 버전마다 page.get_text("chars") 지원이 달라 AssertionError가 날 수 있어
    문자 단위 bbox는 사용하지 않고, **이메일을 '@' 기준으로 분해한 세그먼트**를
    이메일 전체 bbox 내부에서 search_for로 다시 찾아 그 영역을 가리는 방식으로 호환 처리.
- 카드: 숫자/하이픈/공백 토큰 버퍼링 → 숫자만 추출 → 15~16자리 + Luhn/IIN validator
- 최종 적용은 PyMuPDF 버전에 따라 문서 단위(doc.apply_redactions) 또는 페이지 단위(page.apply_redactions)로 호환 처리
"""

from __future__ import annotations

import io
import re
import logging
from typing import List, Tuple, Optional, Dict

import fitz  # PyMuPDF

from .schemas import Box, PatternItem
from .validators import is_valid_email, is_valid_card

# --------------------------------------------------------------------
# 로거
# --------------------------------------------------------------------
logger = logging.getLogger("redaction")
if not logger.handlers:
    logger.setLevel(logging.DEBUG)
    _h = logging.StreamHandler()
    _h.setLevel(logging.DEBUG)
    _h.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    logger.addHandler(_h)

# --------------------------------------------------------------------
# 내부 유틸
# --------------------------------------------------------------------
DASH_CHARS = {"–", "−", "‒", "―", "—"}  # 다양한 대시

def _normalize_dash(s: str) -> str:
    for ch in DASH_CHARS:
        s = s.replace(ch, "-")
    return s

def _compile_pattern(p: PatternItem) -> re.Pattern:
    flags = 0 if getattr(p, "case_sensitive", False) else re.IGNORECASE
    pattern = p.regex
    if getattr(p, "whole_word", False):
        pattern = rf"\b(?:{pattern})\b"
    logger.debug("Compiling pattern: %s -> %s", getattr(p, "name", "?"), pattern)
    return re.compile(pattern, flags)

def _page_words(page: fitz.Page) -> List[Tuple[float, float, float, float, str, int, int, int]]:
    """
    page.get_text('words') → (x0, y0, x1, y1, text, block_no, line_no, word_no)
    """
    words = page.get_text("words") or []
    words.sort(key=lambda w: (w[5], w[6], w[7]))  # 읽기 순서
    return words

def _joinable_token(t: str) -> bool:
    if not t:
        return False
    t = _normalize_dash(t)
    return bool(re.fullmatch(r"[0-9\- ]+", t))

def _word_spans_to_rects(words: List[tuple], spans: List[Tuple[int, int]]) -> List[fitz.Rect]:
    rects: List[fitz.Rect] = []
    for s, e in spans:
        if s < 0 or e > len(words) or s >= e:
            continue
        chunk = words[s:e]
        x0 = min(w[0] for w in chunk); y0 = min(w[1] for w in chunk)
        x1 = max(w[2] for w in chunk); y1 = max(w[3] for w in chunk)
        rects.append(fitz.Rect(x0, y0, x1, y1))
    return rects

def _build_box(page: int, rect: fitz.Rect, pattern_name: str, matched_text: str, valid: bool = True) -> Box:
    # schemas.Box에 맞춰 필드 구성 (pattern_name / value는 라우팅에서 사용)
    return Box(
        page=page,
        x0=float(rect.x0), y0=float(rect.y0),
        x1=float(rect.x1), y1=float(rect.y1),
        pattern_name=pattern_name,
        value=matched_text,
        valid=valid,
    )

# --------------------------------------------------------------------
# 이메일 특수 처리: '@'만 남기고 문자 단위로 가리기(버전 호환)
# --------------------------------------------------------------------
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")

def _union_rect_of_quads(quads: list) -> Optional[fitz.Rect]:
    if not quads:
        return None
    x0 = min(q.rect.x0 for q in quads); y0 = min(q.rect.y0 for q in quads)
    x1 = max(q.rect.x1 for q in quads); y1 = max(q.rect.y1 for q in quads)
    return fitz.Rect(x0, y0, x1, y1)

def _search_within(page: fitz.Page, text: str, clip: Optional[fitz.Rect] = None) -> List[fitz.Rect]:
    """
    페이지에서 텍스트를 찾되, PyMuPDF 버전별로 quads 지원 유무를 안전하게 처리.
    clip 사각형이 주어지면 그 내부에서만 검색.
    """
    rects: List[fitz.Rect] = []
    try:
        # 최신: quads / clip 둘 다 지원
        quads = page.search_for(text, quads=True, clip=clip)  # type: ignore
        if quads:
            r = _union_rect_of_quads(quads)
            if r:
                rects.append(r)
    except TypeError:
        # 구버전: quads / clip 미지원 가능
        try:
            found = page.search_for(text) or []
            if clip:
                for r in found:
                    if r.intersects(clip):
                        rects.append(r & clip)
            else:
                rects.extend(found)
        except Exception as e:
            logger.debug("search_for fallback failed: %s", e)
    return rects

def _email_segment_rects(page: fitz.Page, email_rect: fitz.Rect, email_text: str) -> List[fitz.Rect]:
    """
    이메일을 '@' 기준으로 분해해 각 세그먼트를 email_rect 안에서 다시 검색.
    - '@' 세그먼트는 마스킹하지 않음
    - 나머지 세그먼트(로컬파트, 도메인 전체)는 모두 마스킹
    """
    targets: List[str] = []
    if "@" in email_text:
        left, right = email_text.split("@", 1)
        if left:  targets.append(left)
        if right: targets.append(right)
    else:
        # 혹시 정규식/엔진이 '@' 없는 문자열을 넘기면 전체 가림
        targets.append(email_text)

    out: List[fitz.Rect] = []
    for seg in targets:
        seg = seg.strip()
        if not seg:
            continue
        seg_rects = _search_within(page, seg, clip=email_rect)
        out.extend(seg_rects)
    return out

def _detect_emails(page: fitz.Page, words: List[tuple]) -> List[Tuple[fitz.Rect, str]]:
    """
    1) 페이지 텍스트에서 이메일 후보를 찾고
    2) 후보 전체 bbox를 구한 뒤
    3) '@' 기준 분해된 세그먼트들의 bbox만 모아서 리턴(= 가릴 부분)
    """
    text = page.get_text("text") or ""
    results: List[Tuple[fitz.Rect, str]] = []
    for m in _EMAIL_RE.finditer(text):
        candidate = m.group()
        if not is_valid_email(candidate):
            continue

        # 전체 후보 bbox
        email_rects = _search_within(page, candidate)
        if not email_rects:
            continue

        # 각 전체 bbox에 대해 세그먼트 영역 추출
        for er in email_rects:
            for rr in _email_segment_rects(page, er, candidate):
                results.append((rr, candidate))
    return results

# --------------------------------------------------------------------
# 카드 특수 처리
# --------------------------------------------------------------------
def _detect_cards(page: fitz.Page, words: List[tuple]) -> List[Tuple[fitz.Rect, str]]:
    results: List[Tuple[fitz.Rect, str]] = []
    i, n = 0, len(words)
    while i < n:
        t = _normalize_dash(words[i][4])
        if not _joinable_token(t):
            i += 1
            continue
        start = i
        buf = [t]; i += 1
        while i < n and _joinable_token(_normalize_dash(words[i][4])):
            buf.append(_normalize_dash(words[i][4]))
            i += 1
        raw = "".join(buf)
        digits = re.sub(r"\D", "", raw)
        if 15 <= len(digits) <= 16 and is_valid_card(raw):
            rects = _word_spans_to_rects(words, [(start, i)])
            if rects:
                x0 = min(r.x0 for r in rects); y0 = min(r.y0 for r in rects)
                x1 = max(r.x1 for r in rects); y1 = max(r.y1 for r in rects)
                results.append((fitz.Rect(x0, y0, x1, y1), raw))
    return results

# --------------------------------------------------------------------
# 일반 정규식 패턴
# --------------------------------------------------------------------
def _detect_by_regex(page: fitz.Page, words: List[tuple], pitem: PatternItem) -> List[Tuple[fitz.Rect, str]]:
    tokens = [w[4] for w in words]
    joined = " ".join(tokens)

    # char offset -> word index 근사 매핑
    word_starts = []
    off = 0
    for idx, tok in enumerate(tokens):
        word_starts.append((off, idx))
        off += len(tok) + 1  # 우리가 넣은 공백

    def char_to_word_index(ch: int) -> int:
        last_idx = 0
        for start_off, widx in word_starts:
            if start_off <= ch:
                last_idx = widx
            else:
                break
        return last_idx

    pattern = _compile_pattern(pitem)
    out: List[Tuple[fitz.Rect, str]] = []
    for m in pattern.finditer(joined):
        val = m.group()
        validator = getattr(pitem, "validator", None)
        ok = True
        if callable(validator):
            try:
                ok = bool(validator(val))
            except Exception as e:
                logger.debug("validator error for %s: %s", getattr(pitem, "name", "?"), e)
                ok = False
        if not ok:
            continue

        s_char, e_char = m.span()
        s_idx = char_to_word_index(s_char)
        e_idx = char_to_word_index(max(e_char - 1, s_char)) + 1
        rects = _word_spans_to_rects(words, [(s_idx, e_idx)])
        if rects:
            x0 = min(r.x0 for r in rects); y0 = min(r.y0 for r in rects)
            x1 = max(r.x1 for r in rects); y1 = max(r.y1 for r in rects)
            out.append((fitz.Rect(x0, y0, x1, y1), val))
    return out

# --------------------------------------------------------------------
# 공개: routes_redaction.py 호환 함수
# --------------------------------------------------------------------
def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem]) -> List[Box]:
    """
    입력: PDF 바이트 + PatternItem 리스트
    출력: List[Box] (pydantic 모델)
    """
    if patterns is None:
        patterns = []

    by_name: Dict[str, PatternItem] = {p.name: p for p in patterns if getattr(p, "name", None)}

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    for pno in range(doc.page_count):
        page = doc.load_page(pno)
        words = _page_words(page)

        # 이메일: '@' 제외 마스킹 영역 박스
        if "email" in by_name:
            email_boxes = _detect_emails(page, words)
            logger.debug("[PDF] page=%d emails=%d", pno, len(email_boxes))
            for rect, val in email_boxes:
                boxes.append(_build_box(pno, rect, "email", val, True))

        # 카드
        if "card" in by_name:
            card_boxes = _detect_cards(page, words)
            logger.debug("[PDF] page=%d cards=%d", pno, len(card_boxes))
            for rect, val in card_boxes:
                boxes.append(_build_box(pno, rect, "card", val, True))

        # 일반 정규식
        for name, pitem in by_name.items():
            if name in ("email", "card"):
                continue
            try:
                matches = _detect_by_regex(page, words, pitem)
            except re.error as e:
                logger.warning("Invalid regex for %s: %s", name, e)
                continue
            for rect, val in matches:
                boxes.append(_build_box(pno, rect, name, val, True))

    logger.debug("detect_boxes_from_patterns -> %d boxes", len(boxes))
    doc.close()
    return boxes

def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
    """
    감지된 Box들을 이용해 레닥션 적용 후 PDF 바이트 반환.
    - fill: "black" | "white"
    - PyMuPDF 버전 호환: 문서/페이지 단위 apply 모두 지원
    """
    if not boxes:
        logger.debug("apply_redaction called with 0 boxes — returning original PDF.")
        return pdf_bytes

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    color = (0, 0, 0) if fill.lower() == "black" else (1, 1, 1)

    # 페이지별 그룹화
    by_page: Dict[int, List[Box]] = {}
    for b in boxes:
        if hasattr(b, "valid") and not getattr(b, "valid"):
            continue
        by_page.setdefault(int(b.page), []).append(b)

    added = 0
    for pno, pboxes in by_page.items():
        page = doc.load_page(pno)
        for b in pboxes:
            rect = fitz.Rect(float(b.x0), float(b.y0), float(b.x1), float(b.y1))
            page.add_redact_annot(rect, fill=color)
            added += 1
    logger.debug("Added redact annotations: %d", added)

    # --- 버전 호환 적용 단계 ---
    if hasattr(doc, "apply_redactions"):
        # 최신 계열: 문서 단위 적용
        doc.apply_redactions()
    else:
        # 구버전: 페이지 단위 적용
        for p in doc:
            if hasattr(p, "apply_redactions"):
                p.apply_redactions()

    out = io.BytesIO()
    doc.save(out, garbage=4, deflate=True)
    doc.close()
    return out.getvalue()
