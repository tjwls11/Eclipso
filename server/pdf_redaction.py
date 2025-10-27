# -*- coding: utf-8 -*-
"""
PDF 레닥션 엔진 (PyMuPDF)
- routes_redaction.py 와 완전 호환:
  detect_boxes_from_patterns(pdf_bytes, patterns: List[PatternItem]) -> List[Box]
  apply_redaction(pdf_bytes, boxes: List[Box], fill: Literal["black","white"]) -> bytes

변경 사항 (정규식 미적용 문제 해결):
- 일반 정규식 탐지는 page.get_text("text")에서 regex로 매칭한 "실제 문자열"을
  다시 page.search_for()로 찾아 bbox를 얻는다. (단어 공백-조인으로 인한 미스매치 제거)
- RULES의 validator를 연결하여 유효성 검증 후에만 박스를 생성한다.
- 이메일은 '@'만 남기고 양쪽 세그먼트만 마스킹.
"""

from __future__ import annotations

import io
import re
import logging
from typing import List, Tuple, Optional, Dict, Callable

import fitz  # PyMuPDF

from .schemas import Box, PatternItem
from .validators import is_valid_email, is_valid_card  # 이메일/카드는 별도 로직에 사용
from .redac_rules import RULES  # name -> {regex, validator}

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

def _union_rect_of_quads(quads: list) -> Optional[fitz.Rect]:
    if not quads:
        return None
    x0 = min(q.rect.x0 for q in quads); y0 = min(q.rect.y0 for q in quads)
    x1 = max(q.rect.x1 for q in quads); y1 = max(q.rect.y1 for q in quads)
    return fitz.Rect(x0, y0, x1, y1)

def _search_within(page: fitz.Page, text: str, clip: Optional[fitz.Rect] = None) -> List[fitz.Rect]:
    rects: List[fitz.Rect] = []
    try:
        quads = page.search_for(text, quads=True, clip=clip)  # type: ignore
        if quads:
            r = _union_rect_of_quads(quads)
            if r:
                rects.append(r)
    except TypeError:
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

def _build_box(page: int, rect: fitz.Rect, pattern_name: str, matched_text: str, valid: bool = True) -> Box:
    return Box(
        page=page,
        x0=float(rect.x0), y0=float(rect.y0),
        x1=float(rect.x1), y1=float(rect.y1),
        pattern_name=pattern_name,
        value=matched_text,
        valid=valid,
    )

# --------------------------------------------------------------------
# 이메일: '@'만 남기고 마스킹
# --------------------------------------------------------------------
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")

def _email_segment_rects(page: fitz.Page, email_rect: fitz.Rect, email_text: str) -> List[fitz.Rect]:
    targets: List[str] = []
    if "@" in email_text:
        left, right = email_text.split("@", 1)
        if left:  targets.append(left)
        if right: targets.append(right)
    else:
        targets.append(email_text)

    out: List[fitz.Rect] = []
    for seg in targets:
        seg = seg.strip()
        if not seg:
            continue
        seg_rects = _search_within(page, seg, clip=email_rect)
        out.extend(seg_rects)
    return out

def _detect_emails(page: fitz.Page) -> List[Tuple[fitz.Rect, str]]:
    text = page.get_text("text") or ""
    results: List[Tuple[fitz.Rect, str]] = []
    for m in _EMAIL_RE.finditer(text):
        candidate = m.group()
        if not is_valid_email(candidate):
            continue
        # 전체 이메일 bbox
        email_rects = _search_within(page, candidate)
        if not email_rects:
            continue
        # '@' 양옆 세그먼트만 마스킹
        for er in email_rects:
            for rr in _email_segment_rects(page, er, candidate):
                results.append((rr, candidate))
    return results

# --------------------------------------------------------------------
# 카드: 토큰 버퍼링 유지 (공백/하이픈 포함)
# --------------------------------------------------------------------
def _page_words(page: fitz.Page):
    words = page.get_text("words") or []
    words.sort(key=lambda w: (w[5], w[6], w[7]))
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
# 일반 정규식 탐지(개선판)
#   1) page.get_text("text")에서 regex finditer
#   2) 매칭된 "리터럴 문자열"을 search_for로 찾아 bbox 획득
#   3) RULES[name]['validator']가 있으면 검사
# --------------------------------------------------------------------
def _detect_by_regex_literal(page: fitz.Page, name: str, pitem: PatternItem,
                             validator: Optional[Callable[[str, Optional[dict]], bool]] = None
                             ) -> List[Tuple[fitz.Rect, str]]:
    text = page.get_text("text") or ""
    pattern = _compile_pattern(pitem)
    out: List[Tuple[fitz.Rect, str]] = []
    for m in pattern.finditer(text):
        val = m.group()
        ok = True
        if callable(validator):
            try:
                ok = bool(validator(val, None))
            except TypeError:
                ok = bool(validator(val))  # 시그니처가 하나만 받는 경우 호환
            except Exception as e:
                logger.debug("validator error for %s: %s", name, e)
                ok = False
        if not ok:
            continue

        rects = _search_within(page, val)
        for r in rects:
            out.append((r, val))
    return out

# --------------------------------------------------------------------
# 공개 API
# --------------------------------------------------------------------
def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem]) -> List[Box]:
    if patterns is None:
        patterns = []

    # 패턴 이름 -> PatternItem
    by_name: Dict[str, PatternItem] = {p.name: p for p in patterns if getattr(p, "name", None)}
    # validator 매핑 (RULES 기준)
    name_to_validator: Dict[str, Callable] = {}
    for nm in by_name.keys():
        rule = RULES.get(nm)
        if rule and "validator" in rule:
            name_to_validator[nm] = rule["validator"]

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    for pno in range(doc.page_count):
        page = doc.load_page(pno)
        words = _page_words(page)

        # 이메일: '@' 제외 마스킹 영역
        if "email" in by_name:
            email_boxes = _detect_emails(page)
            logger.debug("[PDF] page=%d emails=%d", pno, len(email_boxes))
            for rect, val in email_boxes:
                boxes.append(_build_box(pno, rect, "email", val, True))

        # 카드
        if "card" in by_name:
            card_boxes = _detect_cards(page, words)
            logger.debug("[PDF] page=%d cards=%d", pno, len(card_boxes))
            for rect, val in card_boxes:
                boxes.append(_build_box(pno, rect, "card", val, True))

        # 일반 정규식 (email/card 제외)
        for name, pitem in by_name.items():
            if name in ("email", "card"):
                continue
            try:
                validator = name_to_validator.get(name)
                matches = _detect_by_regex_literal(page, name, pitem, validator)
            except re.error as e:
                logger.warning("Invalid regex for %s: %s", name, e)
                continue
            for rect, val in matches:
                boxes.append(_build_box(pno, rect, name, val, True))

    logger.debug("detect_boxes_from_patterns -> %d boxes", len(boxes))
    doc.close()
    return boxes

def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
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

    # 버전 호환 적용
    if hasattr(doc, "apply_redactions"):
        doc.apply_redactions()
    else:
        for p in doc:
            if hasattr(p, "apply_redactions"):
                p.apply_redactions()

    out = io.BytesIO()
    doc.save(out, garbage=4, deflate=True)
    doc.close()
    return out.getvalue()
