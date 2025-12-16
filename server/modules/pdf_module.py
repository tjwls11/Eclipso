from __future__ import annotations

import io
import re
from typing import List, Optional, Set, Dict, Any

import fitz  # PyMuPDF
import pymupdf4llm
import logging

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules.ner_module import run_ner
from server.core.regex_utils import match_text

from server.modules.ocr_easyocr import easyocr_blocks
from server.modules.ocr_qwen_post import classify_blocks_with_qwen
from PIL import Image


log_prefix = "[PDF]"
logger = logging.getLogger(__name__)


# ─────────────────────────────
# 기본 텍스트 추출 (/text/extract)
# ─────────────────────────────
def extract_text(file_bytes: bytes) -> dict:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    try:
        pages = []
        all_chunks: List[str] = []

        for idx, page in enumerate(doc):
            raw = page.get_text("text") or ""
            cleaned = raw.replace("\r", "")
            pages.append({"page": idx + 1, "text": cleaned})
            if cleaned:
                all_chunks.append(cleaned)

        full_text = "\n\n".join(all_chunks)

        return {
            "full_text": full_text,
            "pages": pages,
        }
    finally:
        doc.close()


# ─────────────────────────────
# 표 레이아웃 추출
# ─────────────────────────────
def extract_table_layout(pdf_bytes: bytes) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    tables: List[dict] = []

    try:
        for page_idx, page in enumerate(doc):
            finder = page.find_tables()
            if not finder or not finder.tables:
                continue

            for t in finder.tables:
                rect = fitz.Rect(t.bbox)
                tables.append(
                    {
                        "page": page_idx + 1,
                        "bbox": [rect.x0, rect.y0, rect.x1, rect.y1],
                        "row_count": t.row_count,
                        "col_count": t.col_count,
                    }
                )
    finally:
        doc.close()

    return {"tables": tables}


# ─────────────────────────────
# 마크다운 추출 (/text/markdown)
# ─────────────────────────────
def extract_markdown(pdf_bytes: bytes, by_page: bool = True) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        if by_page:
            chunks = pymupdf4llm.to_markdown(doc=doc, page_chunks=True)
            pages: List[dict] = []

            for idx, ch in enumerate(chunks, start=1):
                meta = ch.get("metadata", {}) or {}
                page_no = meta.get("page_number") or idx

                md = (ch.get("text") or "").replace("<br>", "")
                raw_tables = ch.get("tables", []) or []
                tables: List[dict] = []

                for t in raw_tables:
                    bbox = t.get("bbox")
                    rows = t.get("rows") or t.get("row_count")
                    cols = t.get("columns") or t.get("col_count")
                    if not bbox or rows is None or cols is None:
                        continue
                    tables.append(
                        {
                            "bbox": list(bbox),
                            "row_count": int(rows),
                            "col_count": int(cols),
                        }
                    )

                pages.append(
                    {
                        "page": page_no,
                        "markdown": md,
                        "tables": tables,
                    }
                )

            full_md = "\n\n".join(p["markdown"] for p in pages if p["markdown"])
            return {"markdown": full_md, "pages": pages}
        else:
            md = pymupdf4llm.to_markdown(doc=doc).replace("<br>", "\n")
            return {"markdown": md, "pages": []}
    finally:
        doc.close()


# ─────────────────────────────
# 패턴 기반 박스 탐지
# ─────────────────────────────
def _normalize_pattern_names(patterns: List[PatternItem] | None) -> Optional[Set[str]]:
    if not patterns:
        return None
    names: Set[str] = set()
    for p in patterns:
        nm = getattr(p, "name", None) or getattr(p, "rule", None)
        if nm:
            names.add(nm)
    return names or None


def _is_valid_value(need_valid: bool, validator, value: str) -> bool:
    if not need_valid or not callable(validator):
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            # validator(val, ctx) 형태일 수도 있음
            return bool(validator(value, None))
    except Exception:
        print(f"{log_prefix} VALIDATOR ERROR", repr(value))
        return False


def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem] | None) -> List[Box]:
    from server.modules.common import compile_rules  # lazy import

    comp = compile_rules()
    allowed_names = _normalize_pattern_names(patterns)

    print(
        f"{log_prefix} detect_boxes_from_patterns: rules 준비 완료",
        "allowed_names=",
        sorted(allowed_names) if allowed_names else "ALL",
    )

    stats_ok: Dict[str, int] = {}
    stats_fail: Dict[str, int] = {}

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    try:
        for pno, page in enumerate(doc):
            text = page.get_text("text") or ""
            if not text:
                continue

            for (rule_name, rx, need_valid, _prio, validator) in comp:
                if allowed_names and rule_name not in allowed_names:
                    continue

                try:
                    it = rx.finditer(text)
                except Exception:
                    continue

                for m in it:
                    val = m.group(0)
                    if not val:
                        continue

                    ok = _is_valid_value(need_valid, validator, val)

                    if ok:
                        stats_ok[rule_name] = stats_ok.get(rule_name, 0) + 1
                    else:
                        stats_fail[rule_name] = stats_fail.get(rule_name, 0) + 1

                    print(
                        f"{log_prefix} MATCH",
                        "page=",
                        pno + 1,
                        "rule=",
                        rule_name,
                        "need_valid=",
                        need_valid,
                        "ok=",
                        ok,
                        "value=",
                        repr(val),
                    )

                    if not ok:
                        continue

                    rects = page.search_for(val)
                    for r in rects:
                        print(
                            f"{log_prefix} BOX",
                            "page=",
                            pno + 1,
                            "rule=",
                            rule_name,
                            "rect=",
                            (r.x0, r.y0, r.x1, r.y1),
                        )
                        boxes.append(
                            Box(
                                page=pno,
                                x0=r.x0,
                                y0=r.y0,
                                x1=r.x1,
                                y1=r.y1,
                            )
                        )
    finally:
        doc.close()

    print(
        f"{log_prefix} detect summary",
        "OK=",
        {k: v for k, v in sorted(stats_ok.items())},
        "FAIL=",
        {k: v for k, v in sorted(stats_fail.items())},
        "boxes=",
        len(boxes),
    )

    return boxes


# ─────────────────────────────
# OCR + Qwen 기반 박스 탐지 (이미지/차트 위주)
# ─────────────────────────────
def _page_to_pil(page: fitz.Page, dpi: int = 120) -> Image.Image:
    mat = fitz.Matrix(dpi / 72, dpi / 72)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
    return img


def _group_rows_by_y(blocks: List[Dict[str, Any]], row_tol: float = 35.0) -> List[List[Dict[str, Any]]]:
    """
    EasyOCR bbox (pixel 좌표) 기준으로, y-center 가 비슷한 박스들을 같은 행(row)으로 묶는다.
    row_tol: 같은 행으로 볼 최대 center-y 차이(픽셀 단위).
    """
    if not blocks:
        return []

    enriched: List[Dict[str, Any]] = []
    for b in blocks:
        x0, y0, x1, y1 = b.get("bbox", [0, 0, 0, 0])
        cy = 0.5 * (float(y0) + float(y1))
        bb = dict(b)
        bb["_cy"] = cy
        enriched.append(bb)

    enriched.sort(key=lambda b: b["_cy"])

    rows: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    last_cy: Optional[float] = None

    for b in enriched:
        cy = b["_cy"]
        if last_cy is None or abs(cy - last_cy) <= row_tol:
            current.append(b)
        else:
            rows.append(current)
            current = [b]
        last_cy = cy

    if current:
        rows.append(current)

    for row in rows:
        for b in row:
            b.pop("_cy", None)

    # x0 기준으로 각 row 내부 정렬(후처리에서 "오른쪽 값" 판단 용이)
    for row in rows:
        row.sort(key=lambda b: float((b.get("bbox") or [0, 0, 0, 0])[0]))

    return rows


def _text_for_post(b: Dict[str, Any]) -> str:
    return str(b.get("normalized") or b.get("text") or "").strip()


def _count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)


def _looks_value_like(s: str) -> bool:
    # 숫자/기호 기반 값(전화/카드/ID) 또는 이메일 도메인/접미사 조각
    if not s:
        return False
    if "@" in s:
        return True
    d = _count_digits(s)
    if d >= 2:
        return True
    if "-" in s or "." in s:
        # 짧은 접미사("com") 같은 건 아래에서 별도로 처리
        return d >= 1
    # "com" 같은 것: 글자만 2~4자
    if 2 <= len(s) <= 4 and s.isalpha():
        return True
    return False


def _is_incomplete_sensitive(kind: str, text: str) -> bool:
    t = text.strip()
    if not t:
        return False

    if kind == "card":
        # 카드번호가 줄바꿈으로 쪼개지는 케이스(예: ...-68 / 76)
        digits = _count_digits(t)
        return 10 <= digits <= 15
    if kind == "email":
        # '...@naver.' + 'com' 같이 끊긴 케이스
        if "@" not in t:
            return False
        return t.endswith(".") or (re.search(r"\.[A-Za-z]{2,4}$", t) is None)
    return False


def _promote_value_like_in_rows(blocks: List[Dict[str, Any]]) -> None:
    """
    같은 행(row)에서 '값'으로 보이는 블록만 민감정보로 승격.
    (라벨 텍스트 전체가 가려지는 문제를 막기 위해, "값처럼 보이는 것"만 올린다)
    """
    SENSITIVE = {"card", "phone", "email", "id"}

    rows = _group_rows_by_y(blocks, row_tol=35.0)
    for row in rows:
        sens = [b for b in row if (b.get("kind") in SENSITIVE)]
        if not sens:
            continue

        # 값 블록은 보통 라벨 블록보다 오른쪽에 있음 → 민감 블록의 최소 x0를 기준으로 필터링
        sens_min_x0 = min(float((b.get("bbox") or [0, 0, 0, 0])[0]) for b in sens)

        for b in row:
            if (b.get("kind") in (None, "", "none")):
                t = _text_for_post(b)
                if not _looks_value_like(t):
                    continue

                x0 = float((b.get("bbox") or [0, 0, 0, 0])[0])
                if x0 + 3.0 < sens_min_x0:
                    # 민감값보다 왼쪽(라벨 영역) → 승격 금지
                    continue

                # 같은 행에서 값 파편(예: 'com', '76')은 민감으로 승격
                b["kind"] = sens[0].get("kind") or "row_sensitive"


def _promote_multiline_continuations(blocks: List[Dict[str, Any]]) -> None:
    """
    줄바꿈으로 끊긴 값(차트/이미지에서 자주 발생)을 아래 줄 블록에 전파.
    예:
      card:  '...-68' + '76'
      email: '...@naver.' + 'com'
    """
    rows = _group_rows_by_y(blocks, row_tol=35.0)
    if len(rows) < 2:
        return

    def x_overlap_ratio(a: List[float], b: List[float]) -> float:
        ax0, _, ax1, _ = a
        bx0, _, bx1, _ = b
        inter = max(0.0, min(ax1, bx1) - max(ax0, bx0))
        denom = max(1.0, min(ax1 - ax0, bx1 - bx0))
        return inter / denom

    for i in range(len(rows) - 1):
        cur = rows[i]
        nxt = rows[i + 1]

        for a in cur:
            kind = a.get("kind") or "none"
            if kind not in ("card", "email"):
                continue

            at = _text_for_post(a)
            if not _is_incomplete_sensitive(kind, at):
                continue

            ab = list(map(float, (a.get("bbox") or [0, 0, 0, 0])))
            ax0, ay0, ax1, ay1 = ab
            acx = 0.5 * (ax0 + ax1)

            # 다음 줄에서 "짧은 파편" 후보를 찾는다
            best = None
            best_score = 0.0

            for b in nxt:
                if (b.get("kind") or "none") != "none":
                    continue

                bt = _text_for_post(b)
                if not bt:
                    continue

                bb = list(map(float, (b.get("bbox") or [0, 0, 0, 0])))
                bx0, by0, bx1, by1 = bb
                bcx = 0.5 * (bx0 + bx1)

                # 세로 간격이 너무 멀면 제외(줄바꿈 이어짐이 아님)
                if by0 - ay1 > 40.0:
                    continue

                # x 정렬/겹침이 어느 정도 있어야 이어짐으로 판단
                ov = x_overlap_ratio(ab, bb)
                if ov < 0.25 and abs(bcx - acx) > 80.0:
                    continue

                # 종류별 파편 조건
                if kind == "card":
                    if not bt.replace("-", "").replace(" ", "").isdigit():
                        continue
                    # 보통 2~4자리
                    if _count_digits(bt) > 6:
                        continue
                else:  # email
                    if not (2 <= len(bt) <= 6 and bt.isalpha()):
                        continue

                # 점수: 겹침 + 중심 거리
                score = ov - (abs(bcx - acx) / 1000.0)
                if score > best_score:
                    best_score = score
                    best = b

            if best is not None:
                best["kind"] = kind


def detect_boxes_from_ocr(
    pdf_bytes: bytes,
    *,
    dpi: int = 120,
    use_llm: bool = True,
    min_conf: float = 0.3,
) -> List[Box]:
    """
    EasyOCR + (옵션) Qwen 후처리로 PDF 내 이미지/차트 영역의 민감정보 박스 탐지.

    - 페이지 전체를 이미지로 렌더링
    - EasyOCR로 텍스트 블록 추출
    - use_llm=True 이면 Qwen으로 kind 분류(card/phone/email/id/none)
    - 텍스트 레이어가 이미 있는 영역은 제외 (본문 텍스트 침범 방지)
    - 줄바꿈으로 끊긴 값(차트/이미지)을 아래 줄 블록에 전파해서 같이 가림
    - OCR 박스는 과확장하지 않도록(라벨까지 같이 가려지는 문제 방지) 좌측 패딩을 최소화
    """
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    scale = dpi / 72.0
    inv_scale = 1.0 / scale

    try:
        for pno, page in enumerate(doc):
            # 이 페이지에 이미 존재하는 텍스트 단어들의 bbox 수집
            words = page.get_text("words") or []
            text_rects = [fitz.Rect(w[0], w[1], w[2], w[3]) for w in words]

            def overlaps_text_layer(r: fitz.Rect) -> bool:
                for tr in text_rects:
                    if not r.intersects(tr):
                        continue
                    inter = r & tr
                    if inter.get_area() > 0:
                        return True
                return False

            img = _page_to_pil(page, dpi=dpi)

            ocr_blocks = easyocr_blocks(img, min_conf=min_conf, gpu=False)
            print(f"{log_prefix} OCR page={pno + 1} blocks=", len(ocr_blocks))

            if use_llm and ocr_blocks:
                ocr_blocks = classify_blocks_with_qwen(ocr_blocks)

                # "라벨 전체 가림" 방지를 위해, row propagation은 "값처럼 보이는 것"만 승격
                _promote_value_like_in_rows(ocr_blocks)

                # 차트/이미지에서 줄바꿈으로 끊긴 값 전파
                _promote_multiline_continuations(ocr_blocks)

            for blk in ocr_blocks:
                kind = blk.get("kind") or "none"

                if use_llm and kind == "none":
                    # LLM 기준으로 민감 아님 → 스킵
                    continue

                x0_px, y0_px, x1_px, y1_px = blk["bbox"]

                # 픽셀 좌표 → PDF 좌표
                x0 = float(x0_px) * inv_scale
                y0 = float(y0_px) * inv_scale
                x1 = float(x1_px) * inv_scale
                y1 = float(y1_px) * inv_scale

                width = x1 - x0
                height = y1 - y0

                # 과확장하면 라벨(좌측 한글)까지 같이 가려짐 → 좌측 패딩 최소, 우측/상하도 캡을 둠
                if height > 1.0:
                    pad_y = min(max(height * 0.15, 0.6), 3.0)
                    y0 -= pad_y
                    y1 += pad_y

                if width > 1.0:
                    pad_x_left = min(max(width * 0.01, 0.2), 1.2)
                    pad_x_right = min(max(width * 0.06, 0.8), 6.0)
                    x0 -= pad_x_left
                    x1 += pad_x_right

                rect_pdf = fitz.Rect(x0, y0, x1, y1) & page.rect

                # 이미 텍스트가 존재하는 곳(본문)은 OCR 박스에서 제외
                if overlaps_text_layer(rect_pdf):
                    continue

                print(
                    f"{log_prefix} OCR BOX",
                    "page=",
                    pno + 1,
                    "kind=",
                    kind,
                    "text=",
                    repr(_text_for_post(blk)),
                    "bbox_px=",
                    (x0_px, y0_px, x1_px, y1_px),
                    "bbox_pdf=",
                    (rect_pdf.x0, rect_pdf.y0, rect_pdf.x1, rect_pdf.y1),
                )

                boxes.append(
                    Box(
                        page=pno,
                        x0=rect_pdf.x0,
                        y0=rect_pdf.y0,
                        x1=rect_pdf.x1,
                        y1=rect_pdf.y1,
                    )
                )
    finally:
        doc.close()

    print(
        f"{log_prefix} detect_boxes_from_ocr summary",
        "boxes=",
        len(boxes),
    )

    return boxes


# ─────────────────────────────
# 레닥션 적용 공통
# ─────────────────────────────
def _fill_color(fill: str):
    f = (fill or "black").strip().lower()
    return (0, 0, 0) if f == "black" else (1, 1, 1)


def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
    print(f"{log_prefix} apply_redaction: boxes=", len(boxes), "fill=", fill)
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        color = _fill_color(fill)
        for b in boxes:
            page = doc.load_page(int(b.page))
            rect = fitz.Rect(float(b.x0), float(b.y0), float(b.x1), float(b.y1))
            page.add_redact_annot(rect, fill=color)

        for page in doc:
            page.apply_redactions()

        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()
    finally:
        doc.close()


# ─────────────────────────────
# 텍스트 + OCR + NER 통합 레닥션
# ─────────────────────────────
def apply_text_redaction(pdf_bytes: bytes, extra_spans: List[dict] | None = None) -> bytes:
    """
    - 정규식 기반 패턴 탐지
    - (추가) EasyOCR + Qwen 기반 OCR 탐지 (이미지/차트 영역 위주)
    - NER extra_spans → 좌표 변환
    - 최종 박스들에 대해 레닥션 적용
    """
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    ocr_boxes = detect_boxes_from_ocr(
        pdf_bytes,
        dpi=120,       # 150 → 120 (속도)
        use_llm=True,
        min_conf=0.3,
    )

    print(
        f"{log_prefix} apply_text_redaction: pattern_boxes=",
        len(boxes),
        "ocr_boxes=",
        len(ocr_boxes),
    )

    boxes.extend(ocr_boxes)

    # extra_spans (NER 결과) 처리
    if extra_spans:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            page_texts: List[str] = []
            page_offsets: List[int] = []
            current_offset = 0

            for page in doc:
                text = page.get_text("text") or ""
                page_texts.append(text)
                page_offsets.append(current_offset)
                current_offset += len(text) + 1  # +1 for \n

            full_text = "\n".join(page_texts)

            for span in extra_spans:
                start = span.get("start", 0)
                end = span.get("end", 0)
                if end <= start or start >= len(full_text):
                    continue

                span_text = full_text[start: min(end, len(full_text))]
                if not span_text or not span_text.strip():
                    continue

                search_text = span_text.strip()
                if not search_text:
                    continue

                for page_idx, page_offset in enumerate(page_offsets):
                    next_offset = (
                        page_offsets[page_idx + 1]
                        if page_idx + 1 < len(page_offsets)
                        else len(full_text)
                    )

                    if start >= page_offset and start < next_offset:
                        page = doc[page_idx]
                        rects = page.search_for(search_text)

                        if rects:
                            for r in rects:
                                boxes.append(
                                    Box(
                                        page=page_idx,
                                        x0=r.x0,
                                        y0=r.y0,
                                        x1=r.x1,
                                        y1=r.y1,
                                    )
                                )

                            print(
                                f"{log_prefix} NER BOX",
                                "page=",
                                page_idx + 1,
                                "label=",
                                span.get("label", "unknown"),
                                "text=",
                                repr(search_text[:50]),
                                "matches=",
                                len(rects),
                            )
                        break
        finally:
            doc.close()

    return apply_redaction(pdf_bytes, boxes)
