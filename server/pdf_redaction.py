import re
import io
import fitz
import logging
from typing import List, Tuple, Optional
from .schemas import Box, PatternItem
from .redac_rules import RULES  # validator 사용


logger = logging.getLogger("redaction")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)


def _compile_pattern(p: PatternItem) -> re.Pattern:
    flags = 0 if p.case_sensitive else re.IGNORECASE
    pattern = p.regex
    if p.whole_word:
        pattern = rf"\b(?:{pattern})\b"
    logger.debug("Compiling pattern: %s -> %s", p.name, pattern)
    return re.compile(pattern, flags)


def _word_spans_to_rect(words: List[tuple], spans: List[Tuple[int, int]]) -> List[fitz.Rect]:
    rects: List[fitz.Rect] = []
    for s, e in spans:
        chunk = words[s:e]
        if not chunk:
            continue
        x0 = min(w[0] for w in chunk)
        y0 = min(w[1] for w in chunk)
        x1 = max(w[2] for w in chunk)
        y1 = max(w[3] for w in chunk)
        rects.append(fitz.Rect(x0, y0, x1, y1))
    return rects


def _search_exact_bbox(page: fitz.Page, text: str, hint_rect: Optional[fitz.Rect] = None) -> Optional[fitz.Rect]:
    
    try:
        hits = page.search_for(text)  # List[Rect]
    except Exception:
        hits = []
    if not hits:
        return None
    if hint_rect is None:
        return hits[0]
    best, best_iou = None, -1.0
    for r in hits:
        inter = fitz.Rect(
            max(hint_rect.x0, r.x0),
            max(hint_rect.y0, r.y0),
            min(hint_rect.x1, r.x1),
            min(hint_rect.y1, r.y1),
        )
        if inter.x1 <= inter.x0 or inter.y1 <= inter.y0:
            iou = 0.0
        else:
            inter_a = (inter.x1 - inter.x0) * (inter.y1 - inter.y0)
            union_a = (hint_rect.get_area() + r.get_area() - inter_a) or 1.0
            iou = inter_a / union_a
        if iou > best_iou:
            best, best_iou = r, iou
    return best or hits[0]


def _find_pattern_rects_on_page(page: fitz.Page, comp: re.Pattern, pattern_name: str):
    
    results = []
    words = page.get_text("words")
    if not words:
        return []

    tokens = [w[4] for w in words]

    if pattern_name == "card":
        buf = ""
        spans: List[int] = []
        start_idx: Optional[int] = None

        for i, t in enumerate(tokens):
            if re.fullmatch(r"[\d\- ]+", t):  # 숫자/하이픈/공백
                if start_idx is None:
                    start_idx = i
                buf += t
                spans.append(i)
            else:
                if buf:
                    candidate = re.sub(r"\D", "", buf)
                    if comp.fullmatch(candidate):
                        rects = _word_spans_to_rect(words, [(start_idx, spans[-1] + 1)])
                        for r in rects:
                            results.append((r, buf, pattern_name))
                            logger.debug("[CARD MATCH] p=%d buf='%s' cand='%s' len=%d rect=%s",
                                        page.number, buf, candidate, len(candidate), r)
                    buf = ""
                    spans = []
                    start_idx = None

        if buf:
            candidate = re.sub(r"\D", "", buf)
            if comp.fullmatch(candidate):
                rects = _word_spans_to_rect(words, [(start_idx, spans[-1] + 1)])
                for r in rects:
                    results.append((r, buf, pattern_name))
                    logger.debug("[CARD MATCH] p=%d buf='%s' cand='%s' len=%d rect=%s",
                                page.number, buf, candidate, len(candidate), r)

        logger.debug("[RESULT] page=%d pattern=card found=%d", page.number, len(results))
        return results

    joined = " ".join(tokens)
    acc = 0
    for m in comp.finditer(joined):
        matched = m.group(0)
        logger.debug("[MATCH] page=%d pattern=%s matched='%s' span=%s",
                    page.number, pattern_name, matched, (m.start(), m.end()))
        start_char, end_char = m.start(), m.end()
        start_idx = end_idx = None

        acc = 0
        for i, t in enumerate(tokens):
            if i > 0:
                acc += 1  # 공백
            token_start, token_end = acc, acc + len(t)
            if token_end > start_char and token_start < end_char:
                if start_idx is None:
                    start_idx = i
                end_idx = i + 1
            acc += len(t)
        if start_idx is None or end_idx is None:
            continue

        if pattern_name == "email":
            hint_rects = _word_spans_to_rect(words, [(start_idx, end_idx)])
            hint = hint_rects[0] if hint_rects else None
            exact = _search_exact_bbox(page, matched, hint)
            if exact:
                results.append((exact, matched, pattern_name))
                logger.debug("[EMAIL BOX] exact='%s' rect=%s", matched, exact)
                continue
            for r in hint_rects:
                results.append((r, matched, pattern_name))
            continue

        rects = _word_spans_to_rect(words, [(start_idx, end_idx)])
        for r in rects:
            results.append((r, matched, pattern_name))

    logger.debug("[RESULT] page=%d pattern=%s found=%d", page.number, pattern_name, len(results))
    return results


def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem]) -> List[Box]:

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    compiled = [(_compile_pattern(p), p.name) for p in patterns]

    for pno in range(len(doc)):
        page = doc.load_page(pno)
        logger.debug("Scanning page %d...", pno)

        for comp, pname in compiled:
            rects = _find_pattern_rects_on_page(page, comp, pname)

            # validator 적용
            validator = None
            rule = RULES.get(pname)
            if rule:
                validator = rule.get("validator")

            for r, matched, _pname in rects:
                is_ok = True
                if callable(validator):
                    try:
                        is_ok = bool(validator(matched))
                    except Exception as e:
                        logger.exception("[VALIDATOR ERROR] pattern=%s value='%s' err=%s", pname, matched, e)
                        is_ok = False

                if not is_ok:
                    logger.debug("[DROP] pattern=%s value='%s' (validator rejected)", pname, matched)
                    continue

                boxes.append(
                    Box(
                        page=pno,
                        x0=float(r.x0),
                        y0=float(r.y0),
                        x1=float(r.x1),
                        y1=float(r.y1),
                        matched_text=matched,
                        pattern_name=pname,
                    )
                )
                logger.debug("→ Box added: %s | text='%s'", pname, matched)

    doc.close()
    logger.debug("Total boxes detected: %d", len(boxes))
    return boxes


def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill="black") -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    color = (0, 0, 0) if fill == "black" else (1, 1, 1)
    by_page = {}
    for b in boxes:
        by_page.setdefault(b.page, []).append(b)

    logger.debug("APPLY REQUEST: total_boxes=%d, patterns=%s, fill=%s",
                len(boxes), [b.pattern_name for b in boxes], fill)

    for pno, page_boxes in by_page.items():
        page = doc.load_page(pno)
        logger.debug("Applying redactions on page %d (count=%d)", pno, len(page_boxes))
        for b in page_boxes:
            rect = fitz.Rect(b.x0, b.y0, b.x1, b.y1)
            area = (b.x1 - b.x0) * (b.y1 - b.y0)
            logger.debug("  → Redact box: %s | area=%.2f | text='%s'", rect, area, b.matched_text)
            page.add_redact_annot(rect, fill=color)
        page.apply_redactions()

    out = io.BytesIO()
    doc.save(out)
    doc.close()
    return out.getvalue()

def extract_text(file_bytes: bytes):
    from PyPDF2 import PdfReader
    import io

    text = ""
    reader = PdfReader(io.BytesIO(file_bytes))
    for page in reader.pages:
        text += page.extract_text() or ""
    return {"full_text": text, "pages": [{"page": i + 1, "text": p.extract_text() or ""} for i, p in enumerate(reader.pages)]}