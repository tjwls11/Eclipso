import io, fitz, logging
from typing import List
from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules.ner_module import run_ner
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY
from server.core.regex_utils import match_text

log = logging.getLogger("pdf_redact")

def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem]) -> List[Box]:
    boxes = []
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    for pno, page in enumerate(doc):
        text = page.get_text("text") or ""
        for pattern in patterns:
            for m in pattern.compiled.finditer(text):
                rects = page.search_for(m.group(0))
                for r in rects:
                    boxes.append(Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
    doc.close()
    return boxes

def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill="black") -> bytes:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    color = (0, 0, 0) if fill == "black" else (1, 1, 1)
    for b in boxes:
        page = doc.load_page(b.page)
        rect = fitz.Rect(b.x0, b.y0, b.x1, b.y1)
        page.add_redact_annot(rect, fill=color)
    doc.apply_redactions()
    out = io.BytesIO()
    doc.save(out)
    doc.close()
    return out.getvalue()

def apply_text_redaction(pdf_bytes: bytes, extra_spans: list = None) -> bytes:
    """
    기존 정규식 기반 + NER 병합 결과까지 반영
    """
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    if extra_spans:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for s in extra_spans:
            frag = s.get("text_sample") or ""
            if not frag.strip():
                continue
            for page in doc:
                rects = page.search_for(frag)
                for r in rects:
                    if s.get("decision") == "highlight":
                        annot = page.add_highlight_annot(r)
                        annot.set_colors(stroke=(1, 1, 0))
                        annot.set_opacity(0.45)
                        annot.update()
                    else:
                        page.add_redact_annot(r, fill=(0, 0, 0))
        try:
            doc.apply_redactions()
        except Exception:
            pass
        out = io.BytesIO()
        doc.save(out)
        doc.close()
        return out.getvalue()

    return apply_redaction(pdf_bytes, boxes)
