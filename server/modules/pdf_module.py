from __future__ import annotations

import io
import re
from typing import List, Optional, Set, Dict

import fitz 

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS, RULES
from server.modules.ner_module import run_ner 
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY
from server.core.regex_utils import match_text


try:
    from .common import cleanup_text, compile_rules
except Exception:  # pragma: no cover
    from server.modules.common import cleanup_text, compile_rules  # type: ignore


log_prefix = "[PDF]"


# /text/extract 용 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    try:
        pages = []
        all_chunks: List[str] = []

        for idx, page in enumerate(doc):
            raw = page.get_text("text") or ""
            cleaned = cleanup_text(raw)
            pages.append({"page": idx + 1, "text": cleaned})
            if cleaned:
                all_chunks.append(cleaned)

        full_text = cleanup_text("\n\n".join(all_chunks))

        return {
            "full_text": full_text,
            "pages": pages,
        }
    finally:
        doc.close()


# 헬퍼들
def _normalize_pattern_names(
    patterns: List[PatternItem] | None,
) -> Optional[Set[str]]:
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
        # validator 내부 예외는 FAIL 처리
        print(f"{log_prefix} VALIDATOR ERROR", repr(value))
        return False


# PDF 내 박스 탐지
def detect_boxes_from_patterns(
    pdf_bytes: bytes,
    patterns: List[PatternItem] | None,
) -> List[Box]:
    comp = compile_rules()  
    allowed_names = _normalize_pattern_names(patterns)

    print(
        f"{log_prefix} detect_boxes_from_patterns: rules 준비 완료",
        "allowed_names=",
        sorted(allowed_names) if allowed_names else "ALL",
    )

    # 룰별 OK/FAIL 카운터 (디버깅용)
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

                    # 통계
                    if ok:
                        stats_ok[rule_name] = stats_ok.get(rule_name, 0) + 1
                    else:
                        stats_fail[rule_name] = stats_fail.get(rule_name, 0) + 1

                    print(
                        f"{log_prefix} MATCH",
                        "page=", pno + 1,
                        "rule=", rule_name,
                        "need_valid=", need_valid,
                        "ok=", ok,
                        "value=", repr(val),
                    )

                    # FAIL 이면 박스 만들지 않음
                    if not ok:
                        continue

                    # 실제 박스 찾기
                    rects = page.search_for(val)
                    for r in rects:
                        print(
                            f"{log_prefix} BOX",
                            "page=", pno + 1,
                            "rule=", rule_name,
                            "rect=", (r.x0, r.y0, r.x1, r.y1),
                        )
                        boxes.append(
                            Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1)
                        )
    finally:
        doc.close()

    print(
        f"{log_prefix} detect summary",
        "OK=", {k: v for k, v in sorted(stats_ok.items())},
        "FAIL=", {k: v for k, v in sorted(stats_fail.items())},
        "boxes=", len(boxes),
    )

    return boxes


# 레닥션 적용
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

        # 페이지 단위로 실제 레닥션 적용
        for page in doc:
            page.apply_redactions()

        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()
    finally:
        doc.close()


def apply_text_redaction(pdf_bytes: bytes, extra_spans: list | None = None) -> bytes:
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    return apply_redaction(pdf_bytes, boxes)
