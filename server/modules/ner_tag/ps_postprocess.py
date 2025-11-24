from __future__ import annotations
from typing import List, Dict, Any, Tuple
import re


def _split_multiname_ps(text: str, ps_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for span in ps_spans:
        s = span.get("start", 0)
        e = span.get("end", 0)
        if e <= s:
            continue

        sub = text[s:e]

        # 줄바꿈/공백 없으면 그냥 원본 유지
        if ("\n" not in sub) and (" " not in sub):
            out.append(span)
            continue

        found = False
        # 공백 기준 토큰 단위로 분할
        for tok in re.finditer(r"\S+", sub):
            word = tok.group(0)

            if not re.fullmatch(r"[가-힣]{2,}", word):
                continue

            ns = s + tok.start()
            ne = s + tok.end()
            out.append(
                {
                    "start": ns,
                    "end": ne,
                    "label": "PS",
                    "source": "rule",  
                    "score": span.get("score"),
                }
            )
            found = True

        # 토큰에서 아무 것도 못 찾았으면 그냥 원본 유지
        if not found:
            out.append(span)

    return out


def _fill_line_name_holes(text: str, ps_spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # 일반 긴 문서에서 오탐 방지
    if len(text) > 200 and len(ps_spans) < 3:
        return ps_spans

    used: List[Tuple[int, int]] = [(s["start"], s["end"]) for s in ps_spans]

    def overlaps(a_start: int, a_end: int) -> bool:
        for b_start, b_end in used:
            if min(a_end, b_end) > max(a_start, b_start):
                return True
        return False

    out = list(ps_spans)
    lines = text.splitlines(keepends=False)

    offset = 0
    for i, line in enumerate(lines):
        stripped = line.strip()

        if not re.fullmatch(r"[가-힣]{2,3}", stripped):
            offset += len(line) + 1
            continue

        if re.search(r"(도|시|읍|면|리|동|로|길|번지|호)$", stripped):
            offset += len(line) + 1
            continue

        prev_line = lines[i - 1].strip() if i > 0 else ""
        next_line = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if prev_line or next_line:
            offset += len(line) + 1
            continue

        idx = line.find(stripped)
        if idx < 0:
            offset += len(line) + 1
            continue

        line_start = offset + idx
        line_end = line_start + len(stripped)

        if overlaps(line_start, line_end):
            offset += len(line) + 1
            continue

        out.append(
            {
                "start": line_start,
                "end": line_end,
                "label": "PS",
                "source": "rule",
                "score": None,
            }
        )
        used.append((line_start, line_end))
        offset += len(line) + 1

    return out


def postprocess_ps_spans(text: str, spans: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ps = [s for s in spans if s.get("label") == "PS"]
    others = [s for s in spans if s.get("label") != "PS"]

    if not ps:
        return spans

    ps = _split_multiname_ps(text, ps)
    ps = _fill_line_name_holes(text, ps)

    return others + ps


