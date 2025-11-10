from __future__ import annotations
from typing import List, Dict, Any, Tuple
import re

# ──────────────────────────────────────────────────────────────────────────────
def _chunk_text(text: str, chunk_size: int = 1500, overlap: int = 50) -> List[Tuple[int, int, str]]:
    n = len(text)
    if n <= 0:
        return []
    chunks: List[Tuple[int, int, str]] = []
    i = 0
    while i < n:
        j = min(n, i + chunk_size)
        chunks.append((i, j, text[i:j]))
        if j == n:
            break
        i = j - overlap
        if i < 0:
            i = 0
    return chunks

# ──────────────────────────────────────────────────────────────────────────────
_LABEL_MAP = {
    "PS": "PS", "LC": "LC", "OG": "OG", "DT": "DT", "QT": "QT",
    "PERSON": "PS", "PER": "PS", "PEOPLE": "PS",
    "ORGANIZATION": "OG", "ORG": "OG", "INSTITUTION": "OG", "COMPANY": "OG",
    "LOCATION": "LC", "ADDRESS": "LC", "ADDR": "LC", "GPE": "LC", "PLACE": "LC", "FAC": "LC", "FACILITY": "LC",
    "DATE": "DT", "TIME": "DT", "DATETIME": "DT",
    "NUMBER": "QT", "QUANTITY": "QT", "CARDINAL": "QT", "NUM": "QT",
    "B-PER": "PS", "I-PER": "PS", "B-ORG": "OG", "I-ORG": "OG", "B-LOC": "LC", "I-LOC": "LC",
}
def _std_label(label: str) -> str:
    if not label:
        return ""
    key = label.strip().upper()
    return _LABEL_MAP.get(key, key)

# ──────────────────────────────────────────────────────────────────────────────
def _normalize_raw_entities(raw: Any, chunk_start: int, chunk_text: str) -> List[Dict[str, Any]]:
    data = raw
    if isinstance(raw, dict):
        if "entities" in raw:
            data = raw.get("entities", [])
        elif "result" in raw:
            data = raw.get("result", [])
        elif isinstance(raw.get("data"), list):
            data = raw["data"]

    out: List[Dict[str, Any]] = []
    used_ranges: List[Tuple[int, int]] = []

    def _overlap(a: Tuple[int,int], b: Tuple[int,int]) -> bool:
        return min(a[1], b[1]) - max(a[0], b[0]) > 0

    if isinstance(data, list):
        for e in data:
            if not isinstance(e, dict):
                continue
            label = e.get("label") or e.get("entity") or e.get("entity_group") or ""
            std = _std_label(str(label))
            if not std:
                continue

            start = e.get("start") or e.get("begin") or e.get("start_idx") or e.get("offset_start")
            end   = e.get("end")   or e.get("finish") or e.get("end_idx")   or e.get("offset_end")
            score = e.get("score")
            try:
                score = float(score) if score is not None else None
            except Exception:
                score = None

            txt = (e.get("text") or e.get("word") or "").strip()

            if start is not None and end is not None:
                try:
                    s_local = int(start)
                    t_local = int(end)
                except Exception:
                    s_local = None; t_local = None

                if s_local is not None and t_local is not None:
                    # inclusive → exclusive 보정
                    if txt:
                        slice_text = chunk_text[s_local:t_local]
                        if len(txt) == len(slice_text) + 1 and txt.startswith(slice_text):
                            t_local += 1
                        elif len(slice_text) == len(txt) + 1 and slice_text.startswith(txt):
                            t_local -= 1
                    s = chunk_start + max(0, s_local)
                    t = chunk_start + max(s_local, t_local)
                    if t > s and not any(_overlap((s, t), ur) for ur in used_ranges):
                        out.append({"start": s, "end": t, "label": std, "source": "ner", "score": score})
                        used_ranges.append((s, t))
                    continue

            # 위치가 없고 텍스트만 있을 때: chunk 내 최초 매치
            if txt:
                for m in re.finditer(re.escape(txt), chunk_text):
                    s_local, t_local = m.start(), m.end()
                    s = chunk_start + s_local
                    t = chunk_start + t_local
                    if any(_overlap((s, t), ur) for ur in used_ranges):
                        continue
                    out.append({"start": s, "end": t, "label": std, "source": "ner", "score": score})
                    used_ranges.append((s, t))
                    break
    return out

# ──────────────────────────────────────────────────────────────────────────────
_DATE_REGEXES = [
    re.compile(r"\b(19|20)\d{2}[./-](0?[1-9]|1[0-2])[./-](0?[1-9]|[12]\d|3[01])\b"),
    re.compile(r"(19|20)\d{2}\s*년\s*(0?[1-9]|1[0-2])\s*월\s*(0?[1-9]|[12]\d|3[01])\s*일"),
    re.compile(r"\b(0?[1-9]|1[0-2])[./-](0?[1-9]|[12]\d|3[01])[./-]((19|20)\d{2})\b"),
    re.compile(r"\b(0?[1-9]|1[0-2])[/-](\d{2})\b"),
]
def _synthesize_dt_spans(text: str, policy: Dict[str, Any], existing: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    dt_policy = str(policy.get("dt_policy", "sensitive_only"))
    if dt_policy == "off":
        return []
    if any(s.get("label") == "DT" for s in existing):
        return []
    triggers = list(policy.get("dt_sensitive_triggers", []))
    window = int(policy.get("context_window", 18))
    synthesized: List[Dict[str, Any]] = []
    for rx in _DATE_REGEXES:
        for m in rx.finditer(text):
            s, t = m.start(), m.end()
            lo, hi = max(0, s - window), min(len(text), t + window)
            ctx = text[lo:hi]
            if dt_policy == "always" or any(k in ctx for k in triggers):
                synthesized.append({"start": s, "end": t, "label": "DT", "source": "regex", "score": None})
    return synthesized

# ──────────────────────────────────────────────────────────────────────────────
# 개행/새주소 시작 감지자
_NEWLINE_RX = re.compile(r"[\r\n]")
_CITY_START_RX = re.compile(r"^\s*(?:[가-힣]{2,}시|[가-힣]{2,}군|[가-힣]{2,}구)")

def _has_newline(s: str) -> bool:
    return bool(_NEWLINE_RX.search(s or ""))

def _looks_new_address(s: str) -> bool:
    return bool(_CITY_START_RX.search(s or ""))

def _merge_adjacent_same_label(spans: List[Dict[str, Any]], text: str, label: str = "LC", max_gap: int = 1) -> List[Dict[str, Any]]:
    if not spans:
        return spans
    spans = sorted(spans, key=lambda x: (x["start"], x["end"]))
    out: List[Dict[str, Any]] = []
    buf = None
    for s in spans:
        if s.get("label") != label:
            if buf:
                out.append(buf); buf = None
            out.append(s)
            continue
        if buf is None:
            buf = dict(s); continue
        gap_text = text[buf["end"]:s["start"]]
        # 개행·새주소·과도한 구분자는 병합 금지
        if _has_newline(gap_text) or _looks_new_address(text[s["start"]:s["end"]]):
            out.append(buf); buf = dict(s); continue
        if len(gap_text) <= max_gap and re.fullmatch(r"[ \t,\-–—/]*", gap_text or ""):
            buf["end"] = max(buf["end"], s["end"])
        else:
            out.append(buf); buf = dict(s)
    if buf:
        out.append(buf)
    return out

# 괄호 보조지명까지 같은 줄에서만 확장
_PAREN_TAIL_RX = re.compile(r"^\s*\([^)]+\)")
_SUFFIX_RX = re.compile(
    r"^(?:\s*[-–—]?\s*(\d{1,4})(?:[-~]\d{1,4})?\s*(동|로|길|가)?\s*(\d{1,4})?(?:-\d{1,3})?\s*(번지|호|층|동|가|리)?)+"
)

def _extend_lc_suffix_by_text(text: str, end: int, max_steps: int = 2) -> int:
    steps = 0
    i = end
    line_end = text.find("\n", end)
    hard_stop = len(text) if line_end == -1 else line_end  # 줄 끝까지만
    while steps < max_steps and i < hard_stop:
        m = _SUFFIX_RX.match(text[i:hard_stop])
        if m:
            i += m.end()
            steps += 1
            continue
        # 괄호 보조지명: 같은 줄에서만
        m2 = _PAREN_TAIL_RX.match(text[i:hard_stop])
        if m2:
            i += m2.end()
            steps += 1
            continue
        break
    return i

def _attach_address_numbers(spans: List[Dict[str, Any]], text: str, max_gap: int = 2) -> List[Dict[str, Any]]:
    if not spans:
        return spans
    spans = sorted(spans, key=lambda x: (x["start"], x["end"]))
    out: List[Dict[str, Any]] = []
    idx = 0
    while idx < len(spans):
        cur = spans[idx]
        if cur.get("label") != "LC":
            out.append(cur); idx += 1; continue
        end = cur["end"]; j = idx + 1
        while j < len(spans):
            nxt = spans[j]
            gap_text = text[end:nxt["start"]]
            # 줄바꿈 또는 새주소 시작이면 중단
            if _has_newline(gap_text) or _looks_new_address(text[nxt["start"]:nxt["end"]]):
                break
            if len(gap_text) > max_gap or not re.fullmatch(r"[ \t,\-–—]*", gap_text or ""):
                break
            # 숫자/도로명 연속 및 짧은 이어붙임만 허용
            if nxt.get("label") == "QT":
                end = nxt["end"]; j += 1; continue
            if nxt.get("label") == "LC":
                token = text[nxt["start"]:nxt["end"]]
                if re.fullmatch(r"\d+[가-힣A-Za-z\-]*", token) or re.search(r"(로|길)$", text[cur["start"]:end]):
                    end = nxt["end"]; j += 1; continue
                else:
                    break
            break
        end = _extend_lc_suffix_by_text(text, end, max_steps=3)

        cur = dict(cur); cur["end"] = end
        out.append(cur)
        idx = j

    out.sort(key=lambda x: (x["start"], x["end"]))
    merged: List[Dict[str, Any]] = []
    for s in out:
        if not merged:
            merged.append(s); continue
        last = merged[-1]
        # 같은 줄에서만 병합
        gap = text[last["end"]:s["start"]]
        if last["label"] == s["label"] == "LC" and not _has_newline(gap) and len(gap) <= 1:
            last["end"] = max(last["end"], s["end"])
        else:
            merged.append(s)
    return merged

_ROAD_RX = re.compile(r"\b[가-힣A-Za-z0-9]+(?:로|길)\b")
def _synthesize_road_names(text: str) -> List[Dict[str, Any]]:
    spans: List[Dict[str, Any]] = []
    for m in _ROAD_RX.finditer(text):
        spans.append({"start": m.start(), "end": m.end(), "label": "LC", "source": "ner", "score": None})
    return spans

# 왼쪽(상위 행정구역)까지 주소 확장 — 줄 경계는 넘지 않음
_ADDR_HINTS = {"시","군","구","동","읍","면","리","로","길"}
_HINT_RX = re.compile(rf'(?:{"|".join(map(re.escape, sorted(_ADDR_HINTS)) )})$')

def _attach_address_left_context(spans: List[Dict[str, Any]], text: str, max_back_steps: int = 3) -> List[Dict[str, Any]]:
    if not spans:
        return spans
    spans = sorted(spans, key=lambda x: (x["start"], x["end"]))
    out: List[Dict[str, Any]] = []
    for s in spans:
        if s.get("label") != "LC":
            out.append(s); continue
        start, end = s["start"], s["end"]
        i = start
        steps = 0
        # 같은 줄 범위 안에서만 왼쪽 확장
        line_start = text.rfind("\n", 0, start) + 1
        while i > line_start and steps < max_back_steps:
            # 공백 트림
            j = i
            while j > line_start and text[j-1].isspace():
                j -= 1
            # 왼쪽 토큰 경계
            k = j - 1
            while k >= line_start and not text[k].isspace():
                k -= 1
            token = text[k+1:j]
            if not token:
                break
            if _HINT_RX.search(token):
                start = k+1
                i = k+1
                steps += 1
                continue
            break
        if start < s["start"]:
            s = dict(s); s["start"] = start
        out.append(s)
    out.sort(key=lambda x: (x["start"], x["end"]))
    # 같은 줄에서만 인접 LC 병합
    merged: List[Dict[str, Any]] = []
    for it in out:
        if not merged:
            merged.append(it); continue
        last = merged[-1]
        gap = text[last["end"]:it["start"]]
        if last["label"] == it["label"] == "LC" and not _has_newline(gap) and len(gap) <= 1:
            last["end"] = max(last["end"], it["end"])
        else:
            merged.append(it)
    return merged

# 한 글자 LC 노이즈 제거(도로명/접미 연결 예외 허용)
def _filter_short_lc(spans: List[Dict[str, Any]], text: str) -> List[Dict[str, Any]]:
    if not spans:
        return spans
    kept: List[Dict[str, Any]] = []
    _ROAD_RX = re.compile(r"\b[가-힣A-Za-z0-9]+(?:로|길)\b")
    _SUFFIX_RX = re.compile(r"^(?:\s*[-–—]?\s*\d{1,4}(?:[-~]\d{1,4})?\s*(번지|호|층|동|가|리)?)+")
    for s in spans:
        if s.get("label") != "LC":
            kept.append(s); continue
        if (s["end"] - s["start"]) >= 2:
            kept.append(s); continue
        seg = text[s["start"]:s["end"]]
        right = text[s["end"]:]
        if _ROAD_RX.fullmatch(seg) or _SUFFIX_RX.match(right):
            kept.append(s); continue
        # drop 1-char LC
    return kept

# ──────────────────────────────────────────────────────────────────────────────
def run_ner(text: str, policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    from server.api.ner_api import ner_predict_blocking
    chunk_size = int(policy.get("chunk_size", 1500))
    overlap = int(policy.get("chunk_overlap", 50))
    allowed = policy.get("allowed_labels", None)

    spans: List[Dict[str, Any]] = []
    for s, t, sub in _chunk_text(text, chunk_size=chunk_size, overlap=overlap):
        try:
            res = ner_predict_blocking(sub, labels=allowed)
            raw = res.get("raw")
            spans.extend(_normalize_raw_entities(raw, s, sub))
        except Exception:
            continue

    if text:
        spans.extend(_synthesize_dt_spans(text, policy, spans))

    spans.sort(key=lambda x: (x["start"], x["end"]))
    spans = _merge_adjacent_same_label(spans, text, label="LC", max_gap=1)

    try:
        road_spans = _synthesize_road_names(text)
        spans.extend(road_spans)
    except Exception:
        pass
    spans.sort(key=lambda x: (x["start"], x["end"]))

    spans = _attach_address_numbers(spans, text, max_gap=1)
    spans = _attach_address_left_context(spans, text, max_back_steps=3)
    spans = _filter_short_lc(spans, text)
    spans.sort(key=lambda x: (x["start"], x["end"]))
    return spans
