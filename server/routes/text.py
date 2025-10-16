from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from ..redac_rules import RULES
from ..normalize import normalize_text
from ..extract_text import extract_text_from_file

router = APIRouter(tags=["text"])

# ---------- 데이터 모델 ----------
class MatchRequest(BaseModel):
    text: str
    rules: Optional[List[str]] = None
    options: Optional[Dict[str, Any]] = None  # 예: {"rrn_checksum": true, "luhn": true }
    normalize: bool = True                    # 서버 측 정규화 사용 여부(기본 사용)

class MatchItem(BaseModel):
    rule: str
    value: str
    valid: bool
    index: int
    end: int
    context: str

class MatchResponse(BaseModel):
    counts: Dict[str, int]
    items: List[MatchItem]

# 기본 규칙 우선순위
DEFAULT_ORDER = [
    "rrn", "fgn", "email", "phone_mobile", "phone_city",
    "card", "passport", "driver_license"
]

# ---------- API ----------
@router.get("/text/rules")
async def list_rules():
    # 존재하는 RULES 중 DEFAULT_ORDER 순서대로 반환
    return [r for r in DEFAULT_ORDER if r in RULES]

@router.post("/text/extract")
async def extract(file: UploadFile = File(...)):
    try:
        return await extract_text_from_file(file)
    except Exception as e:
        raise HTTPException(status_code=415, detail=str(e))

def _ctx(text: str, start: int, end: int, window: int = 25) -> str:
    return text[max(0, start - window): start] + "【" + text[start:end] + "】" + text[end: end + window]

def _mask_ranges_same_length(s: str, spans, mask_char: str = "R") -> str:
    if not spans: return s
    arr = list(s)
    L = len(arr)
    for st, ed in spans:
        st = max(0, min(st, L)); ed = max(0, min(ed, L))
        for i in range(st, ed):
            if arr[i].isdigit() or arr[i] in "- /":
                arr[i] = mask_char
    return "".join(arr)

@router.post("/text/match", response_model=MatchResponse)
async def match(req: MatchRequest):
    text_in = req.text or ""
    original_text = normalize_text(text_in) if req.normalize else text_in
    working_text = original_text

    selected = req.rules or list(RULES.keys())
    selected = [r for r in selected if r in RULES]
    ordered_rules = [r for r in DEFAULT_ORDER if r in selected]

    results: List[Dict[str, Any]] = []

    # 주민번호 먼저 탐지 후 마스킹
    rrn_spans = []
    if "rrn" in ordered_rules:
        regex = RULES["rrn"]["regex"]
        validator = RULES["rrn"]["validator"]
        for m in regex.finditer(working_text):
            value = m.group(); start, end = m.start(), m.end()
            valid = False
            try:
                valid = bool(validator(value, req.options))
            except Exception:
                valid = False
            results.append({
                "rule": "rrn", "value": value, "valid": valid,
                "index": start, "end": end, "context": _ctx(original_text, start, end)
            })
            rrn_spans.append((start, end))
        working_text = _mask_ranges_same_length(working_text, rrn_spans, "R")

    # 나머지 규칙 탐지
    for rid in ordered_rules:
        if rid == "rrn": continue
        regex = RULES[rid]["regex"]
        validator = RULES[rid]["validator"]
        for m in regex.finditer(working_text):
            value = m.group(); start, end = m.start(), m.end()
            valid = False
            try:
                valid = bool(validator(value, req.options))
            except Exception:
                valid = False
            results.append({
                "rule": rid, "value": value, "valid": valid,
                "index": start, "end": end, "context": _ctx(original_text, start, end)
            }) 

    # 카운트 집계
    counts = {rid: 0 for rid in ordered_rules}
    for r in results:
        counts[r["rule"]] = counts.get(r["rule"], 0) + 1

    return {"counts": counts, "items": results}
