# -*- coding: utf-8 -*-
from __future__ import annotations
import re
import traceback
from typing import List, Dict, Optional

from fastapi import APIRouter, UploadFile, HTTPException
from pydantic import BaseModel

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS, RULES
from server.core.normalize import normalize_text

router = APIRouter(prefix="/text", tags=["text"])

# ---------- models ----------
class ExtractResponse(BaseModel):
    full_text: str

class MatchItem(BaseModel):
    rule: str
    value: str
    valid: bool
    context: str

class MatchResponse(BaseModel):
    items: List[MatchItem]
    counts: Dict[str, int]

class MatchRequest(BaseModel):
    text: str
    rules: Optional[List[str]] = None
    normalize: bool = True

# ---------- helpers ----------
def _compile_selected(selected: Optional[List[str]]):
    """PRESET_PATTERNS에서 선택된 룰만 (name, compiled_regex, ensure_valid)로 컴파일"""
    # 선택이 비어있으면 모든 프리셋 사용
    want = set(selected or [p["name"] for p in PRESET_PATTERNS])
    out = []
    for p in PRESET_PATTERNS:
        name = p["name"]
        if name not in want:
            continue
        pat = p["regex"]
        flags = 0 if p.get("case_sensitive") else re.IGNORECASE
        if p.get("whole_word"):
            pat = rf"\b(?:{pat})\b"
        out.append((name, re.compile(pat, flags), True))  # ensure_valid는 항상 True로 처리
    return out

def _validate(name: str, value: str) -> bool:
    rule = RULES.get((name or "").lower())
    if not rule:
        return True
    fn = rule.get("validator")
    if not callable(fn):
        return True
    try:
        return bool(fn(value))
    except TypeError:
        return bool(fn(value, None))

def _ctx(s: str, i: int, j: int, pad: int = 30) -> str:
    a = max(0, i - pad)
    b = min(len(s), j + pad)
    return s[a:b]

# ---------- endpoints ----------
@router.post("/extract", response_model=ExtractResponse)
async def extract_text(file: UploadFile):
    """
    클라이언트가 기대하는 JSON 스키마에 맞춰 { full_text }로 반환.
    """
    try:
        raw = await extract_from_file(file)  # 문자열
        text = normalize_text(raw or "")
        return ExtractResponse(full_text=text)
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, detail=f"서버 내부 오류: {e}")
# :contentReference[oaicite:1]{index=1}

@router.get("/rules")
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]
# :contentReference[oaicite:2]{index=2}

@router.post("/match", response_model=MatchResponse)
async def match(req: MatchRequest):
    """
    프론트가 보내는 rules/normalize를 반영해 선택 룰만 매칭.
    """
    try:
        text = normalize_text(req.text or "") if req.normalize else (req.text or "")
        comp = _compile_selected(req.rules)

        items: List[MatchItem] = []
        counts: Dict[str, int] = {}

        for (name, rx, _need_valid) in comp:
            c = 0
            for m in rx.finditer(text):
                val = m.group(0)
                ok = _validate(name, val)
                items.append(
                    MatchItem(rule=name, value=val, valid=ok, context=_ctx(text, m.start(), m.end()))
                )
                c += 1
            counts[name] = c

        return MatchResponse(items=items, counts=counts)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, detail=f"매칭 오류: {e}")
# :contentReference[oaicite:3]{index=3}
