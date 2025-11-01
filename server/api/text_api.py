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
    rules: Optional[List[str]] = None   # 지정 안 하면 PRESET 전체
    normalize: bool = True              # True면 서버 표준 정규화 적용

# ---------- helpers ----------
def _compile_selected(selected: Optional[List[str]]):
    """
    PRESET_PATTERNS에서 선택된 룰만 (name, compiled_regex, ensure_valid)로 컴파일.
    - case_sensitive, whole_word 옵션 반영
    """
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
        try:
            rx = re.compile(pat, flags)
        except re.error as e:
            # 문제가 있는 정규식은 스킵(서버 죽지 않도록)
            continue
        ensure_valid = bool(p.get("ensure_valid", True))
        out.append((name, rx, ensure_valid))
    return out

def _validate(name: str, value: str) -> bool:
    """
    RULES에 등록된 validator가 있으면 그것으로 OK/FAIL 판정.
    없으면 True(OK).
    """
    rule = RULES.get((name or "").lower())
    if not rule:
        return True
    fn = rule.get("validator")
    if not callable(fn):
        return True
    try:
        return bool(fn(value))
    except TypeError:
        # 시그니처 차이 허용 (value, _context)
        return bool(fn(value, None))

def _ctx(s: str, i: int, j: int, pad: int = 30) -> str:
    a = max(0, i - pad)
    b = min(len(s), j + pad)
    return s[a:b]

# ---------- endpoints ----------
@router.post("/extract", response_model=ExtractResponse)
async def extract_text(file: UploadFile):
    """
    업로드 문서에서 텍스트를 추출해 { full_text }로 반환.
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

@router.get("/rules")
async def list_rules():
    """정의된 정규식 룰 이름 배열 반환"""
    return [r["name"] for r in PRESET_PATTERNS]

@router.post("/match", response_model=MatchResponse)
async def match(req: MatchRequest):
    """
    선택 룰로 정규식 매칭 수행.
    - req.normalize=True 면 서버 표준 정규화 후 매칭
    - RULES.validator 로 OK/FAIL 판정
    - 컨텍스트 스니펫 포함
    """
    try:
        text = normalize_text(req.text or "") if req.normalize else (req.text or "")
        comp = _compile_selected(req.rules)

        items: List[MatchItem] = []
        counts: Dict[str, int] = {}

        for (name, rx, need_valid) in comp:
            c = 0
            for m in rx.finditer(text):
                val = m.group(0)
                ok = _validate(name, val) if need_valid else True
                items.append(
                    MatchItem(
                        rule=name,
                        value=val,
                        valid=ok,
                        context=_ctx(text, m.start(), m.end())
                    )
                )
                c += 1
            counts[name] = c

        return MatchResponse(items=items, counts=counts)
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, detail=f"매칭 오류: {e}")
