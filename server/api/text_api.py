# -*- coding: utf-8 -*-
from __future__ import annotations

import re
import traceback
from typing import List, Dict, Optional

from fastapi import APIRouter, UploadFile, HTTPException
from pydantic import BaseModel

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS, RULES

# --- 정규화 함수 호환 래퍼 (normalize_text 없는 브랜치 대비) ---
try:
    # 신형: normalize_text 존재
    from server.core.normalize import normalize_text  # type: ignore
except Exception:
    # 구형: normalize()만 있는 경우
    try:
        from server.core.normalize import normalize as _normalize  # type: ignore

        def normalize_text(s: str) -> str:
            r = _normalize(s)
            # (정규화문자열, 인덱스맵) 형태일 수 있음 → 문자열만 사용
            if isinstance(r, (list, tuple)):
                return r[0]
            return r if isinstance(r, str) else str(r)
    except Exception:
        # 최후 안전장치: 정규화 모듈이 전혀 없으면 원문 반환
        def normalize_text(s: str) -> str:
            return s

# 정규식 매칭 유틸과 병합 정책
from server.api.redaction_api import match_text as regex_match_text
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY

router = APIRouter(prefix="/text", tags=["text"])

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
        except re.error:
            continue  # 문제가 있는 정규식은 스킵(서버 안정성 우선)
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
        # 일부 validator는 (value, context) 시그니처
        return bool(fn(value, None))

def _ctx(s: str, i: int, j: int, pad: int = 30) -> str:
    a = max(0, i - pad)
    b = min(len(s), j + pad)
    return s[a:b]


@router.post(
    "/extract",
    response_model=ExtractResponse,
    summary="파일에서 텍스트 추출",
    description="업로드한 문서에서 본문 텍스트를 추출하여 반환"
)
async def extract_text(file: UploadFile):
    """
    업로드 문서에서 텍스트를 추출해 { full_text }로 반환.
    """
    try:
        raw = await extract_from_file(file)  # 문자열
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

@router.get(
    "/policy",
    summary="기본 병합 정책 조회",
    description="정규식·NER 탐지 결과 병합에 사용하는 기본 정책을 반환"
)
async def get_policy():
    return DEFAULT_POLICY

@router.put(
    "/policy",
    summary="병합 정책 설정",
    description="허용 라벨·우선순위 등 병합 정책을 갱신(전달값을 그대로 반환)"
)
async def set_policy(policy: dict):
    return {"ok": True, "policy": policy}

@router.post(
    "/detect",
    summary="정규식+NER 통합 탐지",
    description="정규식과 NER을 선택 실행하고 정책에 따라 병합된 결과를 반환"
)
async def detect(req: dict):
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = (req or {}).get("policy") or DEFAULT_POLICY

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

    # 1) 정규식 결과(유틸 재사용)
    regex_result = {"items": []}
    if run_regex_opt:
        try:
            regex_result = regex_match_text(text)  # {items:[{start,end,rule,...}], counts:{...}}
        except Exception as e:
            regex_result = {"items": [], "error": f"regex_failed: {e}"}

    regex_spans: List[Dict[str, Any]] = []
    for it in regex_result.get("items", []):
        s, e = it.get("start"), it.get("end")
        if s is None or e is None or e <= s:
            continue
        label = it.get("rule") or it.get("label") or it.get("name") or "REGEX"
        regex_spans.append({
            "start": int(s),
            "end": int(e),
            "label": str(label),
            "source": "regex",
            "score": None
        })

    # 2) NER 결과
    ner_spans: List[Dict[str, Any]] = []
    ner_raw_preview: Any = None
    if run_ner_opt:
        try:
            from server.api.ner_api import ner_predict_blocking
            raw_res = ner_predict_blocking(text, labels=policy.get("allowed_labels"))
            ner_raw_preview = raw_res.get("raw")
        except Exception:
            ner_raw_preview = {"error": "ner_raw_preview_failed"}
        from server.modules.ner_module import run_ner
        ner_spans = run_ner(text=text, policy=policy)

    # 3) 병합
    merger = MergePolicy(policy)
    final_spans, report = merger.merge(
        text, regex_spans, ner_spans, degrade=(run_ner_opt is False)
    )

    return {
        "text": text,
        "final_spans": final_spans,
        "report": report,
        "debug": {
            "run_regex": run_regex_opt,
            "run_ner": run_ner_opt,
            "ner_span_count": len(ner_spans),
            "ner_span_head": ner_spans[:5],
            "ner_raw_preview": ner_raw_preview
        }
    }
