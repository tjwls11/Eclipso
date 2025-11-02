from __future__ import annotations

import re
import traceback
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, UploadFile, HTTPException
from pydantic import BaseModel

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS, RULES
from server.core.normalize import normalize_text

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
    start: Optional[int] = None
    end: Optional[int] = None
    location: Optional[Dict[str, int]] = None  # {start, end}

class MatchResponse(BaseModel):
    items: List[MatchItem]
    counts: Dict[str, int]

class MatchRequest(BaseModel):
    text: str
    rules: Optional[List[str]] = None
    normalize: bool = True

def _compile_selected(selected: Optional[List[str]]):
    """PRESET_PATTERNS에서 선택된 룰만 컴파일."""
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
            continue
        ensure_valid = bool(p.get("ensure_valid", True))
        out.append((name, rx, ensure_valid))
    return out

def _validate(name: str, value: str) -> bool:
    """RULES.validator가 있으면 OK/FAIL 판정, 없으면 True."""
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

@router.post(
    "/extract",
    response_model=ExtractResponse,
    summary="파일에서 텍스트 추출",
    description="업로드한 문서에서 본문 텍스트를 추출하여 반환"
)
async def extract_text(file: UploadFile):
    try:
        raw = await extract_from_file(file)
        text = normalize_text(raw or "")
        return ExtractResponse(full_text=text)
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(500, detail=f"서버 내부 오류: {e}")

@router.get(
    "/rules",
    summary="정규식 규칙 이름 목록",
    description="서버에 등록된 개인정보 정규식 규칙들의 이름 배열을 반환"
)
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]

@router.post(
    "/match",
    response_model=MatchResponse,
    summary="정규식 매칭 실행",
    description="입력 텍스트에 대해 선택 규칙으로 정규식 매칭 결과를 반환"
)
async def match(req: MatchRequest):
    try:
        text = normalize_text(req.text or "") if req.normalize else (req.text or "")
        comp = _compile_selected(req.rules)

        items: List[MatchItem] = []
        counts: Dict[str, int] = {}

        for (name, rx, need_valid) in comp:
            c = 0
            for m in rx.finditer(text):
                i, j = m.start(), m.end()
                val = m.group(0)
                ok = _validate(name, val) if need_valid else True
                items.append(
                    MatchItem(
                        rule=name,
                        value=val,
                        valid=ok,
                        context=_ctx(text, i, j),
                        start=i,
                        end=j,
                        location={"start": i, "end": j}
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
            regex_result = regex_match_text(text)
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
