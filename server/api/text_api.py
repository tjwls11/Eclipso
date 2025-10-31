from __future__ import annotations
from fastapi import APIRouter, UploadFile, HTTPException
from typing import Dict, Any, List

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text  # 기존 정규식 매칭 유틸
from server.core.merge_policy import MergePolicy, DEFAULT_POLICY

router = APIRouter(prefix="/text", tags=["text"])

# ──────────────────────────────────────────────────────────────────────────────
@router.post("/extract")
async def extract_text(file: UploadFile):
    try:
        return await extract_from_file(file)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(500, detail=f"서버 내부 오류: {e}")

# ──────────────────────────────────────────────────────────────────────────────
@router.get("/rules")
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]

# ──────────────────────────────────────────────────────────────────────────────
@router.post("/match")
async def match(req: dict):
    text = (req or {}).get("text", "") or ""
    return match_text(text)

# ──────────────────────────────────────────────────────────────────────────────
@router.get("/policy")
async def get_policy():
    return DEFAULT_POLICY

@router.put("/policy")
async def set_policy(policy: dict):
    return {"ok": True, "policy": policy}

# ──────────────────────────────────────────────────────────────────────────────
@router.post("/detect")
async def detect(req: dict):
    """
    req = {
      "text": "...",
      "options": {"run_regex": true, "run_ner": true},
      "policy": {...}  # 없으면 DEFAULT_POLICY 사용
    }
    """
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = (req or {}).get("policy") or DEFAULT_POLICY

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

    # 1) 정규식
    regex_result = match_text(text) if run_regex_opt else {"items": []}
    regex_spans: List[Dict[str, Any]] = []
    for it in regex_result.get("items", []):
        s, e = it.get("start"), it.get("end")
        if s is None or e is None or e <= s:
            continue
        label = it.get("label") or it.get("name") or "REGEX"
        regex_spans.append({
            "start": int(s),
            "end": int(e),
            "label": str(label),
            "source": "regex",
            "score": None
        })

    # 2) NER (+ 디버그 원시 미리보기)
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

    # 3) 병합(정책: 정규식=레닥션, NER=하이라이트, QT 민감=레닥션)
    merger = MergePolicy(policy)
    final_spans, report = merger.merge(text, regex_spans, ner_spans, degrade=(run_ner_opt is False))

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
