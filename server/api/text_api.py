from __future__ import annotations
from fastapi import APIRouter, UploadFile, HTTPException
from typing import Dict, Any, List

from server.utils.file_reader import extract_from_file
from server.core.redaction_rules import PRESET_PATTERNS
from server.api.redaction_api import match_text
from server.modules.pdf_module import extract_markdown as extract_pdf_markdown

router = APIRouter(prefix="/text", tags=["text"])


@router.post(
    "/extract",
    summary="파일에서 텍스트 추출",
    description="업로드한 문서에서 본문 텍스트를 추출하여 반환",
)
async def extract_text(file: UploadFile):
    try:
        return await extract_from_file(file)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(500, detail=f"서버 내부 오류: {e}")


@router.get(
    "/rules",
    summary="정규식 규칙 이름 목록",
    description="서버에 등록된 개인정보 정규식 규칙들의 이름 배열을 반환",
)
async def list_rules():
    return [r["name"] for r in PRESET_PATTERNS]


@router.post(
    "/match",
    summary="정규식 매칭 실행",
    description="입력 텍스트에 대해 정규식 기반 개인정보 패턴(시작/끝 인덱스, 라벨 등)을 탐지하여 반환",
)
async def match(req: dict):
    text = (req or {}).get("text", "") or ""
    return match_text(text)


@router.post(
    "/detect",
    summary="정규식+NER 통합 탐지",
    description=(
        "정규식과 NER을 선택적으로 실행하고, 정책에 따라 결과를 병합하여 반환\n"
        "- options.run_regex / options.run_ner 로 각 탐지 실행 여부를 제어\n"
        "- policy를 함께 전달하면 기본 정책 대신 해당 정책이 병합에 사용됨\n"
        '- 테스트 예시: { \"text\": \"홍길동, 생일은 2004-01-01.소속 중부대학교. 주소는 경기도 고양시 덕양구 동헌로 305. 연락처 010-1234--5678.\", \"options\":  \"run_regex\": true, \"run_ner\": true } }'
    ),
)
async def detect(req: dict):
    text = (req or {}).get("text", "") or ""
    options = (req or {}).get("options", {}) or {}
    policy = (req or {}).get("policy") or {}

    run_regex_opt = bool(options.get("run_regex", True))
    run_ner_opt = bool(options.get("run_ner", True))

    regex_result = match_text(text) if run_regex_opt else {"items": []}
    regex_spans: List[Dict[str, Any]] = []
    for it in regex_result.get("items", []):
        s, e = it.get("start"), it.get("end")
        if s is None or e is None or e <= s:
            continue
        label = it.get("label") or it.get("name") or "REGEX"
        regex_spans.append(
            {
                "start": int(s),
                "end": int(e),
                "label": str(label),
                "source": "regex",
                "score": None,
            }
        )

    masked_text = text
    if run_regex_opt and regex_spans:
        chars = list(text)
        for sp in regex_spans:
            s = int(sp["start"])
            e = int(sp["end"])
            if s < 0:
                s = 0
            if e > len(chars):
                e = len(chars)
            for i in range(s, e):
                if 0 <= i < len(chars) and chars[i] != "\n":
                    chars[i] = " "
        masked_text = "".join(chars)

    ner_spans: List[Dict[str, Any]] = []
    ner_raw_preview: Any = None
    if run_ner_opt:
        try:
            from server.api.ner_api import ner_predict_blocking

            raw_res = ner_predict_blocking(
                masked_text, labels=policy.get("allowed_labels")
            )
            ner_raw_preview = raw_res.get("raw")
        except Exception:
            ner_raw_preview = {"error": "ner_raw_preview_failed"}
        from server.modules.ner_module import run_ner

        ner_spans = run_ner(text=masked_text, policy=policy)

    final_spans = regex_spans + ner_spans
    final_spans.sort(key=lambda x: (x.get("start", 0), x.get("end", 0)))

    filtered_spans: List[Dict[str, Any]] = []
    used_ranges: List[tuple[int, int]] = []

    for span in final_spans:
        start = span.get("start", 0)
        end = span.get("end", 0)
        if end <= start:
            continue
        overlaps = any(
            min(end, used_end) > max(start, used_start)
            for used_start, used_end in used_ranges
        )
        if overlaps:
            continue
        filtered_spans.append(span)
        used_ranges.append((start, end))

    report = {
        "regex_input": len(regex_spans),
        "ner_input": len(ner_spans),
        "final_count": len(filtered_spans),
        "degrade": not run_ner_opt,
    }

    return {
        "text": text,
        "final_spans": filtered_spans,
        "report": report,
        "debug": {
            "run_regex": run_regex_opt,
            "run_ner": run_ner_opt,
            "ner_span_count": len(ner_spans),
            "ner_span_head": ner_spans[:5],
            "ner_raw_preview": ner_raw_preview,
        },
    }

@router.post(
    "/markdown",
    summary="PDF에서 Markdown 텍스트 추출",
    description="업로드한 PDF를 PyMuPDF4LLM으로 변환하여 Markdown 형태로 반환",
)
async def extract_markdown_endpoint(file: UploadFile) -> Dict[str, Any]:
    filename = (file.filename or "").lower()
    if not filename.endswith(".pdf"):
        raise HTTPException(
            status_code=400,
            detail="현재 /text/markdown 엔드포인트는 PDF만 지원합니다.",
        )

    pdf_bytes = await file.read()

    try:
        data = extract_pdf_markdown(pdf_bytes)
    except Exception as e:
        # 내부 오류를 그대로 노출하지 않도록 래핑
        raise HTTPException(
            status_code=500,
            detail=f"Markdown 추출 중 오류: {e}",
        )

    # 그대로 JSON으로 반환
    return data
