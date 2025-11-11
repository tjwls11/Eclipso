from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import urllib.parse
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, UploadFile, File, Form, Response, HTTPException

from server.core.schemas import DetectResponse, PatternItem
from server.modules.pdf_module import detect_boxes_from_patterns, apply_redaction
from server.core.redaction_rules import PRESET_PATTERNS
from server.core.matching import find_sensitive_spans

# XML 계열 처리 모듈(존재/시그니처 호환)
try:
    from server.modules.xml_redaction import xml_scan, xml_redact_to_file
except Exception:  # pragma: no cover
    xml_scan = None
    xml_redact_to_file = None

router = APIRouter(tags=["redaction"])
log = logging.getLogger("redaction.router")


def _ensure_pdf(file: UploadFile) -> None:
    if file is None:
        raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")
    if file.content_type not in ("application/pdf", "application/octet-stream"):
        raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")

def _read_all(file: UploadFile) -> bytes:
    data = file.file.read()
    if not data:
        raise HTTPException(status_code=400, detail="빈 파일입니다.")
    return data

def _parse_patterns_json(patterns_json: Optional[str]) -> List[PatternItem]:
    """프론트 patterns_json -> PatternItem[] (없으면 PRESET 전체)."""
    if patterns_json is None:
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    s = str(patterns_json).strip()
    if not s or s.lower() in ("null", "none"):
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    try:
        obj = json.loads(s)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail=("잘못된 patterns_json: JSON 파싱 실패. 예: {'patterns': [...]} 또는 [...]. "
                    f"구체적 오류: {e}")
        )

    if isinstance(obj, dict):
        if "patterns" in obj and isinstance(obj["patterns"], list):
            arr = obj["patterns"]
        else:
            raise HTTPException(status_code=400, detail="잘못된 patterns_json: 'patterns' 키에 리스트 필요")
    elif isinstance(obj, list):
        arr = obj
    else:
        raise HTTPException(status_code=400, detail="잘못된 patterns_json: 리스트 또는 {'patterns': 리스트} 형태")

    try:
        return [PatternItem(**p) for p in arr]
    except Exception as e:  # pragma: no cover
        raise HTTPException(status_code=400, detail=f"잘못된 patterns 항목: {e}")

def _as_jsonable(obj: Any) -> Any:
    """pydantic 모델/일반객체를 프론트가 소비 가능한 형태로 변환"""
    try:
        if obj is None:
            return {}
        if hasattr(obj, "model_dump") and callable(obj.model_dump):
            return obj.model_dump()
        if hasattr(obj, "dict") and callable(obj.dict):
            return obj.dict()
        if isinstance(obj, (list, dict, str, int, float, bool)):
            return obj
        return json.loads(json.dumps(obj, default=str))
    except Exception:
        return {"result": str(obj)}

def build_disposition(filename: str) -> str:
    """Content-Disposition 헤더(UTF-8 안전) 생성"""
    base = filename or "download.bin"
    ascii_fallback = re.sub(r'[^A-Za-z0-9._-]', '_', base)
    quoted = urllib.parse.quote(base, safe="")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quoted}"


@router.get(
    "/patterns",
    summary="패턴 목록",
    description="서버에 등록된 정규식 패턴(PRESET) 목록 제공"
)
def get_patterns() -> Dict[str, Any]:
    return {
        "patterns": [
            {
                "name": p.get("name"),
                "regex": p.get("regex"),
                "case_sensitive": bool(p.get("case_sensitive", False)),
                "whole_word": bool(p.get("whole_word", False)),
                "ensure_valid": bool(p.get("ensure_valid", True)),
            }
            for p in PRESET_PATTERNS
        ]
    }

@router.post(
    "/redactions/detect",
    response_model=DetectResponse,
    summary="PDF 패턴 박스 검출",
    description="PDF에서 정규식 패턴 위치를 박스로 탐지"
)
async def detect(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(None, description="패턴 목록 JSON(옵션)")
):
    _ensure_pdf(file)
    pdf = await file.read()

    if patterns_json is None:
        log.debug("patterns_json: None")
    else:
        log.debug("patterns_json(len=%d): %r", len(patterns_json), patterns_json[:200])

    patterns = _parse_patterns_json(patterns_json)
    boxes = detect_boxes_from_patterns(pdf, patterns)
    return DetectResponse(total_matches=len(boxes), boxes=boxes)

@router.post(
    "/redactions/apply",
    response_class=Response,
    summary="PDF 레닥션 적용",
    description="PDF에 감지 박스를 채워 레닥션된 PDF 반환"
)
async def apply_pdf(
    file: UploadFile = File(..., description="PDF 파일"),
    mode: Optional[str] = Form(None),
    fill: Optional[str] = Form("black"),
    patterns_json: Optional[str] = Form(None),
):
    _ensure_pdf(file)
    pdf = _read_all(file)

    patterns = _parse_patterns_json(patterns_json)
    fill_color = (fill or "black").lower()

    boxes = detect_boxes_from_patterns(pdf, patterns)
    out = apply_redaction(pdf, boxes, fill=fill_color)

    disp = build_disposition("redacted.pdf")
    return Response(
        content=out,
        media_type="application/pdf",
        headers={"Content-Disposition": disp},
    )

@router.post(
    "/redactions/pdf/scan",
    summary="프론트 호환: PDF 스캔",
    description="프론트 공통 스키마로 PDF 스캔 결과 반환"
)
async def pdf_scan(
    file: UploadFile = File(...),
    patterns_json: Optional[str] = Form(None),
):
    _ensure_pdf(file)
    pdf = await file.read()
    patterns = _parse_patterns_json(patterns_json)

    boxes = detect_boxes_from_patterns(pdf, patterns)

    matches = []
    for b in boxes:
        matches.append({
            "rule": getattr(b, "rule", getattr(b, "name", "pdf")),
            "value": "",
            "page": getattr(b, "page", None),
            "location": None,
            "context": "",
            "valid": True,
        })

    return {
        "file_type": "pdf",
        "extracted_text": "",
        "matches": matches,
    }

@router.post(
    "/redactions/xml/scan",
    summary="프론트 호환: XML 스캔",
    description="DOCX/XLSX/PPTX/HWPX 스캔 결과를 프론트 공통 스키마로 반환"
)
async def xml_scan_endpoint(
    file: UploadFile = File(...),
    patterns_json: Optional[str] = Form(None),  # 구조 호환을 위해 유지(실사용 X)
):
    if xml_scan is None:
        raise HTTPException(status_code=500, detail="xml_redaction 모듈을 불러오지 못했습니다.")

    data = _read_all(file)
    try:
        # 신형: xml_scan(bytes, filename)
        res = xml_scan(data, file.filename or "")
    except TypeError:
        # 구형: xml_scan(bytes)
        res = xml_scan(data)

    return _as_jsonable(res)

@router.post(
    "/redactions/xml/apply",
    response_class=Response,
    summary="프론트 호환: XML 레닥션 적용",
    description="DOCX/XLSX/PPTX/HWPX에 레닥션 적용된 파일 반환"
)
async def xml_apply_endpoint(file: UploadFile = File(...)):
    if xml_redact_to_file is None:
        raise HTTPException(status_code=500, detail="xml_redaction 모듈을 불러오지 못했습니다.")

    data = _read_all(file)
    base = (file.filename or "output")
    stem = base.rsplit(".", 1)[0]
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else "bin"

    ext_to_mime = {
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "hwpx": "application/haansofthwp",
        "hwp":  "application/x-hwp",
        "xml":  "application/xml",
        "zip":  "application/zip",
        "bin":  "application/octet-stream",
    }
    default_mime = ext_to_mime.get(ext, "application/octet-stream")

    # 임시 디렉토리 내 경로 기반 호출 우선
    with tempfile.TemporaryDirectory(prefix="eclipso_") as tdir:
        src_path = os.path.join(tdir, base)
        with open(src_path, "wb") as wf:
            wf.write(data)

        dst_path = os.path.join(tdir, f"{stem}.redacted.{ext}")

        # 1) (src_path, dst_path, filename)
        try:
            res = xml_redact_to_file(src_path, dst_path, base)
            if isinstance(res, (bytes, bytearray)):
                out_bytes = bytes(res)
                out_name = f"{stem}.redacted.{ext}"
            else:
                # 결과 경로 확인
                if not os.path.exists(dst_path):
                    if isinstance(res, str) and os.path.exists(res):
                        dst_path = res
                    elif (isinstance(res, (list, tuple)) and res and isinstance(res[0], str)
                          and os.path.exists(res[0])):
                        dst_path = res[0]
                    else:
                        raise HTTPException(status_code=500, detail="레닥션 결과 파일이 생성되지 않았습니다.")
                with open(dst_path, "rb") as rf:
                    out_bytes = rf.read()
                out_name = os.path.basename(dst_path)

            disp = build_disposition(out_name)
            return Response(content=out_bytes, media_type=default_mime,
                            headers={"Content-Disposition": disp})
        except TypeError:
            pass

        # 2) (src_path, filename)
        try:
            res = xml_redact_to_file(src_path, base)
            if isinstance(res, (bytes, bytearray)):
                out_bytes = bytes(res)
                out_name = f"{stem}.redacted.{ext}"
                disp = build_disposition(out_name)
                return Response(content=out_bytes, media_type=default_mime,
                                headers={"Content-Disposition": disp})
            else:
                if isinstance(res, str) and os.path.exists(res):
                    with open(res, "rb") as rf:
                        out_bytes = rf.read()
                    out_name = os.path.basename(res)
                    disp = build_disposition(out_name)
                    return Response(content=out_bytes, media_type=default_mime,
                                    headers={"Content-Disposition": disp})
                if isinstance(res, (list, tuple)) and len(res) > 0:
                    if isinstance(res[0], (bytes, bytearray)):
                        out_bytes = bytes(res[0])
                        out_name = res[1] if len(res) > 1 else f"{stem}.redacted.{ext}"
                        out_mime = res[2] if len(res) > 2 else default_mime
                        disp = build_disposition(out_name)
                        return Response(content=out_bytes, media_type=out_mime,
                                        headers={"Content-Disposition": disp})
                    if isinstance(res[0], str) and os.path.exists(res[0]):
                        with open(res[0], "rb") as rf:
                            out_bytes = rf.read()
                        out_name = os.path.basename(res[0])
                        disp = build_disposition(out_name)
                        return Response(content=out_bytes, media_type=default_mime,
                                        headers={"Content-Disposition": disp})

                # 파일 생성 기대: dst_path 확인
                if not os.path.exists(dst_path):
                    raise HTTPException(status_code=500, detail="레닥션 결과 파일이 생성되지 않았습니다.")
                with open(dst_path, "rb") as rf:
                    out_bytes = rf.read()
                out_name = os.path.basename(dst_path)
                disp = build_disposition(out_name)
                return Response(content=out_bytes, media_type=default_mime,
                                headers={"Content-Disposition": disp})
        except TypeError:
            pass

        # 3) (src_path)
        try:
            res = xml_redact_to_file(src_path)
            if isinstance(res, (bytes, bytearray)):
                out_bytes = bytes(res)
                out_name = f"{stem}.redacted.{ext}"
            elif isinstance(res, str) and os.path.exists(res):
                with open(res, "rb") as rf:
                    out_bytes = rf.read()
                out_name = os.path.basename(res)
            else:
                if not os.path.exists(dst_path):
                    raise HTTPException(status_code=500, detail="레닥션 결과 파일이 생성되지 않았습니다.")
                with open(dst_path, "rb") as rf:
                    out_bytes = rf.read()
                out_name = os.path.basename(dst_path)

            disp = build_disposition(out_name)
            return Response(content=out_bytes, media_type=default_mime,
                            headers={"Content-Disposition": disp})
        except TypeError:
            # 4) 최후: (bytes, filename) / (bytes, name, mime)
            try:
                res = xml_redact_to_file(data, base)
                if isinstance(res, (bytes, bytearray)):
                    out_bytes = bytes(res)
                    out_name = f"{stem}.redacted.{ext}"
                    disp = build_disposition(out_name)
                    return Response(content=out_bytes, media_type=default_mime,
                                    headers={"Content-Disposition": disp})
                else:
                    out_bytes = res[0]
                    out_name = res[1] if len(res) > 1 else f"{stem}.redacted.{ext}"
                    out_mime = res[2] if len(res) > 2 else default_mime
                    disp = build_disposition(out_name)
                    return Response(content=out_bytes, media_type=out_mime,
                                    headers={"Content-Disposition": disp})
            except Exception as e2:  # pragma: no cover
                raise HTTPException(status_code=500, detail=f"xml_redact_to_file 시그니처 불일치: {e2}")


def match_text(text: str):
    """
    정규식 기반 민감정보 매칭 유틸
    반환: { items, counts }
    항목: rule, value, start, end, context, valid
    """
    try:
        if not isinstance(text, str):
            text = str(text)

        results = find_sensitive_spans(text)
        matches = []
        counts: Dict[str, int] = {}

        for start, end, value, rule_name in results:
            ctx_start = max(0, start - 20)
            ctx_end = min(len(text), end + 20)
            matches.append({
                "rule": rule_name,
                "value": value,
                "start": start,
                "end": end,
                "context": text[ctx_start:ctx_end],
                "valid": True,
            })
            counts[rule_name] = counts.get(rule_name, 0) + 1

        log.debug("regex match count=%d", len(matches))
        return {"items": matches, "counts": counts}

    except Exception as e:  # pragma: no cover
        log.exception("match_text 내부 오류")
        raise HTTPException(status_code=500, detail=f"매칭 오류: {e}")
