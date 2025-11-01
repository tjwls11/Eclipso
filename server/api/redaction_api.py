# -*- coding: utf-8 -*-
from __future__ import annotations
import json
import logging
import re
import traceback
import os
import tempfile
import urllib.parse
from typing import List, Optional, Dict, Any

from fastapi import APIRouter, UploadFile, File, Form, Response, HTTPException

from server.core.schemas import DetectResponse, PatternItem
from server.modules.pdf_module import detect_boxes_from_patterns, apply_redaction
from server.core.redaction_rules import PRESET_PATTERNS, RULES

# XML 계열 처리 모듈 (존재/시그니처 불일치까지 호환)
try:
    from server.modules.xml_redaction import xml_scan, xml_redact_to_file
except Exception:
    xml_scan = None
    xml_redact_to_file = None

router = APIRouter(tags=["redaction"])
log = logging.getLogger("redaction.router")


# ---------------------------
# 공통 유틸
# ---------------------------
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
    if not patterns_json:
        return [PatternItem(**p) for p in PRESET_PATTERNS]

    try:
        obj = json.loads(s)
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400,
            detail=(
                "잘못된 patterns_json: JSON 파싱 실패. 예: {'patterns': [...]} 또는 [...]. "
                f"구체적 오류: {e}"
            ),
        )

    if isinstance(obj, dict):
        if "patterns" in obj and isinstance(obj["patterns"], list):
            arr = obj["patterns"]
        else:
            raise HTTPException(
                status_code=400,
                detail="잘못된 patterns_json: 'patterns' 키에 리스트 필요",
            )
    elif isinstance(obj, list):
        arr = obj
    else:
        raise HTTPException(
            status_code=400,
            detail="잘못된 patterns_json: 리스트 또는 {'patterns': 리스트} 형태",
        )

    try:
        return [PatternItem(**p) for p in arr]
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"잘못된 patterns_json: {e}")

def _as_jsonable(obj: Any) -> Any:
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
    """
    라틴-1만 허용되는 헤더 특성 때문에:
      - ASCII로 안전한 대체값을 filename에 넣고
      - 원래 UTF-8 파일명은 RFC 5987 형식의 filename*로 추가
    """
    base = filename or "download.bin"
    # ASCII 대체: 알파벳/숫자/._-만 남기고 나머지는 _
    ascii_fallback = re.sub(r'[^A-Za-z0-9._-]', '_', base)
    # RFC 5987 percent-encoding
    quoted = urllib.parse.quote(base, safe="")
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quoted}"


# ---------------------------
# /patterns  (프론트 초기 로딩)
# ---------------------------
@router.get("/patterns")
def get_patterns() -> Dict[str, Any]:
    """규칙 목록 제공 (프론트 app.js 에서 호출)"""
    return {
        "patterns": [
            {
                "name": p.get("name"),
                "regex": p.get("regex"),
                "case_sensitive": bool(p.get("case_sensitive", False)),
                "whole_word": bool(p.get("whole_word", False)),
                # validator 통과시에만 OK로 취급하도록 기본 True
                "ensure_valid": bool(p.get("ensure_valid", True)),
            }
            for p in PRESET_PATTERNS
        ]
    }


# ---------------------------
# PDF: 박스 검출 / 적용 (기존 유지)
# ---------------------------
@router.post("/redactions/detect", response_model=DetectResponse)
async def detect(file: UploadFile = File(...), patterns_json: Optional[str] = Form(None)):
    _ensure_pdf(file)
    pdf = await file.read()

    # 로깅(옵션)
    if patterns_json is None:
        log.debug("patterns_json: None")
    else:
        log.debug("patterns_json(len=%d): %r", len(patterns_json), patterns_json[:200])

    items = _parse_patterns_json(patterns_json)
    patterns = _compile_patterns(items)
    boxes = detect_boxes_from_patterns(pdf, patterns)
    return DetectResponse(total_matches=len(boxes), boxes=boxes)


@router.post(
    "/redactions/apply",
    response_class=Response,
    summary="PDF 레닥션 적용",
    description="기본 정규식 패턴으로 레닥션 적용.",
)
async def apply(
    file: UploadFile = File(..., description="PDF 파일"),
):
    _ensure_pdf(file)
    pdf = _read_all(file)
    boxes = detect_boxes_from_patterns(pdf, [PatternItem(**p) for p in PRESET_PATTERNS])
    out = apply_redaction(pdf, boxes, fill=fill)
    disp = build_disposition("redacted.pdf")
    return Response(content=out, media_type="application/pdf",
                    headers={"Content-Disposition": disp})


# ---------------------------
# 프론트 호환 라우트: /redactions/pdf/scan
# ---------------------------
@router.post("/redactions/pdf/scan")
async def pdf_scan(file: UploadFile = File(...), patterns_json: Optional[str] = Form(None)):
    _ensure_pdf(file)
    pdf = await file.read()
    patterns = _parse_patterns_json(patterns_json)

    boxes = detect_boxes_from_patterns(pdf, patterns)
    # 프론트 호환 형태로 변환 (필요 최소 필드)
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
        "extracted_text": "",   # 원하면 /text/extract 연동 가능
        "matches": matches,
    }


# ---------------------------
# 프론트 호환 라우트: /redactions/xml/scan
# ---------------------------
@router.post("/redactions/xml/scan")
async def xml_scan_endpoint(
    file: UploadFile = File(...),
    patterns_json: Optional[str] = Form(None),
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


# ---------------------------
# 프론트 호환 라우트: /redactions/xml/apply
#   ※ 경로 기반/바이트 기반 모든 시그니처를 순차 지원
# ---------------------------
@router.post("/redactions/xml/apply", response_class=Response)
async def xml_apply_endpoint(file: UploadFile = File(...)):
    if xml_redact_to_file is None:
        raise HTTPException(status_code=500, detail="xml_redaction 모듈을 불러오지 못했습니다.")

    data = _read_all(file)
    base = (file.filename or "output")
    stem = base.rsplit(".", 1)[0]
    ext = base.rsplit(".", 1)[-1].lower() if "." in base else "bin"

    # MIME 대략치
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

    # 업로드 바이트를 임시 원본 파일로 저장 → 경로 기반 호출
    with tempfile.TemporaryDirectory(prefix="eclipso_") as tdir:
        src_path = os.path.join(tdir, base)
        with open(src_path, "wb") as wf:
            wf.write(data)

        dst_path = os.path.join(tdir, f"{stem}.redacted.{ext}")

        # 1) (src_path, dst_path, filename)
        try:
            res = xml_redact_to_file(src_path, dst_path, base)
            # 결과가 바이트면 즉시 사용, 아니면 dst_path에서 읽음
            if isinstance(res, (bytes, bytearray)):
                out_bytes = bytes(res)
                out_name = f"{stem}.redacted.{ext}"
            else:
                if not os.path.exists(dst_path):
                    if isinstance(res, str) and os.path.exists(res):
                        dst_path = res
                    elif res and isinstance(res, (list, tuple)) and len(res) > 0 and isinstance(res[0], str) and os.path.exists(res[0]):
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
                # (bytes, name, mime) 또는 경로 반환일 수 있음
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
            # 최후: 바이트 시그니처 시도
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
            except Exception as e2:
                raise HTTPException(status_code=500, detail=f"xml_redact_to_file 시그니처 불일치: {e2}")
