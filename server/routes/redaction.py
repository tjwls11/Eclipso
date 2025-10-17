from __future__ import annotations

import json
import logging
import time
import re
from typing import List, Optional, Literal, Set

from fastapi import APIRouter, UploadFile, File, HTTPException, Response, Form
from fastapi.responses import JSONResponse

# -------- PDF 관련 --------
from ..schemas import DetectResponse, PatternItem, Box
from ..pdf_redaction import detect_boxes_from_patterns, apply_redaction
from ..redac_rules import PRESET_PATTERNS

# -------- XML 관련 --------
from ..schemas import XmlScanResponse
from ..xml_redaction import xml_scan, xml_redact_to_file

# -------- PyMuPDF --------
import fitz  # PyMuPDF

router = APIRouter(tags=["redaction"])
log = logging.getLogger("redaction.router")

# ---------------------------
# 유틸
# ---------------------------
def _ensure_pdf(file: UploadFile) -> None:
    if file is None:
        raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")
    if file.content_type not in ("application/pdf", "application/octet-stream"):
        if not (file.filename or "").lower().endswith(".pdf"):
            raise HTTPException(status_code=400, detail="PDF 파일을 업로드하세요.")

def _read_pdf(file: UploadFile) -> bytes:
    data = file.file.read()
    if not data:
        raise HTTPException(status_code=400, detail="빈 파일입니다.")
    return data

def _default_patterns() -> List[PatternItem]:
    return [PatternItem(**p) for p in PRESET_PATTERNS]

def _parse_patterns_json(patterns_json: Optional[str]) -> List[PatternItem]:
    if not patterns_json:
        return _default_patterns()
    try:
        obj = json.loads(patterns_json)
        if isinstance(obj, dict) and "patterns" in obj:
            obj = obj["patterns"]
        return [PatternItem(**p) for p in obj]
    except Exception as e:
        log.exception("patterns_json 파싱 실패: %s", e)
        raise HTTPException(status_code=400, detail=f"잘못된 patterns_json: {e}")

def _parse_boxes_json(boxes_json: Optional[str]) -> List[Box]:
    if not boxes_json:
        return []
    try:
        obj = json.loads(boxes_json)
        if isinstance(obj, dict) and "boxes" in obj:
            obj = obj["boxes"]
        return [Box(**b) for b in obj]
    except Exception as e:
        log.exception("boxes_json 파싱 실패: %s", e)
        raise HTTPException(status_code=400, detail=f"잘못된 boxes_json: {e}")

def _boxes_from_req(req: Optional[str]):
    if not req:
        return [], None
    try:
        data = json.loads(req)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"잘못된 req JSON: {e}")

    boxes: List[Box] = []
    fill_override: Optional[str] = None

    if isinstance(data, dict):
        if "fill" in data and isinstance(data["fill"], str):
            fill_override = data["fill"]
        if "boxes" in data and isinstance(data["boxes"], list):
            boxes = [Box(**b) for b in data["boxes"]]
        elif isinstance(data.get("boxes"), dict) and "boxes" in data["boxes"]:
            boxes = [Box(**b) for b in data["boxes"]["boxes"]]
    elif isinstance(data, list):
        boxes = [Box(**b) for b in data]
    return boxes, fill_override

def _split_csv_set(s: Optional[str]) -> Set[str]:
    if not s:
        return set()
    return {x.strip() for x in s.split(",") if x.strip()}

def _filter_boxes(
    boxes: List[Box],
    include_patterns: Set[str],
    exclude_patterns: Set[str],
):
    stats = {"total": len(boxes)}
    def _keep(b: Box) -> bool:
        p = (b.pattern_name or "").strip()
        if include_patterns and p not in include_patterns:
            return False
        if p in exclude_patterns:
            return False
        return True
    out = [b for b in boxes if _keep(b)]
    return out, stats

def _dedup_boxes(boxes: List[Box], tol: float = 0.25) -> List[Box]:
    out: List[Box] = []
    def same(a: Box, b: Box) -> bool:
        return (
            a.page == b.page and
            abs(a.x0 - b.x0) <= tol and
            abs(a.y0 - b.y0) <= tol and
            abs(a.x1 - b.x1) <= tol and
            abs(a.y1 - b.y1) <= tol
        )
    for b in boxes:
        if not any(same(b, x) for x in out):
            out.append(b)
    return out

# ---------------------------
# 우선순위 기반 중복 제거 (카드 > 전화 등)
# ---------------------------
_PRIORITY = {
    "card": 100,
    "email": 90,
    "rrn": 80,
    "fgn": 80,
    "phone_mobile": 60,
    "phone_city": 60,
    "phone_service": 60,
    "driver_license": 40,
    "passport": 30,
}

def _overlap_rect(a: Box, b: Box) -> bool:
    return not (a.x1 <= b.x0 or b.x1 <= a.x0 or a.y1 <= b.y0 or b.y1 <= a.y0)

def _suppress_overlapping_boxes(boxes: List[Box]) -> List[Box]:
    """
    같은 페이지에서 박스가 겹치면 우선순위가 높은 rule만 남김.
    """
    boxes = sorted(
        boxes,
        key=lambda b: (_PRIORITY.get((b.pattern_name or ""), 0), -(b.x1 - b.x0) * (b.y1 - b.y0)),
        reverse=True,
    )
    kept: List[Box] = []
    for b in boxes:
        if any(b.page == k.page and _overlap_rect(b, k) for k in kept):
            continue
        kept.append(b)
    return kept

# ---------------------------
# PDF 텍스트/오프셋 인덱스
# ---------------------------
def _pdf_text_and_word_index(pdf_bytes: bytes):
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    pages = []
    full_parts = []
    page_offsets = []
    total_len = 0

    for pno in range(doc.page_count):
        page = doc.load_page(pno)
        words = page.get_text("words") or []
        words.sort(key=lambda w: (w[5], w[6], w[7]))

        parts, bounds, cur = [], [], 0
        for w in words:
            t = w[4] or ""
            if not t:
                continue
            if parts:
                parts.append(" "); cur += 1
            parts.append(t)
            s = cur; cur += len(t); e = cur
            bounds.append((s, e))

        page_text = "".join(parts) + "\n"
        pages.append({"words": words, "word_bounds": bounds, "page_text": page_text})
        page_offsets.append(total_len)
        full_parts.append(page_text); total_len += len(page_text)

    full_text = "".join(full_parts)
    doc.close()
    return full_text, {"pages": pages, "page_offsets": page_offsets}

def _boxes_to_matches_with_offsets(boxes: List[Box], index) -> List[dict]:
    pages = index["pages"]; page_offsets = index["page_offsets"]

    def _overlap(ax0, ay0, ax1, ay1, bx0, by0, bx1, by1):
        return not (ax1 <= bx0 or bx1 <= ax0 or ay1 <= by0 or by1 <= ay0)

    out = []
    for b in boxes:
        pno = int(getattr(b, "page", 0))
        if not (0 <= pno < len(pages)):
            continue
        page = pages[pno]; words = page["words"]; bounds = page["word_bounds"]

        bx0, by0, bx1, by1 = float(b.x0), float(b.y0), float(b.x1), float(b.y1)
        if bx0 > bx1: bx0, bx1 = bx1, bx0
        if by0 > by1: by0, by1 = by1, by0

        covered = []
        for i, w in enumerate(words):
            x0, y0, x1, y1 = float(w[0]), float(w[1]), float(w[2]), float(w[3])
            if _overlap(x0, y0, x1, y1, bx0, by0, bx1, by1): covered.append(i)

        loc = None
        if covered:
            s_idx = min(covered); e_idx = max(covered)
            s_local = bounds[s_idx][0]; e_local = bounds[e_idx][1]
            start = page_offsets[pno] + s_local; end = page_offsets[pno] + e_local
            loc = {"start": int(start), "end": int(end)}

        out.append({
            "rule": (b.pattern_name or ""),
            "value": getattr(b, "matched_text", "") or "",
            "valid": bool(getattr(b, "valid", True)),
            "location": loc,
            "page": pno,
        })
    return out

# ---------------------------
# 패턴 조회
# ---------------------------
@router.get("/patterns")
def list_patterns():
    return {"patterns": PRESET_PATTERNS}

# ---------------------------
# PDF: DETECT (compat)
# ---------------------------
@router.post("/redactions/detect", response_model=DetectResponse)
async def detect(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(None),
):
    _ensure_pdf(file)
    t0 = time.perf_counter()
    pdf = await file.read()
    patterns = _parse_patterns_json(patterns_json)

    boxes = detect_boxes_from_patterns(pdf, patterns)
    # 겹침 제거
    boxes = _suppress_overlapping_boxes(boxes)

    elapsed = (time.perf_counter() - t0) * 1000
    log.debug("DETECT done: total=%d elapsed=%.2fms", len(boxes), elapsed)
    return DetectResponse(total_matches=len(boxes), boxes=boxes)

# ---------------------------
# PDF: APPLY
# ---------------------------
@router.post("/redactions/apply", response_class=Response)
async def apply(
    file: UploadFile = File(..., description="PDF 파일"),
    req: Optional[str] = Form(None),
    boxes_json: Optional[str] = Form(None),
    fill: Optional[str] = Form("black"),
    patterns_json: Optional[str] = Form(None),
    mode: Literal["strict", "auto_all", "auto_merge"] = Form("strict"),
    exclude_patterns: Optional[str] = Form(None),
    include_patterns: Optional[str] = Form(None),
    ensure_patterns: Optional[str] = Form("card"),
):
    _ensure_pdf(file)
    pdf = _read_pdf(file)

    boxes_req, fill_override = _boxes_from_req(req)
    if fill_override: fill = fill_override or fill
    if boxes_json is not None: boxes_req = _parse_boxes_json(boxes_json)

    patterns = _parse_patterns_json(patterns_json)
    excl = _split_csv_set(exclude_patterns)
    incl = _split_csv_set(include_patterns)
    ensure = _split_csv_set(ensure_patterns) or set()

    if mode == "auto_all":
        base_boxes = detect_boxes_from_patterns(pdf, patterns)
    elif mode == "auto_merge":
        detected = detect_boxes_from_patterns(pdf, patterns)
        base_boxes = (boxes_req or []) + detected
    else:
        base_boxes = boxes_req or []
        if ensure:
            ensured = [b for b in detect_boxes_from_patterns(pdf, patterns) if (b.pattern_name or "") in ensure]
            if ensured: base_boxes = _dedup_boxes(base_boxes + ensured)
        if not base_boxes:
            raise HTTPException(status_code=400, detail="boxes가 비어있습니다. (mode=strict)")

    final_boxes, _ = _filter_boxes(base_boxes, include_patterns=incl, exclude_patterns=excl)

    # 겹침 제거 (카드 > 전화 등)
    final_boxes = _suppress_overlapping_boxes(final_boxes)

    out = apply_redaction(pdf, final_boxes, fill=fill or "black")

    # 캐시/파일명
    stamp = time.time_ns()
    return Response(
        content=out,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="redacted_{stamp}.pdf"',
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )

# ---------------------------
# PDF: SCAN (XML과 동일 스키마)
# ---------------------------
@router.post("/redactions/pdf/scan")
async def pdf_scan_endpoint(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(None),
):
    _ensure_pdf(file)
    pdf = await file.read()
    patterns = _parse_patterns_json(patterns_json)

    boxes = detect_boxes_from_patterns(pdf, patterns)
    # 겹침 제거
    boxes = _suppress_overlapping_boxes(boxes)

    full_text, index = _pdf_text_and_word_index(pdf)
    matches = _boxes_to_matches_with_offsets(boxes, index)

    def _compile(p: PatternItem):
        flags = 0 if getattr(p, "case_sensitive", False) else re.IGNORECASE
        pat = p.regex
        if getattr(p, "whole_word", False):
            pat = rf"\b(?:{pat})\b"
        return re.compile(pat, flags)

    taken = []
    for mm in matches:
        loc = mm.get("location")
        if loc:
            taken.append((int(loc["start"]), int(loc["end"])))

    def _overlaps(a, b, c, d):
        return not (b <= c or d <= a)

    for p in patterns:
        rx = _compile(p)
        validator = getattr(p, "validator", None)
        for m in rx.finditer(full_text):
            s, e = m.span()
            if any(_overlaps(s, e, ts, te) for ts, te in taken):
                continue
            val = m.group()
            ok = True
            if callable(validator):
                try: ok = bool(validator(val))
                except Exception: ok = False

            matches.append({
                "rule": p.name,
                "value": val,
                "valid": bool(ok),
                "location": {"start": int(s), "end": int(e)},
                "page": None,
            })
            taken.append((s, e))

    return {
        "file_type": "pdf",
        "extracted_text": full_text,
        "matches": matches,
    }

# ---------------------------
# XML: SCAN
# ---------------------------
@router.post("/redactions/xml/scan", response_model=XmlScanResponse)
async def xml_scan_endpoint(
    file: UploadFile = File(..., description="DOCX/XLSX/PPTX/HWPX 파일"),
):
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="파일을 업로드하세요.")
    lower = file.filename.lower()
    if not lower.endswith((".docx", ".xlsx", ".pptx", ".hwpx")):
        raise HTTPException(status_code=400, detail="지원 확장자: .docx, .xlsx, .pptx, .hwpx")

    data = await file.read()
    try:
        resp = xml_scan(data, file.filename)
    except Exception as e:
        log.exception("XML scan error: %s", e)
        raise HTTPException(status_code=500, detail=f"XML scan error: {e}")
    return resp

# ---------------------------
# XML: APPLY (HWPX MIME/헤더 강화)
# ---------------------------
@router.post("/redactions/xml/apply", response_class=Response)
async def xml_apply_endpoint(
    file: UploadFile = File(..., description="DOCX/XLSX/PPTX/HWPX 파일"),
):
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="파일을 업로드하세요.")
    lower = file.filename.lower()
    if not lower.endswith((".docx", ".xlsx", ".pptx", ".hwpx")):
        raise HTTPException(status_code=400, detail="지원 확장자: .docx, .xlsx, .pptx, .hwpx")

    import tempfile
    from urllib.parse import quote
    from pathlib import Path

    with tempfile.TemporaryDirectory() as td:
        src_path = str(Path(td) / file.filename)
        with open(src_path, "wb") as f:
            f.write(await file.read())

        stem = Path(file.filename).stem
        if lower.endswith(".docx"):
            out_path = str(Path(td) / f"{stem}.redacted.docx")
            mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            ext = "docx"
        elif lower.endswith(".xlsx"):
            out_path = str(Path(td) / f"{stem}.redacted.xlsx")
            mime = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            ext = "xlsx"
        elif lower.endswith(".pptx"):
            out_path = str(Path(td) / f"{stem}.redacted.pptx")
            mime = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            ext = "pptx"
        else:
            out_path = str(Path(td) / f"{stem}.redacted.hwpx")
            # ▼ 중요: 일부 뷰어는 hwpx 전용 MIME을 요구
            mime = "application/vnd.hancom.hwpx+zip"
            ext = "hwpx"

        try:
            xml_redact_to_file(src_path, out_path, file.filename)
        except Exception as e:
            log.exception("XML apply error: %s", e)
            raise HTTPException(status_code=500, detail=f"XML apply error: {e}")

        out_bytes = Path(out_path).read_bytes()

    stamp = time.time_ns()
    utf8_name = f"{stem}.redacted.{ext}"
    ascii_fallback = f"redacted_{stamp}.{ext}"
    filename_star = quote(utf8_name)

    return Response(
        content=out_bytes,
        media_type=mime,
        headers={
            # UTF-8 파일명 + 캐시 무력화 + 강한 no-cache
            "Content-Disposition": (
                f'attachment; filename="{ascii_fallback}"; '
                f"filename*=UTF-8''{filename_star}"
            ),
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )
