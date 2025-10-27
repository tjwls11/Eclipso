# server/routes/redaction.py
from __future__ import annotations

import json
import logging
import time
import re
import os
import io
import shutil
import tempfile
import subprocess
import zipfile
from typing import List, Optional, Literal, Set, Tuple

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

# -------- OLE 디버그용 --------
import olefile  # pip install olefile

# ============ 로깅 기본 설정 (콘솔로 보기 좋게) ============
_root = logging.getLogger()
if not any(isinstance(h, logging.StreamHandler) for h in _root.handlers):
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    _root.addHandler(_h)
_root.setLevel(logging.INFO)
logging.getLogger("ole_redactor").setLevel(logging.INFO)
logging.getLogger("xml_redaction").setLevel(logging.INFO)

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

    log.info("PDF DETECT start: file=%s size=%d", file.filename, len(pdf))
    boxes = detect_boxes_from_patterns(pdf, patterns)
    # 겹침 제거
    boxes = _suppress_overlapping_boxes(boxes)

    elapsed = (time.perf_counter() - t0) * 1000
    log.info("PDF DETECT done: matches=%d elapsed=%.2fms", len(boxes), elapsed)
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
    try:
        _ensure_pdf(file)
        pdf = _read_pdf(file)
        t0 = time.perf_counter()
        log.info("PDF APPLY start: file=%s size=%d mode=%s", file.filename, len(pdf), mode)

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
        final_boxes = _suppress_overlapping_boxes(final_boxes)

        out = apply_redaction(pdf, final_boxes, fill=fill or "black")
        elapsed = (time.perf_counter() - t0) * 1000
        log.info("PDF APPLY done: boxes=%d elapsed=%.2fms", len(final_boxes), elapsed)

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
    except HTTPException:
        raise
    except Exception as e:
        log.exception("PDF apply error: %s", e)
        raise HTTPException(status_code=500, detail=f"PDF apply error: {e}")

# ---------------------------
# PDF: SCAN (XML과 동일 스키마)
# ---------------------------
@router.post("/redactions/pdf/scan")
async def pdf_scan_endpoint(
    file: UploadFile = File(..., description="PDF 파일"),
    patterns_json: Optional[str] = Form(None),
):
    try:
        _ensure_pdf(file)
        pdf = await file.read()
        patterns = _parse_patterns_json(patterns_json)

        log.info("PDF SCAN start: file=%s size=%d", file.filename, len(pdf))
        boxes = detect_boxes_from_patterns(pdf, patterns)
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

        log.info("PDF SCAN done: matches=%d", len(matches))
        return {
            "file_type": "pdf",
            "extracted_text": full_text,
            "matches": matches,
        }
    except HTTPException:
        raise
    except Exception as e:
        log.exception("PDF scan error: %s", e)
        raise HTTPException(status_code=500, detail=f"PDF scan error: {e}")

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
        log.info("XML SCAN start: file=%s size=%d", file.filename, len(data))
        resp = xml_scan(data, file.filename)
        log.info("XML SCAN done: type=%s matches=%d", resp.file_type, resp.total_matches)
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
        body = await file.read()
        open(src_path, "wb").write(body)
        log.info("XML APPLY start: file=%s size=%d tmp=%s", file.filename, len(body), src_path)

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
            mime = "application/vnd.hancom.hwpx+zip"
            ext = "hwpx"

        try:
            t0 = time.perf_counter()
            xml_redact_to_file(src_path, out_path, file.filename)
            ms = (time.perf_counter() - t0) * 1000
            log.info("XML APPLY done: out=%s (%.1fms)", out_path, ms)
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
            "Content-Disposition": (
                f'attachment; filename="{ascii_fallback}"; '
                f"filename*=UTF-8''{filename_star}"
            ),
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )

# =================================================================
# 새 엔드포인트: 레닥션 결과를 이미지(PNG)로 렌더 (ZIP 반환)
# =================================================================

def _render_pdf_to_png_bytes(pdf_bytes: bytes, dpi: int = 144) -> List[Tuple[str, bytes]]:
    """
    PDF 바이트를 페이지별 PNG 바이트로 변환.
    반환: [(filename, png_bytes), ...]
    """
    imgs: List[Tuple[str, bytes]] = []
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        for i in range(doc.page_count):
            page = doc.load_page(i)
            mat = fitz.Matrix(dpi / 72.0, dpi / 72.0)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            png_bytes = pix.tobytes("png")
            imgs.append((f"page_{i+1:03d}.png", png_bytes))
    finally:
        doc.close()
    return imgs

def _office_to_pdf_with_soffice(in_path: str, out_dir: str) -> str:
    """
    LibreOffice 'soffice'로 Office/HWPX 계열을 PDF로 변환.
    성공 시 out_dir 안의 PDF 경로를 반환. 실패 시 예외.
    """
    candidates = [
        shutil.which("soffice"),
        r"C:\Program Files\LibreOffice\program\soffice.exe",
        r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
        r"/usr/bin/soffice",
        r"/usr/local/bin/soffice",
    ]
    soffice = next((p for p in candidates if p and os.path.exists(p)), None)
    if not soffice:
        raise RuntimeError("LibreOffice(soffice) 실행 파일을 찾을 수 없습니다.")

    cmd = [
        soffice, "--headless", "--nologo", "--nofirststartwizard",
        "--convert-to", "pdf", "--outdir", out_dir, in_path,
    ]
    log.info("soffice convert: %s", " ".join(cmd))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"soffice 변환 실패: {proc.stderr or proc.stdout}")

    base = os.path.splitext(os.path.basename(in_path))[0]
    pdf_name = base + ".pdf"
    pdf_path = os.path.join(out_dir, pdf_name)
    if not os.path.exists(pdf_path):
        cands = [os.path.join(out_dir, f) for f in os.listdir(out_dir) if f.lower().endswith(".pdf")]
        if not cands:
            raise RuntimeError("PDF 결과를 찾지 못했습니다.")
        pdf_path = cands[0]
    return pdf_path

@router.post("/redactions/render-images", response_class=Response)
async def render_images_endpoint(
    file: UploadFile = File(..., description="PDF 또는 DOCX/XLSX/PPTX/HWPX"),
    dpi: int = Form(144, description="출력 DPI (기본 144)"),
):
    """
    1) 업로드 파일을 레닥션 적용
    2) PDF면 바로 렌더, 아니면 LibreOffice로 PDF 변환 후 렌더
    3) 모든 페이지 PNG를 ZIP으로 반환
    """
    try:
        if not file or not file.filename:
            raise HTTPException(status_code=400, detail="파일을 업로드하세요.")

        fname = (file.filename or "").lower()
        ok_exts = (".pdf", ".docx", ".xlsx", ".pptx", ".hwpx")
        if not any(fname.endswith(ext) for ext in ok_exts):
            raise HTTPException(status_code=400, detail="지원 확장자: .pdf, .docx, .xlsx, .pptx, .hwpx")

        raw = await file.read()
        log.info("RENDER start: file=%s size=%d dpi=%d", file.filename, len(raw), dpi)

        with tempfile.TemporaryDirectory() as td:
            # 1) src 저장
            src_path = os.path.join(td, file.filename)
            with open(src_path, "wb") as f:
                f.write(raw)

            base, ext = os.path.splitext(file.filename)
            # 2) 레닥션 적용
            if fname.endswith(".pdf"):
                redacted_pdf_path = src_path
            else:
                if fname.endswith(".docx"):
                    out_path = os.path.join(td, base + ".redacted.docx")
                elif fname.endswith(".xlsx"):
                    out_path = os.path.join(td, base + ".redacted.xlsx")
                elif fname.endswith(".pptx"):
                    out_path = os.path.join(td, base + ".redacted.pptx")
                else:
                    out_path = os.path.join(td, base + ".redacted.hwpx")

                try:
                    t0 = time.perf_counter()
                    xml_redact_to_file(src_path, out_path, file.filename)
                    log.info("RENDER redaction done in %.1f ms -> %s", (time.perf_counter()-t0)*1000, out_path)
                except Exception as e:
                    log.exception("XML redaction error during render: %s", e)
                    raise HTTPException(status_code=500, detail=f"XML redaction error: {e}")

                # 3) 레닥션 결과를 PDF로 변환(soffice 필요)
                try:
                    redacted_pdf_path = _office_to_pdf_with_soffice(out_path, td)
                except Exception as e:
                    log.exception("LibreOffice convert error: %s", e)
                    raise HTTPException(
                        status_code=501,
                        detail=f"PDF 변환 불가: LibreOffice(soffice) 필요. 상세: {e}"
                    )

            # 4) PDF → PNG 렌더
            pdf_bytes = open(redacted_pdf_path, "rb").read()
            images = _render_pdf_to_png_bytes(pdf_bytes, dpi=dpi)
            if not images:
                raise HTTPException(status_code=500, detail="이미지 렌더링 실패(빈 결과).")

            # 5) ZIP으로 묶어 반환
            zip_path = os.path.join(td, f"{base}.previews.zip")
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
                for name, data in images:
                    z.writestr(name, data)

            out_bytes = open(zip_path, "rb").read()

        log.info("RENDER done: pages=%d zip=%d bytes", len(images), len(out_bytes))
        return Response(
            content=out_bytes,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{base}.previews.zip"',
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    except HTTPException:
        raise
    except Exception as e:
        log.exception("render-images error: %s", e)
        raise HTTPException(status_code=500, detail=f"render-images error: {e}")

# =================================================================
# 디버그: HWPX의 BinData/*.ole 내부 스트림 검사 (옵션: 레닥션 후 검사)
# =================================================================

def _dump_preview(b: bytes, wid: int = 80) -> str:
    try:
        s = b.decode("utf-8", "ignore")
    except Exception:
        s = repr(b[:wid])
    s = s.replace("\r", " ").replace("\n", " ")
    return (s[:wid] + ("..." if len(s) > wid else ""))

def _find_all(data: bytes, needle: bytes, limit: int = 5):
    offs = []
    i = 0
    while len(offs) < limit and i < len(data):
        j = data.find(needle, i)
        if j < 0:
            break
        offs.append(j)
        i = j + max(1, len(needle))
    return offs

@router.post("/debug/hwpx-ole-inspect")
async def debug_hwpx_ole_inspect(
    file: UploadFile = File(..., description="HWPX 파일"),
    redact_first: bool = Form(False),
    probe: Optional[str] = Form(None, description="찾아볼 문자열(없으면 자동: 규칙 값)"),
    show_bytes: int = Form(96, description="각 스트림 미리보기 바이트"),
):
    """
    BinData/ole*.ole 내부 스트림을 열어 스트림 목록 & 패턴 존재 여부를 확인.
    - redact_first=True 이면 레닥션을 먼저 적용한 결과물을 검사.
    - probe 지정 시 해당 문자열(또는 UTF-16LE 변형)이 있는지 검색.
    """
    try:
        if not file or not file.filename or not file.filename.lower().endswith(".hwpx"):
            raise HTTPException(status_code=400, detail="HWPX 파일을 업로드하세요.")

        raw = await file.read()
        log.info("OLE-INSPECT start: file=%s size=%d redact_first=%s", file.filename, len(raw), redact_first)

        # 필요시 먼저 레닥션
        src_bytes = raw
        if redact_first:
            from pathlib import Path
            with tempfile.TemporaryDirectory() as td:
                src = os.path.join(td, file.filename)
                open(src, "wb").write(raw)
                out = os.path.join(td, Path(file.filename).stem + ".redacted.hwpx")
                try:
                    xml_redact_to_file(src, out, file.filename)
                except Exception as e:
                    log.exception("redact_first 실패: %s", e)
                    raise HTTPException(status_code=500, detail=f"redact_first 실패: {e}")
                src_bytes = open(out, "rb").read()

        # HWPX ZIP 열기
        with zipfile.ZipFile(io.BytesIO(src_bytes), "r") as z:
            bindata_names = sorted(n for n in z.namelist() if n.lower().startswith("bindata/") and n.lower().endswith(".ole"))
            if not bindata_names:
                return {"ok": True, "note": "BinData/*.ole 없음", "files": []}

            results = []
            # 규칙 기반 probe 자동 구성
            auto_probes: List[bytes] = []
            try:
                from ..xml.common import compile_rules
                text = ""
                for n2 in z.namelist():
                    if n2.startswith("Contents/") and n2.endswith(".xml"):
                        text += z.read(n2).decode("utf-8", "ignore") + "\n"
                comp = compile_rules()
                seen = set()
                for _rule, rx, _need_valid, _prio in comp:
                    for m in rx.finditer(text):
                        v = m.group(0)
                        if v and v not in seen:
                            seen.add(v)
                            auto_probes.append(v.encode("utf-8", "ignore"))
                            auto_probes.append(v.encode("utf-16le", "ignore"))
                        if len(auto_probes) >= 16: break
                    if len(auto_probes) >= 16: break
            except Exception as e:
                log.debug("auto probe 구성 실패: %s", e)

            # 사용자가 지정한 probe가 있으면 최우선
            probes: List[bytes] = []
            if probe:
                probes.append(probe.encode("utf-8", "ignore"))
                probes.append(probe.encode("utf-16le", "ignore"))
            probes.extend(auto_probes)

            for name in bindata_names:
                b = z.read(name)
                # CFBF 시그니처/오프셋 점검 (00 32 04 00 프리픽스 같은 케이스)
                off = 0
                sig = b[:8]
                if not (len(b) >= 8 and sig.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")):
                    idx = b.find(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1")
                    if idx > 0:
                        log.info("[debug] %s: CFBF signature at offset=%d", name, idx)
                        off = idx
                    else:
                        log.warning("[debug] %s: CFBF signature not found", name)
                        results.append({
                            "name": name,
                            "note": "not CFBF",
                            "sig_head": b[:16].hex(" "),
                        })
                        continue

                ob = b[off:]
                try:
                    with olefile.OleFileIO(io.BytesIO(ob)) as ole:
                        streams = ole.listdir(streams=True, storages=False)
                        entry = {
                            "name": name,
                            "offset": off,
                            "streams": ["/".join(p) for p in streams],
                            "checks": [],
                        }
                        # 검사 대상 선택
                        targets = []
                        for p in streams:
                            sname = "/".join(p)
                            if any(k in sname for k in ("OOXMLChartContents", "Contents", "OlePres")):
                                targets.append(sname)
                        if not targets:
                            targets = ["/".join(p) for p in streams[:5]]

                        # 각 타깃 스트림 검사
                        for t in targets:
                            hit_info = {"stream": t, "hits": []}
                            try:
                                rb = ole.openstream(t).read()
                            except Exception as e:
                                hit_info["error"] = f"openstream fail: {e}"
                                entry["checks"].append(hit_info)
                                continue

                            # 앞/뒤 미리보기
                            hit_info["size"] = len(rb)
                            hit_info["head"] = rb[:show_bytes].hex(" ")
                            hit_info["head_text"] = _dump_preview(rb[:show_bytes])
                            hit_info["tail_text"] = _dump_preview(rb[-show_bytes:]) if len(rb) >= show_bytes else ""

                            # probe 바이트 검색
                            for p in probes[:16]:
                                offs = _find_all(rb, p, limit=3)
                                if offs:
                                    disp = p.decode("utf-8", "ignore")
                                    hit_info["hits"].append({"probe": disp, "len": len(p), "offsets": offs})
                            entry["checks"].append(hit_info)

                        results.append(entry)
                except Exception as e:
                    log.exception("[debug] %s: OLE open fail: %s", name, e)
                    results.append({"name": name, "offset": off, "error": str(e)})

            log.info("OLE-INSPECT done: files=%d", len(results))
            return {"ok": True, "files": results}
    except HTTPException:
        raise
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="잘못된 HWPX(ZIP) 형식입니다.")
    except Exception as e:
        log.exception("hwpx-ole-inspect error: %s", e)
        raise HTTPException(status_code=500, detail=f"hwpx-ole-inspect error: {e}")
