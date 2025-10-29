# -*- coding: utf-8 -*-
from __future__ import annotations
import io, zipfile, logging, os, time, tempfile, shutil, subprocess
from typing import List, Tuple, Optional
import fitz  # PyMuPDF

from .schemas import XmlScanResponse
from .xml import docx, xlsx, pptx, hwpx
from .xml.common import compile_rules

log = logging.getLogger("xml_redaction")

# -------------------------------------------------
# 유틸: 타입, 스캔
# -------------------------------------------------
def detect_xml_type(filename: str) -> str:
    l = (filename or "").lower()
    if l.endswith(".docx"): return "docx"
    if l.endswith(".xlsx"): return "xlsx"
    if l.endswith(".pptx"): return "pptx"
    if l.endswith(".hwpx"): return "hwpx"
    return "docx"

def xml_scan(file_bytes: bytes, filename: str) -> XmlScanResponse:
    with io.BytesIO(file_bytes) as bio, zipfile.ZipFile(bio, "r") as zipf:
        kind = detect_xml_type(filename)
        if kind == "xlsx":
            matches, k, text = xlsx.scan(zipf)
        elif kind == "pptx":
            matches, k, text = pptx.scan(zipf)
        elif kind == "hwpx":
            matches, k, text = hwpx.scan(zipf)
        else:
            matches, k, text = docx.scan(zipf)

        if text and len(text) > 20000:
            text = text[:20000] + "\n… (truncated)"
        return XmlScanResponse(file_type=k, total_matches=len(matches), matches=matches, extracted_text=text or "")

# -------------------------------------------------
# HWPX: 시크릿 수집 (사전 스캔)
# -------------------------------------------------
def _collect_hwpx_secrets(zin: zipfile.ZipFile) -> List[str]:
    text = hwpx.hwpx_text(zin)
    comp = compile_rules()
    secrets: List[str] = []
    seen = set()
    for _rule_name, rx, _need_valid, _prio in comp:
        for m in rx.finditer(text or ""):
            v = m.group(0)
            if not v or v in seen: continue
            seen.add(v)
            secrets.append(v)
    return secrets

# -------------------------------------------------
# 프리뷰 재생성 유틸
# -------------------------------------------------
def _find_soffice() -> Optional[str]:
    candidates = [
        shutil.which("soffice"),
        r"C:\Program Files\LibreOffice\program\soffice.exe",
        r"C:\Program Files (x86)\LibreOffice\program\soffice.exe",
        r"/usr/bin/soffice",
        r"/usr/local/bin/soffice",
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None

def _office_to_pdf_with_soffice(in_path: str, out_dir: str) -> str:
    soffice = _find_soffice()
    if not soffice:
        raise RuntimeError("LibreOffice(soffice) 실행 파일을 찾지 못했습니다.")
    cmd = [
        soffice, "--headless", "--nologo", "--nofirststartwizard",
        "--convert-to", "pdf", "--outdir", out_dir, in_path,
    ]
    t0 = time.perf_counter()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    dt = (time.perf_counter() - t0) * 1000
    log.info("HWPX preview regen: soffice convert done (%.1fms)", dt)
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

def _render_pdf_to_png_bytes(pdf_path: str, dpi: int = 144) -> List[bytes]:
    images: List[bytes] = []
    doc = fitz.open(pdf_path)
    try:
        for i in range(doc.page_count):
            page = doc.load_page(i)
            mat = fitz.Matrix(dpi / 72.0, dpi / 72.0)
            pix = page.get_pixmap(matrix=mat, alpha=False)
            images.append(pix.tobytes("png"))
    finally:
        doc.close()
    log.info("HWPX preview regen: rendered %d page(s) at %ddpi", len(images), dpi)
    return images

def _list_preview_names(zipf: zipfile.ZipFile) -> List[str]:
    names = []
    for n in zipf.namelist():
        nl = n.lower()
        if nl.startswith("preview/") and nl.endswith((".png", ".jpg", ".jpeg")):
            names.append(n)
    names.sort()
    return names

def _rewrite_zip_replacing_previews(
    redacted_tmp_hwpx: str,
    dst_path: str,
    new_images: List[bytes],
    original_preview_names: List[str],
) -> None:
    """
    redacted_tmp_hwpx(1차 레닥션 결과) → 최종 dst_path 재작성.
    Preview/* 이미지는 new_images로 치환. 파일명은 원래 preview 이름을 최대한 유지.
    """
    with zipfile.ZipFile(redacted_tmp_hwpx, "r") as zin, \
         zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED) as zout:

        # mimetype은 STORED로 복사 (필요 시)
        if "mimetype" in zin.namelist():
            zi = zipfile.ZipInfo("mimetype")
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, zin.read("mimetype"))

        # 교체 대상 이름 목록(없으면 새 이름 생성)
        preview_names = _list_preview_names(zin)
        if not preview_names:
            if original_preview_names:
                preview_names = original_preview_names[:]
            else:
                preview_names = [f"Preview/page_{i+1:03d}.png" for i in range(len(new_images))]

        replace_map = {preview_names[i]: new_images[i] for i in range(min(len(preview_names), len(new_images)))}

        used = set()
        for item in zin.infolist():
            name = item.filename
            low = name.lower()
            if name == "mimetype":
                continue
            if low.startswith("preview/") and low.endswith((".png", ".jpg", ".jpeg")) and name in replace_map:
                zout.writestr(name, replace_map[name])
                used.add(name)
            else:
                zout.writestr(item, zin.read(name))

        for n in preview_names:
            if n not in used and n in replace_map:
                zout.writestr(n, replace_map[n])

    log.info("HWPX preview regen: wrote %d preview image(s) into %s",
             min(len(preview_names), len(new_images)), os.path.basename(dst_path))

# -------------------------------------------------
# 메인: XML → 파일로 레닥션 (+옵션 프리뷰 재생성)
# -------------------------------------------------
def xml_redact_to_file(src_path: str, dst_path: str, filename: str) -> None:
    comp = compile_rules()
    kind = detect_xml_type(filename)
    log.info("XML redact: file=%s kind=%s", filename, kind)

    # --- HWPX: 사전 스캔으로 secrets 수집 → hwpx에 주입 ---
    original_preview_names: List[str] = []
    if kind == "hwpx":
        with zipfile.ZipFile(src_path, "r") as zin:
            try:
                secrets = _collect_hwpx_secrets(zin)
            except Exception:
                secrets = []
            original_preview_names = _list_preview_names(zin)
        hwpx.set_hwpx_secrets(secrets)
        log.info("HWPX secrets collected: %d", len(secrets))

    # ---------- 1차: 임시 레닥션 결과 만들기 ----------
    with tempfile.TemporaryDirectory() as td:
        tmp_redacted = os.path.join(td, os.path.splitext(os.path.basename(dst_path))[0] + ".tmp.hwpx")

        # Pass 1: 레닥션 ZIP 작성
        with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(tmp_redacted, "w", zipfile.ZIP_DEFLATED) as zout:
            if kind == "hwpx" and "mimetype" in zin.namelist():
                zi = zipfile.ZipInfo("mimetype"); zi.compress_type = zipfile.ZIP_STORED
                zout.writestr(zi, zin.read("mimetype"))

            kept = dropped = modified = 0

            for item in zin.infolist():
                name = item.filename
                data = zin.read(name)

                def _write_decision(red: Optional[bytes]):
                    nonlocal kept, dropped, modified
                    # 규칙:
                    #   red is None  -> 원본 그대로 기록(keep)
                    #   red == b""   -> 이 파트는 ZIP에 기록하지 않음(drop)
                    #   else bytes   -> 수정된 바이트로 기록(modify)
                    if red is None:
                        zout.writestr(item, data); kept += 1
                        log.debug("[%s] keep   %s", kind.upper(), name)
                    elif isinstance(red, (bytes, bytearray)) and len(red) == 0:
                        dropped += 1
                        log.debug("[%s] drop   %s", kind.upper(), name)
                        # 기록 생략
                    else:
                        zout.writestr(item, red); modified += 1
                        log.debug("[%s] modify %s", kind.upper(), name)

                if kind == "docx":
                    red = docx.redact_item(name, data, comp)
                    _write_decision(red)

                elif kind == "xlsx":
                    red = xlsx.redact_item(name, data, comp)
                    _write_decision(red)

                elif kind == "pptx":
                    red = pptx.redact_item(name, data, comp)
                    _write_decision(red)

                elif kind == "hwpx":
                    red = hwpx.redact_item(name, data, comp)
                    _write_decision(red)

                else:
                    # 알 수 없는 형식 → 그대로
                    zout.writestr(item, data); kept += 1
                    log.debug("[OTHER] keep %s", name)

            log.info("%s ZIP result: kept=%d modified=%d dropped=%d",
                     kind.upper(), kept, modified, dropped)

        # ---------- 옵션: 프리뷰 재생성 ----------
        regen = (os.getenv("HWPX_REGEN_PREVIEW", "0") in ("1", "true", "TRUE"))
        if kind == "hwpx" and regen:
            log.info("HWPX preview regen: start (env HWPX_REGEN_PREVIEW=1)")
            try:
                pdf_path = _office_to_pdf_with_soffice(tmp_redacted, td)
                dpi = int(os.getenv("HWPX_PREVIEW_DPI", "144") or "144")
                images = _render_pdf_to_png_bytes(pdf_path, dpi=dpi)
                if not images:
                    log.warning("HWPX preview regen: 렌더 결과가 비어있습니다. 원본 프리뷰 유지.")
                    shutil.copyfile(tmp_redacted, dst_path)
                else:
                    _rewrite_zip_replacing_previews(
                        redacted_tmp_hwpx=tmp_redacted,
                        dst_path=dst_path,
                        new_images=images,
                        original_preview_names=original_preview_names,
                    )
            except Exception as e:
                log.warning("HWPX preview regen: 실패 → 원본 프리뷰 유지 (%s)", e)
                shutil.copyfile(tmp_redacted, dst_path)
        else:
            shutil.copyfile(tmp_redacted, dst_path)

    if kind == "hwpx":
        hwpx.set_hwpx_secrets([])  # 다음 파일 영향 방지
    log.info("HWPX redact done" if kind=="hwpx" else "XML redact done")
