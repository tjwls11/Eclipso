# -*- coding: utf-8 -*-
from __future__ import annotations
import io, zipfile, logging, os, sys
from typing import List
from .schemas import XmlScanResponse
from .xml import docx, xlsx, pptx, hwpx
from .xml.common import compile_rules

# -------- logger --------
log = logging.getLogger("xml_redaction")
if not log.handlers:
    parent = logging.getLogger("uvicorn.error")
    if parent.handlers:
        for h in parent.handlers:
            log.addHandler(h)
    else:
        h = logging.StreamHandler(sys.stdout)
        f = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        h.setFormatter(f)
        log.addHandler(h)
log.setLevel(getattr(logging, os.getenv("XML_LOG", "INFO").upper(), logging.INFO))

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
        if kind == "xlsx":   matches, k, text = xlsx.scan(zipf)
        elif kind == "pptx": matches, k, text = pptx.scan(zipf)
        elif kind == "hwpx": matches, k, text = hwpx.scan(zipf)
        else:                matches, k, text = docx.scan(zipf)

        if text and len(text) > 20000:
            text = text[:20000] + "\n… (truncated)"
        return XmlScanResponse(file_type=k, total_matches=len(matches), matches=matches, extracted_text=text or "")

def _collect_hwpx_secrets(zin: zipfile.ZipFile) -> List[str]:
    text = hwpx.hwpx_text(zin)
    comp = compile_rules()
    secrets: List[str] = []
    seen = set()
    for _rule_name, rx, _need_valid, _prio in comp:
        for m in rx.finditer(text or ""):
            v = m.group(0)
            if v and v not in seen:
                seen.add(v); secrets.append(v)
    return secrets

def xml_redact_to_file(src_path: str, dst_path: str, filename: str) -> None:
    comp = compile_rules()
    kind = detect_xml_type(filename)
    log.info("XML redact: file=%s kind=%s", filename, kind)

    # --- HWPX: 사전 스캔으로 secrets 수집 → hwpx에 주입 ---
    prewrote_mimetype = False
    if kind == "hwpx":
        with zipfile.ZipFile(src_path, "r") as zin:
            try:
                secrets = _collect_hwpx_secrets(zin)
                hwpx.set_hwpx_secrets(secrets)
                log.info("HWPX secrets collected: %d", len(secrets))
            except Exception as e:
                log.warning("HWPX secret scan failed: %s", e)
                hwpx.set_hwpx_secrets([])

    with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED) as zout:
        # HWPX mimetype을 무압축으로 먼저 기록(중복 방지 위해 루프에서 스킵)
        if kind == "hwpx" and "mimetype" in zin.namelist():
            zi = zipfile.ZipInfo("mimetype"); zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, zin.read("mimetype"))
            prewrote_mimetype = True

        for item in zin.infolist():
            name = item.filename
            if kind == "hwpx" and prewrote_mimetype and name == "mimetype":
                continue  # Duplicate name 경고 방지

            data = zin.read(name)
            if kind == "docx":
                red = docx.redact_item(name, data, comp)
            elif kind == "xlsx":
                red = xlsx.redact_item(name, data, comp)
            elif kind == "pptx":
                red = pptx.redact_item(name, data, comp)
            elif kind == "hwpx":
                red = hwpx.redact_item(name, data, comp)
                if name.lower().startswith("bindata/"):
                    from .xml.ole_redactor import _hexdump
                    log.debug("BinData seen: %s head=%s (%d bytes)", name, _hexdump(data, 16), len(data))
            else:
                red = None

            zout.writestr(item, data if red is None else red)

    if kind == "hwpx":
        hwpx.set_hwpx_secrets([])
        log.info("HWPX redact done")
