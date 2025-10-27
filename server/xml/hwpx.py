# -*- coding: utf-8 -*-
from __future__ import annotations
import io, re, zipfile, os
from typing import Optional, List, Tuple
from .common import (
    cleanup_text, compile_rules, sub_text_nodes, chart_sanitize,
    redact_embedded_xlsx_bytes,
    HWPX_STRIP_PREVIEW, HWPX_DISABLE_CACHE, HWPX_BLANK_PREVIEW,
)
from ..schemas import XmlMatch, XmlLocation

# 레닥션 전 사전 스캔 결과를 주입 받는 곳
_CURRENT_SECRETS: List[str] = []

def set_hwpx_secrets(values: List[str] | None):
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))

def hwpx_text(zipf: zipfile.ZipFile) -> str:
    out = []
    for name in sorted(n for n in zipf.namelist() if n.startswith("Contents/") and n.endswith(".xml")):
        xml = zipf.read(name).decode("utf-8","ignore")
        out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
    for name in sorted(n for n in zipf.namelist() if (n.startswith("Chart/") or n.startswith("Charts/")) and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8","ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I|re.DOTALL):
            v = (m.group(1) or m.group(2) or "").strip()
            if v: out.append(v)
    for name in (n for n in zipf.namelist() if n.startswith("BinData/")):
        b = zipf.read(name)
        if len(b)>=4 and b[:2]==b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(b),"r") as ez:
                    from .common import xlsx_text_from_zip
                    out.append(xlsx_text_from_zip(ez))
            except Exception:
                pass
    return cleanup_text("\n".join(x for x in out if x))

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = hwpx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            out.append(XmlMatch(
                rule=rule_name, value=m.group(0), valid=True,
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="hwpx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "hwpx", text

def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    low = filename.lower()

    # Preview 폴더: 삭제/블랭크 옵션
    if low.startswith("preview/"):
        if HWPX_STRIP_PREVIEW:
            return b""
        if HWPX_BLANK_PREVIEW and low.endswith((".png",".jpg",".jpeg")):
            # 1x1 투명 PNG
            return (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc\x00\x01"
                    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")

    # settings.xml: 캐시 끄기/미리보기 끄기(옵션)
    if HWPX_DISABLE_CACHE and low.endswith("settings.xml"):
        try:
            txt = data.decode("utf-8","ignore")
            txt = re.sub(r'(?i)usepreview\s*=\s*"(?:true|1)"', 'usePreview="false"', txt)
            txt = re.sub(r"(?i)usepreview\s*=\s*'(?:true|1)'", "usePreview='false'", txt)
            txt = re.sub(r"(?is)<\s*usepreview\s*>.*?</\s*usepreview\s*>", "<usePreview>false</usePreview>", txt)
            txt = re.sub(r"(?is)<\s*preview\s*>.*?</\s*preview\s*>", "<preview>0</preview>", txt)
            txt = re.sub(r'(?i)usecache\s*=\s*"(?:true|1)"', 'useCache="false"', txt)
            txt = re.sub(r"(?is)<\s*cache\s*>.*?</\s*cache\s*>", "<cache>0</cache>", txt)
            return txt.encode("utf-8","ignore")
        except Exception:
            return data

    # 본문 XML
    if low.startswith("contents/") and low.endswith(".xml"):
        return sub_text_nodes(data, comp)[0]

    # 차트 XML
    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    # BinData: 내장 XLSX / OLE
    if low.startswith("bindata/"):
        if len(data)>=4 and data[:2]==b"PK":  # embedded xlsx
            try:
                return redact_embedded_xlsx_bytes(data)
            except Exception:
                return data
        else:
            # OLE(CFBF)
            try:
                from .ole_redactor import redact_ole_bin_preserve_size
                return redact_ole_bin_preserve_size(data, _CURRENT_SECRETS)
            except Exception:
                return data

    return None
