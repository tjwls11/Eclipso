# -*- coding: utf-8 -*-
from __future__ import annotations
import io, re, zipfile, os
from typing import Optional, List, Tuple

from .common import (
    cleanup_text, compile_rules, sub_text_nodes, chart_sanitize,
    redact_embedded_xlsx_bytes,
    HWPX_STRIP_PREVIEW, HWPX_DISABLE_CACHE, HWPX_BLANK_PREVIEW,
)
from server.core.schemas import XmlMatch, XmlLocation
from server.core.redaction_rules import RULES  # ✅ validator 사용

_CURRENT_SECRETS: List[str] = []

def set_hwpx_secrets(values: List[str] | None):
    global _CURRENT_SECRETS
    _CURRENT_SECRETS = list(dict.fromkeys(v for v in (values or []) if v))

# --------------------------------------------------------------------
# 규칙 포맷 유연 파서: dict/tuple/list 어떤 형태로 와도 표준화해서 사용
#   - dict: {name, regex, case_sensitive, whole_word, ensure_valid}
#   - tuple/list len 3~4: (name, regex|compiled, ensure_valid[, prio])
#   - tuple/list len >=5: 앞의 4개만 사용 (여분 무시)
# 반환: (rule_name:str, compiled_rx:re.Pattern, need_valid:bool, prio:int)
# --------------------------------------------------------------------
def _iter_rules_flexible(comp):
    if not comp:
        return
    for item in comp:
        # dict 형태 (PRESET_PATTERNS 원형)
        if isinstance(item, dict):
            name = item.get("name", "")
            pattern = item.get("regex", "")
            cs = bool(item.get("case_sensitive", False))
            ww = bool(item.get("whole_word", False))
            need_valid = bool(item.get("ensure_valid", True))
            if not name or not pattern:
                continue
            flags = 0 if cs else re.IGNORECASE
            pat = rf"\b(?:{pattern})\b" if ww else pattern
            try:
                rx = re.compile(pat, flags)
            except re.error:
                continue
            yield name, rx, need_valid, 0
            continue

        # tuple/list 형태
        if isinstance(item, (list, tuple)):
            if len(item) < 2:
                continue
            name = item[0]
            rx = item[1]
            need_valid = bool(item[2]) if len(item) >= 3 else True
            prio = int(item[3]) if len(item) >= 4 else 0
            if isinstance(rx, str):
                try:
                    rx = re.compile(rx, re.IGNORECASE)
                except re.error:
                    continue
            if not isinstance(rx, re.Pattern):
                continue
            yield name, rx, need_valid, prio
            continue

        # 기타 타입은 스킵
        continue

def _is_valid(rule_name: str, value: str, need_valid: bool) -> bool:
    """RULES에 validator가 있으면 적용; need_valid=False면 무조건 True"""
    if not need_valid:
        return True
    try:
        rule = RULES.get(rule_name)
        if not isinstance(rule, dict):
            return True
        validator = rule.get("validator")
        if not callable(validator):
            return True
        try:
            return bool(validator(value))
        except TypeError:
            return bool(validator(value, None))
    except Exception:
        return False

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

def extract_text(file_bytes: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        return hwpx_text(zipf)

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = hwpx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    # ✅ 유연 파서 + validator를 통한 valid 판정
    for rule_name, rx, need_valid, _prio in _iter_rules_flexible(comp):
        for m in rx.finditer(text):
            val = m.group(0)
            ok = _is_valid(rule_name, val, need_valid)
            out.append(XmlMatch(
                rule=rule_name, value=val, valid=bool(ok),
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="hwpx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "hwpx", text

def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    low = filename.lower()

    if low.startswith("preview/"):
        if HWPX_STRIP_PREVIEW:
            return b""
        if HWPX_BLANK_PREVIEW and low.endswith((".png",".jpg",".jpeg")):
            return (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc\x00\x01"
                    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")

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

    if low.startswith("contents/") and low.endswith(".xml"):
        return sub_text_nodes(data, comp)[0]

    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    if low.startswith("bindata/"):
        if len(data)>=4 and data[:2]==b"PK":
            try:
                return redact_embedded_xlsx_bytes(data)
            except Exception:
                return data
        else:
            try:
                from .ole_redactor import redact_ole_bin_preserve_size
                return redact_ole_bin_preserve_size(data, _CURRENT_SECRETS)
            except Exception:
                return data

    return None
