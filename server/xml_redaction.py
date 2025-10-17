# server/xml_redaction.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Tuple, Dict, Optional

from .redac_rules import PRESET_PATTERNS, RULES
from .schemas import XmlMatch, XmlLocation, XmlScanResponse

# =========================================
# 옵션 (HWPX 전용)
# =========================================
HWPX_STRIP_PREVIEW = True        # Preview/* 드롭
HWPX_DISABLE_CACHE = True        # settings.xml에서 preview/cache 끄기
HWPX_BLANK_PREVIEW = False       # Preview 이미지 1x1 PNG로 대체(보통 False)
HWPX_BLANK_OLE_BINDATA = False   # OLE 전체 블랭크(권장 X, 보수 마스킹 사용)

# =========================================
# 공통 마스킹 유틸
# =========================================
def _mask_keep_separators(s: str) -> str:
    return "".join("*" if ch.isalnum() else ch for ch in s)

def _mask_email_preserve_at(value: str) -> str:
    return "".join(ch if ch == "@" else "*" for ch in value)

def _mask_for_rule(rule_name: str, value: str) -> str:
    if (rule_name or "").lower() == "email":
        return _mask_email_preserve_at(value)
    return _mask_keep_separators(value)

# =========================================
# 텍스트 정리
# =========================================
_FOOTNOTE_PATTERNS = [
    re.compile(r"\s*\(\^\d+\)"),
    re.compile(r"\s*\^\d+\)"),
    re.compile(r"\s*\^\d+\."),
    re.compile(r"\s*\^\d+\b"),
]
def _cleanup_text(text: str) -> str:
    if not text:
        return ""
    t = text
    for rx in _FOOTNOTE_PATTERNS:
        t = rx.sub("", t)
    t = re.sub(r"[\x00-\x09\x0B-\x1F]", " ", t)
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    return t.strip()

# =========================================
# 룰 컴파일 / 검증 + 우선순위
# =========================================
# 카드 > 이메일 > 주민/외국인 > 전화 > 운전면허 > 여권
_RULE_PRIORITY = {
    "card": 100,
    "email": 90,
    "rrn": 80,
    "fgn": 80,
    "phone_mobile": 60,
    "phone_city": 60,
    "phone_service": 60,  # 있을 경우
    "driver_license": 40,
    "passport": 30,
}

def _compile_rules():
    comp = []
    for r in PRESET_PATTERNS:
        name = r["name"]
        pat = r["regex"]
        flags = 0 if r.get("case_sensitive") else re.IGNORECASE
        if r.get("whole_word"):
            pat = rf"\b(?:{pat})\b"
        priority = _RULE_PRIORITY.get(name, 0)
        comp.append((name, re.compile(pat, flags), bool(r.get("ensure_valid", False)), priority))
    # 우선순위 높은 순으로 정렬
    comp.sort(key=lambda t: t[3], reverse=True)
    return comp

def _context_snippet(text: str, s: int, e: int, pad: int = 20) -> str:
    a = max(0, s - pad); b = min(len(text), e + pad)
    return text[a:b]

def _is_valid(kind: str, value: str) -> bool:
    rule = RULES.get((kind or "").lower())
    if rule:
        validator = rule.get("validator")
        if callable(validator):
            try:
                return bool(validator(value))
            except TypeError:
                return bool(validator(value, None))
    return True

# ---------- 공통: 우선순위 기반 마스킹 엔진 ----------
def _mask_text_with_priority(txt: str, comp) -> tuple[str, int]:
    """
    텍스트 내에서 우선순위가 높은 룰부터 매치 수집.
    이미 선택된 구간과 겹치면 낮은 우선순위 매치는 무시.
    마지막에 역순으로 실제 치환을 적용.
    """
    if not txt:
        return "", 0
    taken: List[tuple[int, int]] = []
    repls: List[tuple[int, int, str]] = []

    def _overlaps(a0, a1, b0, b1):
        return not (a1 <= b0 or b1 <= a0)

    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(txt):
            s, e = m.span()
            # 이미 상위 우선순위로 잡힌 구간과 겹치면 skip
            if any(_overlaps(s, e, ts, te) for ts, te in taken):
                continue
            val = m.group(0)
            if need_valid and not _is_valid(rule_name, val):
                continue
            taken.append((s, e))
            repls.append((s, e, _mask_for_rule(rule_name, val)))

    if not repls:
        return txt, 0

    # 시작 인덱스 역순으로 치환
    repls.sort(key=lambda r: r[0], reverse=True)
    out = list(txt)
    for s, e, rep in repls:
        out[s:e] = list(rep)
    return "".join(out), len(repls)

# =========================================
# XML: 텍스트 노드만 치환 (태그/속성 보존)
# =========================================
_TEXT_NODE_RE = re.compile(r">(?!\s*<)([^<]+)<", re.DOTALL)

def _sub_text_nodes_preserving(xml_bytes: bytes, comp) -> Tuple[bytes, int]:
    """
    XML 전체 문자열에 정규식 적용하지 않고, >…< 사이 텍스트에만 마스킹 적용.
    우선순위 기반으로 겹치는 매치는 낮은 룰을 무시한다.
    """
    s = xml_bytes.decode("utf-8", "ignore")
    def _apply_rules(txt: str) -> str:
        masked, _ = _mask_text_with_priority(txt, comp)
        return masked
    out = _TEXT_NODE_RE.sub(lambda m: ">" + _apply_rules(m.group(1)) + "<", s)
    # 카운트는 필요시 별도 로그로만 쓰므로 0 반환해도 무방
    return out.encode("utf-8", "ignore"), 0

# =========================================
# XML: 텍스트 값(단일 문자열)에 룰 적용
# =========================================
def _sub_value(v: str, comp) -> tuple[str, int]:
    if v is None:
        return "", 0
    return _mask_text_with_priority(v, comp)

# =========================================
# 내장 XLSX 처리(차트 포함, 안전 치환)
# =========================================
_NS = {
    "c": "http://schemas.openxmlformats.org/drawingml/2006/chart",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
}

_C_EXTERNAL_RE = re.compile(rb"(?is)<\s*c:externalData\b[^>]*>.*?</\s*c:externalData\s*>")

def _strip_chart_external_data(xml_bytes: bytes) -> tuple[bytes, int]:
    after = _C_EXTERNAL_RE.sub(b"", xml_bytes)
    return (after, 1) if after != xml_bytes else (xml_bytes, 0)

def _detect_xml_encoding(b: bytes) -> str:
    m = re.match(rb'^<\?xml[^>]*encoding=["\']([^"\']+)["\']', b.strip()[:200], re.I)
    if m:
        enc = m.group(1).decode("ascii", "ignore")
        enc_low = enc.lower().replace("-", "").replace("_", "")
        return "utf-8" if enc_low in ("utf8", "utf") else enc
    return "utf-8"

def _et_from_bytes(xml_bytes: bytes) -> tuple[ET.ElementTree, str]:
    enc = _detect_xml_encoding(xml_bytes)
    try:
        s = xml_bytes.decode(enc, "strict")
    except Exception:
        s = xml_bytes.decode(enc, "ignore")
    return ET.ElementTree(ET.fromstring(s)), enc

def _et_to_bytes(tree: ET.ElementTree, enc: str) -> bytes:
    bio = io.BytesIO()
    tree.write(bio, encoding=enc, xml_declaration=True)
    return bio.getvalue()

def _safe_text_mask(s: str) -> str:
    if s is None:
        return ""
    t = s.strip()
    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", t):
        return "0"
    return "***"

def _chart_sanitize_preserve_structure(xml_bytes: bytes, comp) -> tuple[bytes, int]:
    """
    차트 XML: 구조 보존 + 값만 무해화
    - externalData 제거
    - c:f 내용 비우기
    - c:strCache / c:numCache / a:t 값 마스킹 (우선순위 기반)
    """
    b2, ext = _strip_chart_external_data(xml_bytes)
    tree, enc = _et_from_bytes(b2)
    root = tree.getroot()
    hits = ext
    rules = comp  # 이미 우선순위 정렬됨

    # 수식 제거
    for f in root.findall(".//c:f", _NS):
        if f.text:
            f.text = ""
            hits += 1

    # strCache
    for v in root.findall(".//c:strCache//c:pt/c:v", _NS):
        if v.text is not None:
            new, cnt = _sub_value(v.text, rules)
            v.text = new if cnt else _safe_text_mask(v.text)
            hits += (1 if cnt else 0)

    # numCache
    for v in root.findall(".//c:numCache//c:pt/c:v", _NS):
        if v.text is not None:
            v.text = "0"
            hits += 1

    # 라벨 텍스트
    for tnode in root.findall(".//a:t", _NS):
        if tnode.text:
            new, cnt = _sub_value(tnode.text, rules)
            tnode.text = new if cnt else _safe_text_mask(tnode.text)
            hits += (1 if cnt else 0)

    return _et_to_bytes(tree, enc), hits

def _xlsx_text_from_zip(zipf: zipfile.ZipFile) -> str:
    out = []
    for name in zipf.namelist():
        if name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/"):
            try:
                xml = zipf.read(name).decode("utf-8", "ignore")
                out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
            except KeyError:
                pass
    for name in (n for n in zipf.namelist() if n.startswith("xl/charts/") and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I | re.DOTALL):
            v = (m.group(1) or m.group(2) or "").strip()
            if v:
                out.append(v)
    return _cleanup_text("\n".join(out))

def _redact_embedded_xlsx_bytes(xlsx_bytes: bytes) -> bytes:
    comp = _compile_rules()
    bio_in = io.BytesIO(xlsx_bytes)
    bio_out = io.BytesIO()
    with zipfile.ZipFile(bio_in, "r") as zin, zipfile.ZipFile(bio_out, "w", zipfile.ZIP_DEFLATED) as zout:
        for it in zin.infolist():
            name = it.filename
            data = zin.read(name)
            low = name.lower()

            if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
                data, _ = _sub_text_nodes_preserving(data, comp)

            elif low.startswith("xl/charts/") and low.endswith(".xml"):
                data, _ = _chart_sanitize_preserve_structure(data, comp)

            zout.writestr(it, data)
    return bio_out.getvalue()

# =========================================
# OLE(CFBF) 보수 마스킹 (길이 보존)
# =========================================
_PHONE_ASCII_RX = re.compile(rb'(?<!\d)\d{2,4}\s*-\s*\d{3,4}\s*-\s*\d{4}(?!\d)')
_EMAIL_ASCII_RX = re.compile(rb'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}')
_CARD_ASCII_RX  = re.compile(rb'(?<!\d)\d{4}(?:\s*-\s*|\s)\d{4}(?:\s*-\s*|\s)\d{4}(?:\s*-\s*|\s)\d{4}(?!\d)')
_PHONE_U16_RX   = re.compile(
    rb'(?:(?<!\x00\d)\d\x00){2,4}\s?\x00-\x00\s?\x00(?:(?:\d\x00){3,4})\s?\x00-\x00\s?\x00(?:(?:\d\x00){4})(?!\x00\d)'
)
_EMAIL_U16_RX   = re.compile(
    rb'(?:[A-Za-z0-9._%+\-]\x00)+@\x00(?:[A-Za-z0-9.\-]\x00)+\.\x00(?:[A-Za-z]{2,}\x00)'
)
_CARD_U16_RX    = re.compile(
    rb'(?:(?:\d\x00){4})(?:\s?\x00-\x00\s?\x00|\s\x00)'
    rb'(?:(?:\d\x00){4})(?:\s?\x00-\x00\s?\x00|\s\x00)'
    rb'(?:(?:\d\x00){4})(?:\s?\x00-\x00\s?\x00|\s\x00)'
    rb'(?:(?:\d\x00){4})(?!\x00)'
)

def _mask_ascii_span(buf: bytearray, s: int, e: int, keep_at: bool=False):
    for i in range(s, e):
        b = buf[i]
        if 48 <= b <= 57 or 65 <= b <= 90 or 97 <= b <= 122:
            buf[i] = 0x2A
        elif keep_at and b == 64:
            pass

def _mask_utf16le_span(buf: bytearray, s: int, e: int, keep_at: bool=False):
    for i in range(s, e, 2):
        lo, hi = buf[i], buf[i+1]
        if hi == 0x00:
            if (0x30 <= lo <= 0x39) or (0x41 <= lo <= 0x5A) or (0x61 <= lo <= 0x7A):
                buf[i], buf[i+1] = 0x2A, 0x00
            elif keep_at and lo == 0x40:
                pass

def _mask_regex_ascii(buf: bytearray, rx: re.Pattern, keep_at=False) -> int:
    hits = 0
    bnow = bytes(buf)
    for m in list(rx.finditer(bnow)):
        _mask_ascii_span(buf, m.start(), m.end(), keep_at=keep_at)
        hits += 1
    return hits

def _mask_regex_u16(buf: bytearray, rx: re.Pattern, keep_at=False) -> int:
    hits = 0
    bnow = bytes(buf)
    for m in list(rx.finditer(bnow)):
        _mask_utf16le_span(buf, m.start(), m.end(), keep_at=keep_at)
        hits += 1
    return hits

def _compile_rules_for_strings():
    return _compile_rules()

def _sub_with_rules_on_string(txt: str) -> str:
    comp = _compile_rules_for_strings()
    out, _ = _mask_text_with_priority(txt, comp)
    return out

def _redact_ole_bytes_conservative(data: bytes) -> bytes:
    b = bytearray(data)

    # 1) ASCII 문자열 덩어리
    ascii_chunks = []
    start = None
    for i, by in enumerate(b):
        if 32 <= by <= 126:
            if start is None:
                start = i
        else:
            if start is not None and (i - start) >= 6:
                ascii_chunks.append((start, i))
            start = None
    if start is not None and (len(b) - start) >= 6:
        ascii_chunks.append((start, len(b)))

    for s, e in ascii_chunks:
        try:
            txt = bytes(b[s:e]).decode('ascii', 'ignore')
        except Exception:
            continue
        red = _sub_with_rules_on_string(txt)
        nb = red.encode('ascii', 'ignore')
        if len(nb) < (e - s):
            nb = nb + b'*' * ((e - s) - len(nb))
        elif len(nb) > (e - s):
            nb = nb[:(e - s)]
        b[s:e] = nb

    # 2) UTF-16LE 문자열 덩어리
    i = 0; n = len(b)
    while i + 4 <= n:
        j = i; good = 0
        while j + 1 < n and (32 <= b[j] <= 126) and b[j+1] == 0x00:
            good += 1; j += 2
        if good >= 4:
            s, e = i, j
            try:
                txt = bytes(b[s:e]).decode('utf-16le', 'ignore')
            except Exception:
                i = j; continue
            red = _sub_with_rules_on_string(txt)
            nb = red.encode('utf-16le', 'ignore')
            if len(nb) < (e - s):
                nb = nb + b'\x2A\x00' * (((e - s) - len(nb)) // 2)
            elif len(nb) > (e - s):
                nb = nb[:(e - s)]
            b[s:e] = nb
            i = j
        else:
            i += 2

    # 3) 강제 바이트 패턴
    _mask_regex_ascii(b, _PHONE_ASCII_RX)
    _mask_regex_u16(b, _PHONE_U16_RX)
    _mask_regex_ascii(b, _EMAIL_ASCII_RX, keep_at=True)
    _mask_regex_u16(b, _EMAIL_U16_RX, keep_at=True)
    _mask_regex_ascii(b, _CARD_ASCII_RX)
    _mask_regex_u16(b, _CARD_U16_RX)

    return bytes(b)

# =========================================
# HWPX: 텍스트/차트/바이너리
# =========================================
def _hwpx_text(zipf: zipfile.ZipFile) -> str:
    out = []
    for name in sorted(n for n in zipf.namelist() if n.startswith("Contents/") and n.endswith(".xml")):
        xml = zipf.read(name).decode("utf-8", "ignore")
        out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
    for name in sorted(n for n in zipf.namelist() if (n.startswith("Chart/") or n.startswith("Charts/")) and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I | re.DOTALL):
            v = (m.group(1) or m.group(2) or "").strip()
            if v:
                out.append(v)
    for name in (n for n in zipf.namelist() if n.startswith("BinData/")):
        b = zipf.read(name)
        if len(b) >= 4 and b[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(b), "r") as ez:
                    out.append(_xlsx_text_from_zip(ez))
            except Exception:
                pass
    return _cleanup_text("\n".join(x for x in out if x))

def _hwpx_redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    low = filename.lower()

    if low.startswith("preview/"):
        if HWPX_STRIP_PREVIEW:
            return b""
        if HWPX_BLANK_PREVIEW and low.endswith((".png", ".jpg", ".jpeg")):
            return (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
                    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc\x00\x01"
                    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82")

    if HWPX_DISABLE_CACHE and low.endswith("settings.xml"):
        try:
            txt = data.decode("utf-8", "ignore")
            txt = re.sub(r'(?i)usepreview\s*=\s*"(?:true|1)"', 'usePreview="false"', txt)
            txt = re.sub(r"(?i)usepreview\s*=\s*'(?:true|1)'", "usePreview='false'", txt)
            txt = re.sub(r"(?is)<\s*usepreview\s*>.*?</\s*usepreview\s*>", "<usePreview>false</usePreview>", txt)
            txt = re.sub(r"(?is)<\s*preview\s*>.*?</\s*preview\s*>", "<preview>0</preview>", txt)
            txt = re.sub(r'(?i)usecache\s*=\s*"(?:true|1)"', 'useCache="false"', txt)
            txt = re.sub(r"(?is)<\s*cache\s*>.*?</\s*cache\s*>", "<cache>0</cache>", txt)
            return txt.encode("utf-8", "ignore")
        except Exception:
            return data

    if low.startswith("contents/") and low.endswith(".xml"):
        return _sub_text_nodes_preserving(data, comp)[0]

    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
        b2, _hits = _chart_sanitize_preserve_structure(data, comp)
        return _sub_text_nodes_preserving(b2, comp)[0]

    if low.startswith("bindata/"):
        if len(data) >= 4 and data[:2] == b"PK":
            try:
                return _redact_embedded_xlsx_bytes(data)
            except Exception:
                return data
        else:
            if HWPX_BLANK_OLE_BINDATA:
                return b"D0CF11E0A1B11AE1"
            return _redact_ole_bytes_conservative(data)

    return None

# =========================================
# DOCX/XLSX/PPTX (간단판)
# =========================================
def _charts_text_from_zip(zipf: zipfile.ZipFile, prefix: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name in sorted(n for n in zipf.namelist() if n.startswith(prefix) and n.endswith(".xml")):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
        except KeyError:
            continue
        parts = []
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", xml, re.I | re.DOTALL):
            s = m.group(1) or m.group(2) or ""
            if s:
                parts.append(s)
        if parts:
            out[name] = _cleanup_text("\n".join(parts))
    return out

def _docx_text(zipf: zipfile.ZipFile) -> str:
    try:
        xml = zipf.read("word/document.xml").decode("utf-8", "ignore")
    except KeyError:
        xml = ""
    text_main = "".join(m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL))
    text_main = _cleanup_text(text_main)
    charts_map = _charts_text_from_zip(zipf, "word/charts/")
    text_charts = _cleanup_text("\n".join(charts_map.values())) if charts_map else ""
    return _cleanup_text("\n".join(x for x in [text_main, text_charts] if x))

def _docx_scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = _docx_text(zipf)
    comp = _compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            val = m.group(0)
            ok = _is_valid(rule_name, val) if need_valid else True
            out.append(XmlMatch(
                rule=rule_name, value=val, valid=ok,
                context=_context_snippet(text, m.start(), m.end()),
                location=XmlLocation(kind="docx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "docx", text

def _docx_redact_item(filename: str, data: bytes, comp) -> bytes:
    low = filename.lower()
    if low == "word/document.xml":
        return _sub_text_nodes_preserving(data, comp)[0]
    if low.startswith("word/charts/") and low.endswith(".xml"):
        b2, _ = _chart_sanitize_preserve_structure(data, comp)
        return _sub_text_nodes_preserving(b2, comp)[0]
    return data

def _xlsx_text(zipf: zipfile.ZipFile) -> str:
    all_txt = []
    for name in zipf.namelist():
        if name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/"):
            try:
                xml = zipf.read(name).decode("utf-8", "ignore")
            except KeyError:
                continue
            all_txt += [tm.group(1) for tm in re.finditer(r">([^<>]+)<", xml)]
    c_map = _charts_text_from_zip(zipf, "xl/charts/")
    if c_map:
        all_txt += sum((v.split("\n") for v in c_map.values()), [])
    return _cleanup_text("\n".join(all_txt))

def _xlsx_scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = _xlsx_text(zipf)
    comp = _compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            val = m.group(0)
            ok = _is_valid(rule_name, val) if need_valid else True
            out.append(XmlMatch(
                rule=rule_name, value=val, valid=ok,
                context=_context_snippet(text, m.start(), m.end()),
                location=XmlLocation(kind="xlsx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "xlsx", text

def _xlsx_redact_item(filename: str, data: bytes, comp) -> bytes:
    low = filename.lower()
    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        return _sub_text_nodes_preserving(data, comp)[0]
    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = _chart_sanitize_preserve_structure(data, comp)
        return _sub_text_nodes_preserving(b2, comp)[0]
    return data

def _pptx_text(zipf: zipfile.ZipFile) -> str:
    all_txt = []
    for name in sorted(n for n in zipf.namelist() if n.startswith("ppt/slides/") and n.endswith(".xml")):
        xml = zipf.read(name).decode("utf-8", "ignore")
        all_txt += [tm.group(1) for tm in re.finditer(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)]
    c_map = _charts_text_from_zip(zipf, "ppt/charts/")
    if c_map:
        all_txt += sum((v.split("\n") for v in c_map.values()), [])
    return _cleanup_text("\n".join(all_txt))

def _pptx_scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = _pptx_text(zipf)
    comp = _compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            val = m.group(0)
            ok = _is_valid(rule_name, val) if need_valid else True
            out.append(XmlMatch(
                rule=rule_name, value=val, valid=ok,
                context=_context_snippet(text, m.start(), m.end()),
                location=XmlLocation(kind="pptx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "pptx", text

def _pptx_redact_item(filename: str, data: bytes, comp) -> bytes:
    low = filename.lower()
    if low.startswith("ppt/slides/") and low.endswith(".xml"):
        return _sub_text_nodes_preserving(data, comp)[0]
    if low.startswith("ppt/charts/") and low.endswith(".xml"):
        b2, _ = _chart_sanitize_preserve_structure(data, comp)
        return _sub_text_nodes_preserving(b2, comp)[0]
    return data

# =========================================
# 엔트리
# =========================================
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
            matches, k, text = _xlsx_scan(zipf)
        elif kind == "pptx":
            matches, k, text = _pptx_scan(zipf)
        elif kind == "hwpx":
            text = _hwpx_text(zipf)
            comp = _compile_rules()
            out: List[XmlMatch] = []
            # 스캔은 단순 노출용이라도, 규칙은 우선순위 정렬 상태
            for rule_name, rx, need_valid, _prio in comp:
                for m in rx.finditer(text):
                    val = m.group(0)
                    ok = _is_valid(rule_name, val) if need_valid else True
                    out.append(XmlMatch(
                        rule=rule_name, value=val, valid=ok,
                        context=_context_snippet(text, m.start(), m.end()),
                        location=XmlLocation(kind="hwpx", part="*merged_text*", start=m.start(), end=m.end()),
                    ))
            matches, k = out, "hwpx"
        else:
            matches, k, text = _docx_scan(zipf)

        if text and len(text) > 20000:
            text = text[:20000] + "\n… (truncated)"

        return XmlScanResponse(
            file_type=k,
            total_matches=len(matches),
            matches=matches,
            extracted_text=text or "",
        )

def xml_redact_to_file(src_path: str, dst_path: str, filename: str) -> None:
    comp = _compile_rules()
    kind = detect_xml_type(filename)
    with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(dst_path, "w", zipfile.ZIP_DEFLATED) as zout:
        if kind == "hwpx" and "mimetype" in zin.namelist():
            zi = zipfile.ZipInfo("mimetype")
            zi.compress_type = zipfile.ZIP_STORED
            zout.writestr(zi, zin.read("mimetype"))

        for item in zin.infolist():
            name = item.filename
            data = zin.read(name)

            if kind == "docx":
                data = _docx_redact_item(name, data, comp)
                zout.writestr(item, data)

            elif kind == "xlsx":
                data = _xlsx_redact_item(name, data, comp)
                zout.writestr(item, data)

            elif kind == "pptx":
                data = _pptx_redact_item(name, data, comp)
                zout.writestr(item, data)

            elif kind == "hwpx":
                red = _hwpx_redact_item(name, data, comp)
                if red is None:
                    zout.writestr(item, data)
                elif red == b"":
                    continue
                else:
                    zout.writestr(item, red)

            else:
                zout.writestr(item, data)
