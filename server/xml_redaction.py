# server/xml_redaction.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import List, Tuple, Callable, Optional

from .redac_rules import PRESET_PATTERNS, RULES
from .schemas import XmlMatch, XmlLocation, XmlScanResponse

# ======================= 옵션 =======================
HWPX_STRIP_PREVIEW = True      # Preview/ 폴더를 결과 파일에서 제거
HWPX_BLANK_PREVIEW = False     # Preview 이미지를 1x1 PNG로 대체(대개 False)

# (중요) 차트 보존 + OLE 내부 문자열 마스킹 모드
HWPX_BLANK_OLE_BINDATA = False   # 차트가 사라지지 않도록 False (OLE은 보수 마스킹으로 처리)

# 프런트 요구사항: extracted_text에는 항상 "원본(raw)"을 내려보냄
PREVIEW_SHOW_ONLY_MATCHES = False

# 라스트리조트(정규식에서 놓친 숫자 패턴 보정) 적용 위치
APPLY_LAST_RESORT_IN_SCAN   = False   # 스캔(미리보기/매치 추출)에는 비적용
APPLY_LAST_RESORT_IN_REDACT = True    # 저장(레닥션 파일)시에만 적용

# ====== 디버그 ======
REDACTION_DEBUG = True  # True면 레닥션 과정 요약을 zip 내부 redaction_debug.txt에 기록
DebugCB = Optional[Callable[[str], None]]

# 1x1 PNG (HWPX 블랭크 프리뷰용)
_BLANK_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0cIDATx\x9cc\x00\x01"
    b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)

# ====== 빈 OLE(CFBF) 스텁(필요시 사용) ======
_BLANK_OLE = bytes.fromhex(
    "D0CF11E0A1B11AE10000000000000000"
    "00000000000000000000000000000000"
    "3E000300FEFF0900" + "00"*480
)

# ======================= 공통 유틸 =======================
_XML_DECL_RE = re.compile(rb'^<\?xml[^>]*encoding=["\']([^"\']+)["\']', re.I)

def _detect_xml_encoding(b: bytes) -> str:
    m = _XML_DECL_RE.match(b.strip()[:200])
    if m:
        enc = m.group(1).decode("ascii", "ignore")
        enc_low = enc.lower().replace("-", "").replace("_", "")
        return "utf-8" if enc_low in ("utf8", "utf") else enc
    return "utf-8"

def _bytes_to_elementtree(b: bytes) -> Tuple[ET.ElementTree, str]:
    enc = _detect_xml_encoding(b)
    try:
        s = b.decode(enc, "strict")
    except Exception:
        s = b.decode(enc, "ignore")
    return ET.ElementTree(ET.fromstring(s)), enc

def _elementtree_to_bytes(tree: ET.ElementTree, enc: str) -> bytes:
    bio = io.BytesIO()
    try:
        tree.write(bio, encoding=enc, xml_declaration=True)
    except LookupError:
        bio = io.BytesIO()
        tree.write(bio, encoding="utf-8", xml_declaration=True)
    return bio.getvalue()

def _looks_like_zip(b: bytes) -> bool:
    return len(b) >= 4 and b[:2] == b"PK"

# ======================= 마스킹/정규화 =======================
_ZW = "\u200b\u200c\u200d\u2060"       # zero-width
_HYPH = "\u2010\u2011\u2012\u2013\u2014\u2212"  # 다양한 하이픈

def _pre_norm(s: str) -> str:
    if not s:
        return s
    s = s.replace("\u00a0", " ")
    for ch in _ZW:
        s = s.replace(ch, "")
    for ch in _HYPH:
        s = s.replace(ch, "-")
    return s.replace("\r\n", "\n").replace("\r", "\n")

def _mask_keep_seps(s: str) -> str:
    return "".join("*" if ch.isalnum() else ch for ch in s)

def _mask_email_preserve_at(v: str) -> str:
    return "".join(ch if ch == "@" else "*" for ch in v)

def _mask_for_rule(rule: str, v: str) -> str:
    return _mask_email_preserve_at(v) if (rule or "").lower() == "email" else _mask_keep_seps(v)

# ======================= 텍스트 정리 =======================
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
    t = re.sub(r"[\x00-\x09\x0B-\x1F]", " ", t)  # 제어문자
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    return t.strip()

# ======================= Luhn & 라스트리조트 =======================
def _digits(s: str) -> str:
    return "".join(ch for ch in s if ch.isdigit())

def _luhn_ok(num: str) -> bool:
    if not (14 <= len(num) <= 19):
        return False
    tot = 0
    odd = len(num) & 1
    for i, ch in enumerate(num):
        d = ord(ch) - 48
        if (i & 1) == odd:
            d *= 2
            if d > 9:
                d -= 9
        tot += d
    return (tot % 10) == 0

_CARD_SEP = r"(?:\s*-\s*|\s+)"
_LAST_RESORT_PATTERNS = [
    ("phone_city", re.compile(r'(?<!\d)0\d{1,2}\s*-\s*\d{3,4}\s*-\s*\d{4}(?!\d)')),
    ("card", re.compile(rf'(?<!\d)\d{{4}}{_CARD_SEP}\d{{4}}{_CARD_SEP}\d{{4}}{_CARD_SEP}\d{{4}}(?!\d)')),
]

def _mask_digits_preserve_seps(s: str) -> str:
    return "".join("*" if ch.isdigit() else ch for ch in s)

def _last_resort_mask(txt: str) -> Tuple[str, bool]:
    changed = False
    cur = txt
    for kind, rx in _LAST_RESORT_PATTERNS:
        def repl(m: re.Match):
            nonlocal changed
            g = m.group(0)
            if kind == "card":
                if not _luhn_ok(_digits(g)):
                    return g
            changed = True
            return _mask_digits_preserve_seps(g)
        cur2 = rx.sub(repl, cur)
        if cur2 != cur:
            changed = True
            cur = cur2
    return cur, changed

# ======================= 원문 표시용 보정 =======================
_TAG_RE = re.compile(r"<[^>]+>")
_REF_RE = re.compile(r"\bSheet\d+!\$[A-Z]+\$\d+(?::\$[A-Z]+\$\d+)?\b")
_GEN_RE = re.compile(r"\bGeneral\b", re.I)

def _strip_tags(s: str) -> str:
    return _TAG_RE.sub(" ", s)

def _hide_chart_meta(s: str) -> str:
    return _GEN_RE.sub(" ", _REF_RE.sub(" ", s))

# ======================= 룰 컴파일/검증/치환 =======================
def _compile_rules():
    comp = []
    for r in PRESET_PATTERNS:
        name = r["name"]
        pat = r["regex"]
        flags = 0 if r.get("case_sensitive") else re.IGNORECASE
        if r.get("whole_word"):
            pat = rf"\b(?:{pat})\b"
        need_valid = bool(r.get("ensure_valid", False))
        if name.lower() in {"card", "credit_card", "cc"}:
            need_valid = True
        comp.append((name, re.compile(pat, flags), need_valid))
    return comp

def _is_valid(kind: str, value: str) -> bool:
    k = (kind or "").lower()
    if k in {"card", "credit_card", "cc"}:
        return _luhn_ok(_digits(value))
    rule = RULES.get(k)
    if rule:
        validator = rule.get("validator")
        if callable(validator):
            try:
                return bool(validator(value))
            except TypeError:
                return bool(validator(value, None))
    return True

def _apply_rules_to_text(raw: str, comp, *, last_resort: bool) -> Tuple[str, bool, int]:
    changed = False
    count = 0
    cur = _pre_norm(raw)
    for rule_name, rx, need_valid in comp:
        def _repl(m: re.Match):
            nonlocal changed, count
            val = m.group(0)
            if need_valid and not _is_valid(rule_name, val):
                return val
            changed = True
            count += 1
            return _mask_for_rule(rule_name, val)
        cur2 = rx.sub(_repl, cur)
        if cur2 != cur:
            cur = cur2
    if last_resort:
        cur2, ch2 = _last_resort_mask(cur)
        if ch2:
            count += 1
            changed = True
            cur = cur2
    return cur, changed, count

# ======================= OOXML 치환 공통 =======================
def _ln(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag

_TEXT_TAGS = {"t", "v"}  # a:t, w:t, s:v, c:v

def redact_xml_bytes_precise(xml_bytes: bytes, filename: str, comp, *, last_resort: bool) -> Tuple[bytes, bool, int]:
    try:
        tree, enc = _bytes_to_elementtree(xml_bytes)
    except Exception:
        return xml_bytes, False, 0
    root = tree.getroot()
    changed = False
    count = 0
    for el in root.iter():
        ln = _ln(el.tag)
        if ln in _TEXT_TAGS and el.text:
            new, ch, c = _apply_rules_to_text(el.text, comp, last_resort=last_resort)
            if ch:
                el.text, changed = new, True
                count += c
        if el.tail:
            new, ch, c = _apply_rules_to_text(el.tail, comp, last_resort=last_resort)
            if ch:
                el.tail, changed = new, True
                count += c
    return (_elementtree_to_bytes(tree, enc), True, count) if changed else (xml_bytes, False, 0)

# ======================= HWPX 텍스트 노드 보수 치환 =======================
_TEXT_NODE_RE = re.compile(r">(?!\s*<)([^<]+)<", re.DOTALL)

def _sub_text_nodes_preserving(xml_bytes: bytes, comp, *, last_resort: bool) -> Tuple[bytes, int]:
    enc = _detect_xml_encoding(xml_bytes)
    try:
        s = xml_bytes.decode(enc, "strict")
    except Exception:
        s = xml_bytes.decode(enc, "ignore")
    total = 0
    def _apply_all(txt: str) -> str:
        nonlocal total
        cur = _pre_norm(txt)
        for rule_name, rx, need_valid in comp:
            def _r(m: re.Match):
                nonlocal total
                v = m.group(0)
                if need_valid and not _is_valid(rule_name, v):
                    return v
                total += 1
                return _mask_for_rule(rule_name, v)
            cur = rx.sub(_r, cur)
        if last_resort:
            cur2, ch2 = _last_resort_mask(cur)
            if ch2:
                total += 1
                cur = cur2
        return cur
    out = _TEXT_NODE_RE.sub(lambda m: ">" + _apply_all(m.group(1)) + "<", s)
    return out.encode(enc, "ignore"), total

# ======================= 내장 XLSX (임베디드 차트 포함) =======================
_CHART_VAL_RE = re.compile(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", re.I | re.DOTALL)

def _redact_embedded_xlsx_bytes(xlsx_bytes: bytes, comp) -> Tuple[bytes, int]:
    bio_in, bio_out = io.BytesIO(xlsx_bytes), io.BytesIO()
    total = 0
    with zipfile.ZipFile(bio_in, "r") as zin, zipfile.ZipFile(bio_out, "w", zipfile.ZIP_DEFLATED) as zout:
        for it in zin.infolist():
            data, low = zin.read(it.filename), it.filename.lower()
            if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
                xml = data.decode("utf-8", "ignore")
                xml, _, c = _apply_rules_to_text(xml, _compile_rules(), last_resort=True)
                data = xml.encode("utf-8", "ignore")
                total += c
            elif low.startswith("xl/charts/") and low.endswith(".xml"):
                data, c = _sub_text_nodes_preserving(data, _compile_rules(), last_resort=True)
                total += c
            zout.writestr(it, data)
    return bio_out.getvalue(), total

def _extract_text_from_xlsx_for_preview(xlsx_bytes: bytes) -> str:
    out = []
    with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as z:
        if "xl/sharedStrings.xml" in z.namelist():
            s = z.read("xl/sharedStrings.xml").decode("utf-8", "ignore")
            out += re.findall(r">([^<>]+)<", s)
        for n in (n for n in z.namelist() if n.startswith("xl/worksheets/")):
            s = z.read(n).decode("utf-8", "ignore")
            out += re.findall(r">([^<>]+)<", s)
        for n in (n for n in z.namelist() if n.startswith("xl/charts/") and n.endswith(".xml")):
            s = z.read(n).decode("utf-8", "ignore")
            for m in _CHART_VAL_RE.finditer(s):
                v = (m.group(1) or m.group(2) or "").strip()
                if v:
                    out.append(v)
    return _cleanup_text("\n".join(out))

# ======================= 차트 externalData/참조 제거(옵션) =======================
_C_EXTERNAL_RE = re.compile(rb"(?is)<\s*c:externalData\b[^>]*>.*?</\s*c:externalData\s*>")
_C_REF_RE = re.compile(rb"(?is)<c:(?:strRef|numRef)\b[^>]*>.*?<c:(?:strCache|numCache)\b")

def _strip_chart_external_data(xml_bytes: bytes) -> tuple[bytes, int]:
    after = _C_EXTERNAL_RE.sub(b"", xml_bytes)
    if after != xml_bytes:
        return after, 1
    return xml_bytes, 0

def _strip_chart_refs_to_cache(xml_bytes: bytes) -> tuple[bytes, int]:
    after, n = _C_REF_RE.subn(b"<c:strCache", xml_bytes)
    return after, n

# ======================= OLE(CFBF) 내부 문자열/패턴 보수 마스킹 =======================
def _mask_ascii_keep_seps_text(s: str, comp) -> tuple[str, int]:
    out, _, cnt = _apply_rules_to_text(s, comp, last_resort=True)
    return out, cnt

# ---- 바이트 레벨 강제 마스킹(전화번호) ----
_PHONE_ASCII_RX = re.compile(rb'(?<!\d)\d{2,4}\s*-\s*\d{3,4}\s*-\s*\d{4}(?!\d)')
_PHONE_U16_RX = re.compile(
    rb'(?:(?<!\x00\d)\d\x00){2,4}\s?\x00-\x00\s?\x00(?:(?:\d\x00){3,4})\s?\x00-\x00\s?\x00(?:(?:\d\x00){4})(?!\x00\d)'
)

def _mask_phone_ascii_bytes(buf: bytearray) -> int:
    hits = 0
    bnow = bytes(buf)
    for m in list(_PHONE_ASCII_RX.finditer(bnow)):
        s, e = m.span()
        seg = bytearray(bnow[s:e])
        for i, by in enumerate(seg):
            if 48 <= by <= 57:
                seg[i] = 0x2A
        buf[s:e] = seg
        hits += 1
    return hits

def _mask_phone_utf16le_bytes(buf: bytearray) -> int:
    hits = 0
    bnow = bytes(buf)
    for m in list(_PHONE_U16_RX.finditer(bnow)):
        s, e = m.span()
        seg = bytearray(bnow[s:e])
        for i in range(0, len(seg) - 1, 2):
            lo, hi = seg[i], seg[i+1]
            if 0x30 <= lo <= 0x39 and hi == 0x00:
                seg[i], seg[i+1] = 0x2A, 0x00
        buf[s:e] = seg
        hits += 1
    return hits

def _redact_ole_bytes_conservative(data: bytes, comp) -> tuple[bytes, int]:
    """
    CFBF(OLE) 바이너리 안에서
      1) '문자열로 보이는' 덩어리(ASCII/UTF-16LE) 길이 보존 마스킹
      2) 바이트 레벨 강제 패턴(전화번호) 마스킹
    """
    b = bytearray(data)
    total = 0

    # 1) ASCII 문자열 덩어리
    ascii_chunks = []
    start = None
    for i, by in enumerate(b):
        if 32 <= by <= 126:
            if start is None: start = i
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
        red, cnt = _mask_ascii_keep_seps_text(txt, comp)
        if cnt:
            nb = red.encode('ascii', 'ignore')
            if len(nb) < (e - s):
                nb = nb + b'*' * ((e - s) - len(nb))
            elif len(nb) > (e - s):
                nb = nb[:(e - s)]
            b[s:e] = nb
            total += cnt

    # 2) UTF-16LE 문자열 덩어리
    i = 0
    n = len(b)
    while i + 4 <= n:
        j = i
        good = 0
        while j + 1 < n:
            lo, hi = b[j], b[j+1]
            if (32 <= lo <= 126) and (hi == 0x00):
                good += 1
                j += 2
            else:
                break
        if good >= 4:
            s, e = i, j
            try:
                txt = bytes(b[s:e]).decode('utf-16le', 'ignore')
            except Exception:
                i = j
                continue
            red, cnt = _mask_ascii_keep_seps_text(txt, comp)
            if cnt:
                nb = red.encode('utf-16le', 'ignore')
                if len(nb) < (e - s):
                    nb = nb + b'\x2A\x00' * (((e - s) - len(nb)) // 2)
                elif len(nb) > (e - s):
                    nb = nb[:(e - s)]
                b[s:e] = nb
                total += cnt
            i = j
        else:
            i += 2

    # 3) 바이트 레벨 강제 마스킹(전화번호)
    forced = 0
    forced += _mask_phone_ascii_bytes(b)
    forced += _mask_phone_utf16le_bytes(b)
    total += forced

    return bytes(b), total

# ======================= 원문(사람용) 추출 =======================
def _extract_human_text_from_xml(xml_bytes: bytes, prefer_chart_vals: bool = False) -> str:
    enc = _detect_xml_encoding(xml_bytes)
    try:
        s = xml_bytes.decode(enc, "strict")
    except Exception:
        s = xml_bytes.decode(enc, "ignore")

    if prefer_chart_vals:
        vals = []
        for m in _CHART_VAL_RE.finditer(s):
            v = (m.group(1) or m.group(2) or "").strip()
            if v:
                vals.append(v)
        if vals:
            return _hide_chart_meta(_strip_tags(_cleanup_text("\n".join(vals))))

    try:
        tree = ET.ElementTree(ET.fromstring(s))
    except Exception:
        return ""
    parts = []
    for el in tree.getroot().iter():
        tag = el.tag.rsplit("}", 1)[-1] if "}" in el.tag else el.tag
        if tag in ("f", "formatCode"):
            continue
        if el.text and el.text.strip():
            parts.append(el.text)
        if el.tail and el.tail.strip():
            parts.append(el.tail)
    return _hide_chart_meta(_strip_tags(_cleanup_text("\n".join(parts))))

# ======================= 스캔/레닥션 제너릭 =======================
def _scan_generic(zipf: zipfile.ZipFile, include_pred, kind: str) -> Tuple[List[XmlMatch], str]:
    comp = _compile_rules()
    collected = []
    for name in sorted(zipf.namelist()):
        low = name.lower()
        if not low.endswith(".xml") or not include_pred(name):
            continue
        b = zipf.read(name)
        prefer_chart = (kind == "hwpx" and (low.startswith("chart/") or low.startswith("charts/"))) or \
                       (kind in ("docx", "pptx", "xlsx") and (low.startswith("ppt/charts/") or low.startswith("word/charts/") or low.startswith("xl/charts/")))
        extracted = _extract_human_text_from_xml(b, prefer_chart_vals=prefer_chart)
        if extracted:
            collected.append(extracted)

    text = _cleanup_text("\n".join(collected))
    matches: List[XmlMatch] = []
    for rule_name, rx, need_valid in _compile_rules():
        for m in rx.finditer(text):
            val = m.group(0)
            ok = _is_valid(rule_name, val) if need_valid else True
            matches.append(XmlMatch(
                rule=rule_name,
                value=val,
                valid=ok,
                context=text[max(0, m.start()-20):min(len(text), m.end()+20)],
                location=XmlLocation(kind=kind, part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return matches, text

def _writestr_like(zipout: zipfile.ZipFile, srcinfo: zipfile.ZipInfo, data: bytes):
    zi = zipfile.ZipInfo(filename=srcinfo.filename, date_time=srcinfo.date_time)
    zi.compress_type = srcinfo.compress_type
    zi.external_attr = srcinfo.external_attr
    zi.internal_attr = srcinfo.internal_attr
    zi.create_system = srcinfo.create_system
    zipout.writestr(zi, data)

def _redact_generic(zin: zipfile.ZipFile, zout: zipfile.ZipFile, include_pred, debug: DebugCB=None) -> Tuple[int, int]:
    comp = _compile_rules()
    total_files = 0
    total_hits = 0
    for it in zin.infolist():
        data, name = zin.read(it.filename), it.filename
        if name.lower().endswith(".xml") and include_pred(name):
            new_data, changed, cnt = redact_xml_bytes_precise(data, name, comp, last_resort=APPLY_LAST_RESORT_IN_REDACT)
            if changed:
                if debug: debug(f"[GEN] {name} changed count={cnt}")
                _writestr_like(zout, it, new_data)
                total_files += 1
                total_hits += cnt
                continue
        _writestr_like(zout, it, data)
    if debug:
        debug(f"[GENERIC] files_changed={total_files}, total_hits={total_hits}")
    return total_files, total_hits

# ======================= 포맷별 =======================
def _docx_scan(zipf): m, t = _scan_generic(zipf, lambda n: n.startswith("word/"), "docx"); return m, "docx", t
def _docx_redact(zin, zout, debug: DebugCB=None): _redact_generic(zin, zout, lambda n: n.startswith("word/"), debug)

def _xlsx_scan(zipf): m, t = _scan_generic(zipf, lambda n: n.startswith("xl/"), "xlsx"); return m, "xlsx", t
def _xlsx_redact(zin, zout, debug: DebugCB=None): _redact_generic(zin, zout, lambda n: n.startswith("xl/"), debug)

def _pptx_scan(zipf): m, t = _scan_generic(zipf, lambda n: n.startswith("ppt/"), "pptx"); return m, "pptx", t
def _pptx_redact(zin, zout, debug: DebugCB=None): _redact_generic(zin, zout, lambda n: n.startswith("ppt/"), debug)

def _hwpx_scan(zipf):
    pred = lambda n: (n.lower().endswith(".xml")
                      and not n.lower().startswith("meta-inf/")
                      and not n.lower().startswith("preview/"))
    matches, text = _scan_generic(zipf, pred, "hwpx")

    # BinData 내장 XLSX(차트 포함) 원문도 수집
    extra = []
    for n in zipf.namelist():
        if n.lower().startswith("bindata/"):
            b = zipf.read(n)
            if _looks_like_zip(b):
                extra.append(_extract_text_from_xlsx_for_preview(b))
    merged = _hide_chart_meta(_strip_tags("\n".join([text] + [e for e in extra if e])))
    return matches, "hwpx", _cleanup_text(merged)

def _hwpx_redact(zin, zout, debug: DebugCB=None):
    comp = _compile_rules()
    pred_xml = lambda n: (n.lower().endswith(".xml")
                          and not n.lower().startswith("meta-inf/")
                          and not n.lower().startswith("preview/"))

    names = [it.filename for it in zin.infolist()]
    charts = [n for n in names if n.lower().startswith(("chart/", "charts/")) and n.lower().endswith(".xml")]
    bindatas = [n for n in names if n.lower().startswith("bindata/")]
    if debug:
        debug(f"[INV] chart_xml={len(charts)} files")
        for n in charts[:20]: debug(f"[INV]   chart: {n}")
        debug(f"[INV] bindata={len(bindatas)} files")
        for n in bindatas[:20]: debug(f"[INV]   bin: {n}")

    files_changed = 0
    total_hits = 0

    for it in zin.infolist():
        name, data, low = it.filename, zin.read(it.filename), it.filename.lower()

        # Preview 제거/대체
        if low.startswith("preview/"):
            if HWPX_STRIP_PREVIEW:
                if debug: debug(f"[HWPX] drop {name}")
                continue
            if HWPX_BLANK_PREVIEW and (low.endswith(".png") or low.endswith(".jpg") or low.endswith(".jpeg")):
                _writestr_like(zout, it, _BLANK_PNG)
                if debug: debug(f"[HWPX] blank Preview image: {name}")
            else:
                _writestr_like(zout, it, data)
            continue

        # settings.xml 캐시/프리뷰 OFF
        if low.endswith("settings.xml"):
            try:
                txt0 = data.decode("utf-8", "ignore"); txt = txt0
                txt = re.sub(r'(?i)usepreview\s*=\s*"(?:true|1)"', 'usePreview="false"', txt)
                txt = re.sub(r"(?i)usepreview\s*=\s*'(?:true|1)'", "usePreview='false'", txt)
                txt = re.sub(r"(?is)<\s*usepreview\s*>.*?</\s*usepreview\s*>", "<usePreview>false</usePreview>", txt)
                txt = re.sub(r"(?is)<\s*preview\s*>.*?</\s*preview\s*>", "<preview>0</preview>", txt)
                txt = re.sub(r'(?i)usecache\s*=\s*"(?:true|1)"', 'useCache="false"', txt)
                txt = re.sub(r"(?is)<\s*cache\s*>.*?</\s*cache\s*>", "<cache>0</cache>", txt)
                data = txt.encode("utf-8")
                if debug and txt0 != txt: debug("[HWPX] settings.xml: preview/cache disabled")
            except Exception:
                pass
            _writestr_like(zout, it, data)
            continue

        # BinData 처리 (XLSX ZIP / OLE)
        if low.startswith("bindata/"):
            if _looks_like_zip(data):
                new, cnt = _redact_embedded_xlsx_bytes(data, comp)
                _writestr_like(zout, it, new)
                files_changed += (1 if cnt else 0)
                total_hits += cnt
                if debug: debug(f"[BinData] {name} redacted ZIP={cnt}")
            else:
                # OLE: 보수 문자열 + 바이트 강제 패턴 마스킹(차트 표시 유지)
                new, cnt = _redact_ole_bytes_conservative(data, comp)
                if HWPX_BLANK_OLE_BINDATA and cnt == 0:
                    _writestr_like(zout, it, _BLANK_OLE)
                    if debug: debug(f"[BinData] {name} blanked (opt)")
                else:
                    _writestr_like(zout, it, new if cnt else data)
                files_changed += (1 if cnt else 0)
                total_hits += cnt
                if debug: debug(f"[BinData] {name} redacted OLE={cnt}")
            continue

        # 차트 XML
        if low.startswith(("chart/", "charts/")) and low.endswith(".xml"):
            data2, ext_removed = _strip_chart_external_data(data)
            data2, ref_removed = _strip_chart_refs_to_cache(data2)  # 캐시 외 참조 제거(옵션)
            data3, changed, cnt = redact_xml_bytes_precise(
                data2, name, comp, last_resort=APPLY_LAST_RESORT_IN_REDACT
            )
            if not changed:
                data3, cnt2 = _sub_text_nodes_preserving(
                    data2, comp, last_resort=APPLY_LAST_RESORT_IN_REDACT
                )
                cnt += cnt2
            _writestr_like(zout, it, data3 if (cnt or ext_removed or ref_removed) else data)
            if cnt or ext_removed or ref_removed:
                files_changed += 1
                total_hits += cnt + (1 if ext_removed else 0) + (ref_removed)
                if debug:
                    debug(f"[ChartXML] {name} redacted count={cnt} ext_removed={ext_removed} ref_removed={ref_removed}")
            else:
                if debug: debug(f"[ChartXML] {name} nochange")
            continue

        # 일반 XML
        if pred_xml(name):
            new_data, cnt = _sub_text_nodes_preserving(
                data, comp, last_resort=APPLY_LAST_RESORT_IN_REDACT
            )
            _writestr_like(zout, it, new_data if cnt else data)
            if cnt:
                files_changed += 1
                total_hits += cnt
                if debug: debug(f"[XML] {name} redacted count={cnt}")
        else:
            _writestr_like(zout, it, data)

    if debug:
        debug(f"[HWPX] files_changed={files_changed}, total_hits={total_hits}")

# ======================= 미리보기(매치 → 문자열) =======================
def _preview_from_matches(matches: List[XmlMatch]) -> str:
    seen, out = set(), []
    for m in matches:
        masked = _mask_for_rule(m.rule, _pre_norm(m.value))
        key = (m.rule, masked)
        if key in seen:
            continue
        seen.add(key)
        out.append(f"[{m.rule}] {masked}")
    return "\n".join(out)

# ======================= 타입/엔트리 =======================
def detect_xml_type(filename: str) -> str:
    l = (filename or "").lower()
    if l.endswith(".docx"): return "docx"
    if l.endswith(".xlsx"): return "xlsx"
    if l.endswith(".pptx"): return "pptx"
    if l.endswith(".hwpx"): return "hwpx"
    return "docx"

def detect_xml_type_by_content(zipf: zipfile.ZipFile) -> str:
    names = [n.lower() for n in zipf.namelist()]
    if any(n.startswith("contents/") for n in names) or any(n.startswith("chart/") for n in names) or any(n.startswith("charts/") for n in names):
        return "hwpx"
    if any(n.startswith("ppt/") for n in names):
        return "pptx"
    if any(n.startswith("word/") for n in names):
        return "docx"
    if any(n.startswith("xl/") for n in names):
        return "xlsx"
    return detect_xml_type("")

def xml_scan(file_bytes: bytes, filename: str) -> XmlScanResponse:
    with io.BytesIO(file_bytes) as bio, zipfile.ZipFile(bio, "r") as zipf:
        kind = detect_xml_type_by_content(zipf)

        if kind == "xlsx":
            matches, k, raw = _xlsx_scan(zipf)
        elif kind == "pptx":
            matches, k, raw = _pptx_scan(zipf)
        elif kind == "hwpx":
            matches, k, raw = _hwpx_scan(zipf)
        else:
            matches, k, raw = _docx_scan(zipf)

        preview = raw
        if preview and len(preview) > 20000:
            preview = preview[:20000] + "\n… (truncated)"

        return XmlScanResponse(
            file_type=k,
            total_matches=len(matches),
            matches=matches,
            extracted_text=preview or "",
        )

# ======================= 패키지 사후 검증(Residual Scan) =======================
_RESIDUAL_PATTERNS = [
    re.compile(rb'(?<!\d)\d{2,4}\s*-\s*\d{3,4}\s*-\s*\d{4}(?!\d)'),                     # 전화번호 ASCII
    re.compile(rb'(?:\d\x00){2,4}\s?\x00-\x00\s?\x00(?:\d\x00){3,4}\s?\x00-\x00\s?\x00(?:\d\x00){4}'),  # 전화번호 UTF-16LE
    re.compile(rb'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}'),                  # 이메일 ASCII
    re.compile(rb'(?<!\d)\d{4}(?:\s*-\s*|\s)\d{4}(?:\s*-\s*|\s)\d{4}(?:\s*-\s*|\s)\d{4}(?!\d)'),        # 카드 4-4-4-4
]

def _residual_scan(zip_bytes: bytes) -> list[str]:
    out: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
            for name in sorted(z.namelist()):
                b = z.read(name)
                hit_total = 0
                for rx in _RESIDUAL_PATTERNS:
                    for m in rx.finditer(b):
                        hit_total += 1
                        if hit_total <= 5:
                            s, e = m.span()
                            frag = b[max(0, s-16):min(len(b), e+16)]
                            frag = bytes((ch if 32 <= ch <= 126 else 0x2E) for ch in frag)
                            out.append(f"[RESIDUAL] {name} @ {s}-{e} :: {frag.decode('ascii','ignore')}")
                if hit_total:
                    out.append(f"[RESIDUAL] {name} total_hits={hit_total}")
    except Exception as e:
        out.append(f"[RESIDUAL] scan_error: {e}")
    return out

# ======================= ZIP 쓰기/레닥션 엔트리 =======================
def xml_redact_to_file(src_path: str, dst_path: str, filename: str) -> None:
    debug_lines: List[str] = []
    def log(s: str):
        if REDACTION_DEBUG:
            debug_lines.append(s)

    with zipfile.ZipFile(src_path, "r") as zin, zipfile.ZipFile(dst_path, "w") as zout:
        kind = detect_xml_type_by_content(zin)
        if REDACTION_DEBUG:
            log(f"[INFO] kind={kind}, filename={filename}")

        if kind == "hwpx":
            if "mimetype" in zin.namelist():
                zi = zipfile.ZipInfo("mimetype")
                zi.compress_type = zipfile.ZIP_STORED
                zout.writestr(zi, zin.read("mimetype"))
            _hwpx_redact(zin, zout, debug=log)
        elif kind == "docx":
            _docx_redact(zin, zout, debug=log)
        elif kind == "xlsx":
            _xlsx_redact(zin, zout, debug=log)
        elif kind == "pptx":
            _pptx_redact(zin, zout, debug=log)
        else:
            for it in zin.infolist():
                _writestr_like(zout, it, zin.read(it.filename))

    # ===== 사후 검증: 결과물 재스캔 후 디버그 파일로 기록 =====
    if REDACTION_DEBUG:
        try:
            out_bytes = open(dst_path, "rb").read()
            residual = _residual_scan(out_bytes)
            if residual:
                debug_lines.append("[RESIDUAL] ========= begin =========")
                debug_lines.extend(residual)
                debug_lines.append("[RESIDUAL] =========  end  =========")
        except Exception as e:
            debug_lines.append(f"[RESIDUAL] failed: {e}")

        with zipfile.ZipFile(dst_path, "a") as zout:
            zout.writestr("redaction_debug.txt", "\n".join(debug_lines).encode("utf-8"))
