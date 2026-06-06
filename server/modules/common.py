from __future__ import annotations
import io
import re
import zipfile
import unicodedata
import xml.etree.ElementTree as ET
from typing import List, Tuple, Optional, Callable, Dict, Any

try:
    from ..core.redaction_rules import PRESET_PATTERNS, RULES
except Exception:  # pragma: no cover
    from server.core.redaction_rules import PRESET_PATTERNS, RULES  # type: ignore

__all__ = [
    "cleanup_text",
    "cleanup_text_keep_tabs",
    "compile_rules",
    "sub_text_nodes",
    "mask_literals_in_xml_text_nodes",
    "chart_sanitize",
    "chart_rels_sanitize",
    "sanitize_docx_content_types",
    "xlsx_text_from_zip",
    "redact_embedded_xlsx_bytes",
    "HWPX_STRIP_PREVIEW",
    "HWPX_DISABLE_CACHE",
    "HWPX_BLANK_PREVIEW",
]

HWPX_STRIP_PREVIEW = False
HWPX_DISABLE_CACHE = True
HWPX_BLANK_PREVIEW = True

# 텍스트 정리(개행/공백 + 유니코드 NFKC)
def cleanup_text(text: str) -> str:
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        t = unicodedata.normalize("NFKC", t)
    except Exception:
        pass
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    return t.strip()

def cleanup_text_keep_tabs(text: str) -> str:
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    try:
        t = unicodedata.normalize("NFKC", t)
    except Exception:
        pass
    t = re.sub(r"[ ]+\n", "\n", t)       
    t = re.sub(r"\n{3,}", "\n\n", t)     
    t = re.sub(r"[ ]{2,}", " ", t)       
    return t.strip()

_RULE_PRIORITY = {
    "card": 100, "email": 90, "rrn": 80, "fgn": 80,
    "phone_mobile": 60, "phone_city": 60,
    "driver_license": 40, "passport": 30,
}

def compile_rules() -> List[Tuple[str, re.Pattern, bool, int, Optional[Callable]]]:
    comp: List[Tuple[str, re.Pattern, bool, int, Optional[Callable]]] = []
    for r in PRESET_PATTERNS:
        name = r["name"]
        pat = r["regex"]
        flags = 0 if r.get("case_sensitive") else re.IGNORECASE
        if r.get("whole_word"):
            pat = rf"\b(?:{pat})\b"
        prio = _RULE_PRIORITY.get(name, 0)
        rule_key = (name or "").lower()
        validator = RULES.get(rule_key, {}).get("validator")
        validator = validator if callable(validator) else None
        ensure_valid_flag = r.get("ensure_valid", None)
        need_valid = (validator is not None) if ensure_valid_flag is None else bool(ensure_valid_flag)
        comp.append((name, re.compile(pat, flags), need_valid, prio, validator))
    comp.sort(key=lambda t: t[3], reverse=True)
    return comp

# validator 호출 래퍼
def _is_valid(value: str, validator: Optional[Callable]) -> bool:
    if not validator:
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            return bool(validator(value, None))
    except Exception:
        return False

# 마스킹 유틸(HTML 엔티티 보존)
_ENTITY_RE = re.compile(r"&(#\d+|#x[0-9A-Fa-f]+|[A-Za-z][A-Za-z0-9]+);")

def _mask_preserving_entities(v: str, mask_char_fn) -> str:
    out: List[str] = []
    i = 0
    n = len(v)
    while i < n:
        if v[i] == "&":
            m = _ENTITY_RE.match(v, i)
            if m:
                out.append(v[i:m.end()])
                i = m.end()
                continue
        out.append(mask_char_fn(v[i]))
        i += 1
    return "".join(out)

def _mask_email(v: str) -> str:
    def _m(ch: str) -> str:
        if ch in ("@", "-"):
            return ch
        if ch.isalnum() or ch in "._":
            return "*"
        return ch
    return _mask_preserving_entities(v, _m)

def _mask_keep_rules(v: str) -> str:
    def _mask(ch: str) -> str:
        if ch == "-":
            return ch
        if ch.isalnum() or ch in "._":
            return "*"
        return ch
    return _mask_preserving_entities(v, _mask)

def _mask_value(rule: str, v: str) -> str:
    return _mask_email(v) if (rule or "").lower() == "email" else _mask_keep_rules(v)

# 매칭 스팬 수집/필터/적용
def _collect_spans(src: str, comp) -> tuple[List[tuple], List[tuple]]:
    allowed: List[tuple] = []  
    forbidden: List[tuple] = [] 
    for name, rx, need_valid, prio, validator in comp:
        for m in rx.finditer(src):
            s, e = m.span()
            val = m.group(0)
            if need_valid and not _is_valid(val, validator):
                forbidden.append((s, e))
            else:
                allowed.append((s, e, name, prio))
    return allowed, forbidden

def _overlap(a0, a1, b0, b1) -> bool:
    return not (a1 <= b0 or b1 <= a0)

def _filter_allowed_by_forbidden(allowed, forbidden):
    if not forbidden:
        return allowed
    out = []
    for s, e, nm, pr in allowed:
        if any(_overlap(s, e, fs, fe) for fs, fe in forbidden):
            continue
        out.append((s, e, nm, pr))
    return out

def _mask_digits_keep_first_n(v: str, keep_n: int) -> str:
    dcnt = 0
    out = []
    for ch in (v or ""):
        if ch.isdigit():
            dcnt += 1
            out.append(ch if dcnt <= keep_n else "*")
        else:
            out.append(ch)
    return "".join(out)


def _mask_digits_keep_last_n(v: str, keep_last_n: int) -> str:
    s = v or ""
    digit_pos = [i for i, ch in enumerate(s) if ch.isdigit()]
    if len(digit_pos) <= keep_last_n:
        return s
    keep = set(digit_pos[-keep_last_n:])
    out = []
    for i, ch in enumerate(s):
        if ch.isdigit() and i not in keep:
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)


def _mask_phone_keep_first_group(v: str) -> str:
    s = v or ""
    m = re.search(r"\d+", s)
    if not m:
        return s
    cut = m.end()
    out = []
    for i, ch in enumerate(s):
        if i >= cut and ch.isdigit():
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)


def _mask_card_keep_first4_last4(v: str) -> str:
    s = v or ""
    digit_pos = [i for i, ch in enumerate(s) if ch.isdigit()]
    if len(digit_pos) <= 8:
        return s
    keep = set(digit_pos[:4] + digit_pos[-4:])
    out = []
    for i, ch in enumerate(s):
        if ch.isdigit() and i not in keep:
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)


def _mask_value_with_policy(rule: str, v: str, masking_policy: Optional[dict]) -> str:
    # 기본: 기존 전체 마스킹
    r = (rule or "").lower()
    pol = masking_policy or {}

    # 이메일은 기존 로직 유지(형식 보존)
    if r == "email":
        return _mask_email(v)

    # 부분 마스킹 규칙
    if r == "rrn" and str(pol.get("rrn") or "") == "keep_birth6":
        return _mask_digits_keep_first_n(v, 6)
    if r == "fgn" and str(pol.get("fgn") or "") == "keep_birth6":
        return _mask_digits_keep_first_n(v, 6)

    if r in ("phone_mobile", "phone_city") and str(pol.get("phone") or "") == "keep_first_group":
        return _mask_phone_keep_first_group(v)

    if r == "card" and str(pol.get("card") or "") == "keep_first4_last4":
        return _mask_card_keep_first4_last4(v)

    if r in ("ps", "name") and str(pol.get("ps") or "") == "keep_first_char":
        s = v or ""
        hangul_pos = [i for i, ch in enumerate(s) if re.fullmatch(r"[가-힣]", ch or "")]
        if len(hangul_pos) <= 1:
            return s
        keep_i = hangul_pos[0]
        out = []
        for i, ch in enumerate(s):
            if re.fullmatch(r"[가-힣]", ch or "") and i != keep_i:
                out.append("*")
            else:
                out.append(ch)
        return "".join(out)

    return _mask_keep_rules(v)


def _apply_spans(src: str, allowed, masking_policy: Optional[dict] = None) -> tuple[str, int]:
    if not allowed:
        return src, 0
    allowed.sort(key=lambda t: (t[0], -t[3], -(t[1] - t[0])))
    out = list(src)
    hits = 0
    for s, e, nm, _pr in sorted(allowed, key=lambda t: t[0], reverse=True):
        out[s:e] = list(_mask_value_with_policy(nm, src[s:e], masking_policy))
        hits += 1
    return "".join(out), hits

# XML 텍스트 노드 마스킹
_TEXT_NODE_RE = re.compile(r">([^<>]+)<", re.DOTALL)
_XML_DECL_ENC_RE = re.compile(br'encoding\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


def _detect_xml_encoding(xml_bytes: bytes) -> tuple[str, bytes]:
    """
    XML 바이트의 인코딩을 최대한 보수적으로 감지해서 (encoding, bom_bytes)를 반환.
    - utf-16/utf-8 BOM을 우선
    - (BOM 없을 때) XML 선언부 encoding=...을 ASCII 범위에서 탐색
    """
    if not xml_bytes:
        return "utf-8", b""

    # BOM 우선
    if xml_bytes.startswith(b"\xEF\xBB\xBF"):
        return "utf-8", b"\xEF\xBB\xBF"
    if xml_bytes.startswith(b"\xFF\xFE"):
        return "utf-16le", b"\xFF\xFE"
    if xml_bytes.startswith(b"\xFE\xFF"):
        return "utf-16be", b"\xFE\xFF"

    # XML 선언부는 보통 ASCII라서 앞부분만 스캔
    head = xml_bytes[:256]
    try:
        m = _XML_DECL_ENC_RE.search(head)
        if m:
            enc = (m.group(1) or b"").decode("ascii", "ignore").strip().lower()
            if enc:
                # python codec alias 보정
                if enc in ("utf8",):
                    enc = "utf-8"
                if enc in ("utf16",):
                    # BOM 없을 때 utf-16은 endianness 추정이 어려우니 우선 utf-8로 fallback
                    return "utf-8", b""
                return enc, b""
    except Exception:
        pass

    return "utf-8", b""


def _xml_bytes_to_text(xml_bytes: bytes) -> tuple[str, str, bytes]:
    enc, bom = _detect_xml_encoding(xml_bytes)
    try:
        if bom and enc == "utf-8":
            # utf-8-sig처럼 BOM 제거 후 디코드
            return xml_bytes[len(bom) :].decode("utf-8", "ignore"), "utf-8", bom
        return xml_bytes.decode(enc, "ignore"), enc, bom
    except Exception:
        # 최후의 fallback
        return xml_bytes.decode("utf-8", "ignore"), "utf-8", b""


def _xml_text_to_bytes(text: str, enc: str, bom: bytes) -> bytes:
    try:
        if enc in ("utf-16le", "utf-16be") and bom:
            return bom + (text or "").encode(enc, "ignore")
        if enc == "utf-8" and bom:
            return bom + (text or "").encode("utf-8", "ignore")
        return (text or "").encode(enc, "ignore")
    except Exception:
        return (text or "").encode("utf-8", "ignore")

def sub_text_nodes(xml_bytes: bytes, comp, masking_policy: Optional[Dict[str, Any]] = None) -> Tuple[bytes, int]:
    s, enc, bom = _xml_bytes_to_text(xml_bytes)
    all_allowed: List[tuple] = []
    all_forbidden: List[tuple] = []
    for m in _TEXT_NODE_RE.finditer(s):
        txt = m.group(1)
        if not txt:
            continue
        base = m.start(1)
        allowed, forbidden = _collect_spans(txt, comp)
        for a_s, a_e, nm, pr in allowed:
            all_allowed.append((base + a_s, base + a_e, nm, pr))
        for f_s, f_e in forbidden:
            all_forbidden.append((base + f_s, base + f_e))
    all_allowed = _filter_allowed_by_forbidden(all_allowed, all_forbidden)
    masked, hits = _apply_spans(s, all_allowed, masking_policy=masking_policy)
    return _xml_text_to_bytes(masked, enc, bom), hits

def mask_entities_in_xml_text_nodes(
    xml_bytes: bytes,
    entities: List[Dict[str, Any]],
    masking_policy: Optional[Dict[str, Any]] = None,
) -> bytes:
    if not xml_bytes or not entities:
        return xml_bytes

    s, enc, bom = _xml_bytes_to_text(xml_bytes)

    items: List[Tuple[str, str]] = []
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        lab = str(ent.get("label") or ent.get("entity_group") or ent.get("entity") or "").upper()
        t = ent.get("text") or ent.get("value")
        if t is None:
            continue
        v = str(t).strip()
        if not v:
            continue
        if len(v) < 2 and lab != "PS":
            continue
        items.append((lab, v))

    if not items:
        return xml_bytes

    # dedupe + 긴 문자열 우선
    seen = set()
    norm_items: List[Tuple[str, str]] = []
    for lab, v in sorted(items, key=lambda x: (-len(x[1]), x[0], x[1])):
        k = (lab, v)
        if k in seen:
            continue
        seen.add(k)
        norm_items.append((lab, v))

    def _mask_for_label(lab: str, v: str) -> str:
        ll = (lab or "").upper()
        if ll == "PS":
            return _mask_value_with_policy("ps", v, masking_policy)
        if "@" in v and "." in v.split("@", 1)[-1]:
            return _mask_email(v)
        return _mask_keep_rules(v)

    def _apply_to_segment(seg: str) -> str:
        out = seg
        for lab, lit in norm_items:
            if not lit:
                continue
            if lit in out:
                out = out.replace(lit, _mask_for_label(lab, lit))
        return out

    pieces: List[str] = []
    last = 0
    for m in _TEXT_NODE_RE.finditer(s):
        pieces.append(s[last:m.start(1)])
        pieces.append(_apply_to_segment(m.group(1)))
        last = m.end(1)
    pieces.append(s[last:])

    out_s = "".join(pieces)
    if out_s == s:
        return xml_bytes
    return _xml_text_to_bytes(out_s, enc, bom)


def mask_literals_in_xml_text_nodes(xml_bytes: bytes, literals: List[str]) -> bytes:
    if not xml_bytes or not literals:
        return xml_bytes

    s, enc, bom = _xml_bytes_to_text(xml_bytes)

    lits = [str(x) for x in literals if isinstance(x, str) and x.strip()]
    if not lits:
        return xml_bytes
    lits = sorted(set(lits), key=lambda x: (-len(x), x))

    def _mask_literal(v: str) -> str:
        vv = (v or "").strip()
        if "@" in vv and "." in vv.split("@", 1)[-1]:
            return _mask_email(vv)
        return _mask_keep_rules(vv)

    def _apply_to_segment(seg: str) -> str:
        out = seg
        for lit in lits:
            if not lit or len(lit) < 2:
                continue
            if lit in out:
                out = out.replace(lit, _mask_literal(lit))
        return out

    # 텍스트 노드 영역만 치환
    pieces: List[str] = []
    last = 0
    for m in _TEXT_NODE_RE.finditer(s):
        pieces.append(s[last:m.start(1)])
        pieces.append(_apply_to_segment(m.group(1)))
        last = m.end(1)
    pieces.append(s[last:])

    out_s = "".join(pieces)
    if out_s == s:
        return xml_bytes
    return _xml_text_to_bytes(out_s, enc, bom)

 # (중복 구현 제거: 위의 encoding-aware 버전만 사용)

# 차트 라벨/값 마스킹(XML)
def chart_sanitize(xml_bytes: bytes, comp) -> Tuple[bytes, int]:
    return sub_text_nodes(xml_bytes, comp)

# DOCX ContentTypes 패스스루(훅용 자리)
def sanitize_docx_content_types(xml_bytes: bytes) -> bytes:
    return xml_bytes

# DOCX chart relationships(.rels) sanitize
def chart_rels_sanitize(xml_bytes: bytes) -> bytes:
    try:
        s = xml_bytes.decode("utf-8", "ignore")
        if ("TargetMode" not in s) and ("External" not in s) and ("http" not in s) and ("file:" not in s):
            return xml_bytes

        root = ET.fromstring(s)
        removed = False
        for rel in list(root):
            try:
                attrs = rel.attrib or {}
                target_mode = (attrs.get("TargetMode") or attrs.get("targetMode") or "").strip().lower()
                target = (attrs.get("Target") or attrs.get("target") or "").strip()
                t_low = target.lower()
                is_external = (target_mode == "external") or t_low.startswith(("http://", "https://", "file:", "mailto:"))
                if is_external:
                    root.remove(rel)
                    removed = True
            except Exception:
                continue

        if not removed:
            return xml_bytes
        out = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        return out if isinstance(out, (bytes, bytearray)) else xml_bytes
    except Exception:
        return xml_bytes

# XLSX 텍스트 수정
def xlsx_text_from_zip(zipf: zipfile.ZipFile) -> str:
    out: List[str] = []
    try:
        sst = zipf.read("xl/sharedStrings.xml").decode("utf-8", "ignore")
        out += [m.group(1) for m in re.finditer(r"<t[^>]*>(.*?)</t>", sst, re.DOTALL)]
    except KeyError:
        pass
    for name in (n for n in zipf.namelist() if n.startswith("xl/worksheets/") and n.endswith(".xml")):
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
            out += [m.group(1) for m in re.finditer(r"<v[^>]*>(.*?)</v>", xml, re.DOTALL)]
            out += [m.group(1) for m in re.finditer(r"<t[^>]*>(.*?)</t>", xml, re.DOTALL)]
        except KeyError:
            continue
    for name in (n for n in zipf.namelist() if n.startswith("xl/charts/") and n.endswith(".xml")):
        try:
            s2 = zipf.read(name).decode("utf-8", "ignore")
            for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s2, re.I | re.DOTALL):
                v = (m.group(1) or m.group(2) or "").strip()
                if v:
                    out.append(v)
        except KeyError:
            continue
    return cleanup_text("\n".join(out))

# 내장 XLSX 레닥션(ZIP 리라이트)
def redact_embedded_xlsx_bytes(xlsx_bytes: bytes) -> bytes:
    comp = compile_rules()
    bio_in = io.BytesIO(xlsx_bytes)
    bio_out = io.BytesIO()
    with zipfile.ZipFile(bio_in, "r") as zin, \
        zipfile.ZipFile(bio_out, "w", zipfile.ZIP_DEFLATED) as zout:
        for it in zin.infolist():
            name = it.filename
            data = zin.read(name)
            low = name.lower()
            if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
                data, _ = sub_text_nodes(data, comp)
            elif low.startswith("xl/charts/") and low.endswith(".xml"):
                data, _ = chart_sanitize(data, comp)
            zout.writestr(it, data)
    return bio_out.getvalue()