# -*- coding: utf-8 -*-
from __future__ import annotations
import io, re, zipfile
from typing import List, Tuple, Optional, Callable

# 올바른 경로: server/core/redaction_rules.py
from ..core.redaction_rules import PRESET_PATTERNS, RULES

__all__ = [
    # 공개 유틸
    "cleanup_text",
    "compile_rules",
    "sub_text_nodes",
    "chart_sanitize",
    "chart_rels_sanitize",
    "xlsx_text_from_zip",
    "redact_embedded_xlsx_bytes",
    "sanitize_docx_content_types",
    # 옵션 상수
    "HWPX_STRIP_PREVIEW",
    "HWPX_DISABLE_CACHE",
    "HWPX_BLANK_PREVIEW",
]

# ---------- 옵션(HWPX) ----------
HWPX_STRIP_PREVIEW = True
HWPX_DISABLE_CACHE = True
HWPX_BLANK_PREVIEW = False

# ---------- 텍스트 정리 ----------
def cleanup_text(text: str) -> str:
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text:
        return ""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"[ \t]+\n", "\n", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    t = re.sub(r"[ \t]{2,}", " ", t)
    return t.strip()

# ---------- 룰 컴파일 + 우선순위 ----------
_RULE_PRIORITY = {
    "card": 100, "email": 90, "rrn": 80, "fgn": 80,
    "phone_mobile": 60, "phone_city": 60,
    "phone_mobile": 60, "phone_city": 60,
    "driver_license": 40, "passport": 30,
}
def compile_rules() -> List[Tuple[str, re.Pattern, bool, int, Optional[Callable]]]:
    comp: List[Tuple[str, re.Pattern, bool, int, Optional[Callable]]] = []
    for r in PRESET_PATTERNS:
        name = r["name"]
        pat = r["regex"]

        # 대소문자 옵션
        flags = 0 if r.get("case_sensitive") else re.IGNORECASE
        if r.get("whole_word"):
            pat = rf"\b(?:{pat})\b"
        prio = _RULE_PRIORITY.get(name, 0)
        validator = RULES.get((name or "").lower(), {}).get("validator")
        validator = validator if callable(validator) else None
        comp.append((name, re.compile(pat, flags), bool(r.get("ensure_valid", False)), prio, validator))
    # 우선순위 높은 순
    comp.sort(key=lambda t: t[3], reverse=True)
    return comp

def _is_valid(value: str, validator: Optional[Callable]) -> bool:
    if validator is None:
        return True
    try:
        return bool(validator(value))
    except TypeError:
        return bool(validator(value, None))

# ---------- 마스킹 규칙 ----------
def _mask_email(v: str) -> str:
    """이메일: '@'와 '-'만 보존. 영숫자/ '.' / '_' 는 가림."""
    out = []
    for ch in v:
        if ch in ("@", "-"):
            out.append(ch)
        elif ch.isalnum() or ch in "._":
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)

def _mask_keep_rules(v: str) -> str:
    """공통: '-' 보존, 영숫자 및 '.' '_' 가림, 나머지 기호/공백 보존."""
    out = []
    for ch in v:
        if ch == "-":
            out.append(ch)              # 하이픈 보존
        elif ch.isalnum() or ch in "._":
            out.append("*")             # 영숫자/ . / _ 가림
        else:
            out.append(ch)
    return "".join(out)

def _mask_value(rule: str, v: str) -> str:
    return _mask_email(v) if (rule or "").lower() == "email" else _mask_keep_rules(v)

# ---------- 핵심: 2-패스(토큰 단위) 마스킹 ----------
def _collect_spans(src: str, comp) -> tuple[List[tuple], List[tuple]]:
    """허용 구간(OK)과 금지 구간(FAIL)을 수집."""
    allowed = []   # (s, e, rule, prio)
    forbidden = [] # (s, e)
    for name, rx, need_valid, prio, validator in comp:
        for m in rx.finditer(src):
            s, e = m.span()
            val = m.group(0)
            if need_valid and not _is_valid(val, validator):
                # FAIL → 토큰 전체 보호
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

def _apply_spans(src: str, allowed) -> tuple[str, int]:
    if not allowed:
        return src, 0
    # 시작 오름차순, 우선순위 내림차순, 길이 내림차순
    allowed.sort(key=lambda t: (t[0], -t[3], -(t[1]-t[0])))
    out = list(src)
    hits = 0
    # 뒤에서 앞으로 치환(오프셋 무관)
    for s, e, nm, _pr in sorted(allowed, key=lambda t: t[0], reverse=True):
        seg = src[s:e]
        out[s:e] = list(_mask_value(nm, seg))
        hits += 1
    return "".join(out), hits

def sub_text_nodes(xml_bytes: bytes, comp) -> Tuple[bytes, int]:
    """XML(UTF-8 가정) 전체 문자열에서 토큰 단위로 2-패스 마스킹."""
    s = xml_bytes.decode("utf-8", "ignore")
    allowed, forbidden = _collect_spans(s, comp)
    allowed = _filter_allowed_by_forbidden(allowed, forbidden)
    masked, hits = _apply_spans(s, allowed)
    return masked.encode("utf-8", "ignore"), hits

# ---------- 차트 관련 ----------
# rels 정리 스텁(필요 시 확장). docx_module가 import하므로 반드시 존재해야 함.
def chart_rels_sanitize(rels_bytes: bytes) -> Tuple[bytes, int]:
    return rels_bytes, 0

def chart_sanitize(xml_bytes: bytes, comp) -> Tuple[bytes, int]:
    """차트 XML도 동일 정책으로 텍스트만 마스킹."""
    return sub_text_nodes(xml_bytes, comp)

# ---------- DOCX [Content_Types].xml 보정 ----------
def sanitize_docx_content_types(xml_bytes: bytes) -> bytes:
    return xml_bytes

# ---------- XLSX 텍스트 수집 ----------
# ---------- XLSX 텍스트 수집 ----------
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
        xml = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", xml, re.I | re.DOTALL):
            v = (m.group(1) or m.group(2) or "").strip()
            if v:
                out.append(v)
    return cleanup_text("\n".join(out))

# ---------- OOXML 내장 XLSX 레닥션 ----------
# ---------- OOXML 내장 XLSX 레닥션 ----------
def redact_embedded_xlsx_bytes(xlsx_bytes: bytes) -> bytes:
    """
    OOXML(예: docx/pptx) 안에 포함된 .xlsx를 레닥션.
    구조(relationship, 주소 등)를 건드리지 않고 텍스트 노드만 마스킹한다.
    """
    comp = compile_rules()
    bio_in = io.BytesIO(xlsx_bytes)
    bio_out = io.BytesIO()
    with zipfile.ZipFile(bio_in, "r") as zin, zipfile.ZipFile(bio_out, "w", zipfile.ZIP_DEFLATED) as zout:
        for it in zin.infolist():
            name = it.filename
            data = zin.read(name)
            low = name.lower()
            name = it.filename
            data = zin.read(name)
            low = name.lower()
            if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
                data, _ = sub_text_nodes(data, comp)
            elif low.startswith("xl/charts/") and low.endswith(".xml"):
                data, _ = chart_sanitize(data, comp)
            elif low.startswith("xl/charts/_rels/") and low.endswith(".rels"):
                data, _ = chart_rels_sanitize(data)
            zout.writestr(it, data)
    return bio_out.getvalue()
