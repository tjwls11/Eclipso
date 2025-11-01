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
    """
    HWPX(zip)에서 텍스트를 모아 하나의 문자열로 합친다.
    - Contents/*.xml: 본문
    - Chart(s)/*.xml: 차트 라벨/값
    - BinData/*: 내장 XLSX 안의 텍스트
    """
    out: List[str] = []

    names = zipf.namelist()

    # 1) 본문 Contents/* 의 텍스트
    for name in sorted(names):
        low = name.lower()
        if not (low.startswith("contents/") and low.endswith(".xml")):
            continue
        try:
            xml = zipf.read(name).decode("utf-8", "ignore")
            out += [m.group(1) for m in re.finditer(r">([^<>]+)<", xml)]
        except Exception:
            continue

    # 2) 차트 Chart(s)/* 의 a:t, c:v 텍스트 (라벨/범주/제목 등)
    for name in sorted(names):
        low = name.lower()
        if not ((low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml")):
            continue
        try:
            s = zipf.read(name).decode("utf-8", "ignore")
            for m in re.finditer(
                r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>",
                s,
                re.I | re.DOTALL,
            ):
                v = (m.group(1) or m.group(2) or "").strip()
                if v:
                    out.append(v)
        except Exception:
            continue

    # 3) BinData/*: ZIP(=내장 XLSX)이면 그 안에서도 텍스트 수집
    for name in names:
        low = name.lower()
        if not low.startswith("bindata/"):
            continue
        try:
            b = zipf.read(name)
        except KeyError:
            continue
        if len(b) >= 4 and b[:2] == b"PK":
            # OOXML(XLSX)일 가능성 → 공유 문자열/워크시트/차트에서 텍스트 수집
            try:
                from .common import xlsx_text_from_zip
            except Exception:  # pragma: no cover
                from server.modules.common import xlsx_text_from_zip  # type: ignore
            try:
                with zipfile.ZipFile(io.BytesIO(b), "r") as ez:
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

    # RULES에서 validator 가져오기 (없으면 None → 항상 True로 간주)
    try:
        # 일반적인 현재 리포 구조
        from ..core.redaction_rules import RULES
    except Exception:
        try:
            from ..redaction_rules import RULES  # type: ignore
        except Exception:
            from server.core.redaction_rules import RULES  # type: ignore

    def _get_validator(rule_name: str):
        v = None
        try:
            v = RULES.get(rule_name, {}).get("validator")
        except Exception:
            v = None
        return v if callable(v) else None

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


# ─────────────────────────────────────────────────────────────────────────────
# 파일 단위 레닥션
# ─────────────────────────────────────────────────────────────────────────────
def redact_item(filename: str, data: bytes, comp) -> Optional[bytes]:
    """
    filename: HWPX ZIP 내 엔트리 경로
    data    : 원본 바이트
    comp    : compile_rules() 결과
    return  : 바이트를 반환하면 교체, None이면 원본 유지
    """
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
            txt = data.decode("utf-8", "ignore")
            # usePreview / preview / useCache / cache 끄기
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
        masked, _ = sub_text_nodes(data, comp)
        return masked

    if (low.startswith("chart/") or low.startswith("charts/")) and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)   # a:t, c:strCache
        masked, _ = sub_text_nodes(b2, comp)
        return masked

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
