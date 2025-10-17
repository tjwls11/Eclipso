from __future__ import annotations

from typing import List, Optional, Literal
from pydantic import BaseModel
import re
from datetime import datetime

# =========================================================
# PDF 쪽 스키마 (원본 유지)
# =========================================================

class PatternItem(BaseModel):
    name: str
    regex: str
    case_sensitive: bool = False
    whole_word: bool = False
    ensure_valid: bool = False

class Box(BaseModel):
    page: int
    x0: float
    y0: float
    x1: float
    y1: float
    # PDF 라우터 호환 필드
    pattern_name: Optional[str] = None
    value: Optional[str] = None
    valid: Optional[bool] = None

class DetectResponse(BaseModel):
    total_matches: int
    boxes: List[Box]

class PdfScanResponse(BaseModel):
    total_matches: int
    boxes: List[Box]

# =========================================================
# XML(DOCX/XLSX/PPTX/HWPX) 스키마
# =========================================================

class XmlLocation(BaseModel):
    kind: Literal["docx", "xlsx", "pptx", "hwpx"]
    part: str
    para_idx: Optional[int] = None
    run_idx: Optional[int] = None
    cell_ref: Optional[str] = None
    start: Optional[int] = None
    end: Optional[int] = None

class XmlMatch(BaseModel):
    rule: str
    value: str
    valid: bool
    context: Optional[str] = None
    location: XmlLocation

class XmlScanResponse(BaseModel):
    file_type: Literal["docx", "xlsx", "pptx", "hwpx"]
    total_matches: int
    matches: List[XmlMatch]
    extracted_text: Optional[str] = ""

# =========================================================
# 공용 다운로드 응답
# =========================================================

class RedactResult(BaseModel):
    file_name: str
    download_path: str  # 예: /redactions/download?path=/tmp/...

# ----------------- validators (임포트/폴백) -----------------
try:
    from .validators import (
        is_valid_rrn,
        is_valid_fgn,
        is_valid_phone_mobile,
        is_valid_phone_city,
        is_valid_email,
        is_valid_card,
        is_valid_driver_license,
    )
except ImportError:
    from validators import (
        is_valid_rrn,
        is_valid_fgn,
        is_valid_phone_mobile,
        is_valid_phone_city,
        is_valid_email,
        is_valid_card,
        is_valid_driver_license,
    )

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")

def is_valid_date6(digits: str) -> bool:
    try:
        dt = datetime.strptime(digits, "%y%m%d")
        return dt.date() <= datetime.today().date()
    except ValueError:
        return False

def is_valid_rrn(rrn: str, opts: dict | None = None) -> bool:
    d = _digits(rrn)
    if len(d) != 13:
        return False
    if not is_valid_date6(d[:6]):
        return False
    return is_valid_rrn_checksum(d) if (opts or {}).get("rrn_checksum", True) else True

def is_valid_fgn_checksum(fgn: str) -> bool:
    d = _digits(fgn)
    if len(d) != 13:
        return False
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    total = sum(int(x) * w for x, w in zip(d[:-1], weights))
    chk = (11 - (total % 11)) % 10
    chk = (chk + 2) % 10
    return chk == int(d[-1])

def is_valid_fgn(fgn: str, opts: dict | None = None) -> bool:
    d = _digits(fgn)
    if len(d) != 13:
        return False
    if not is_valid_date6(d[:6]):
        return False
    if d[6] not in "5678":
        return False
    y = int(d[:2])
    this_year = int(str(datetime.today().year)[2:])
    full_year = 1900 + y if y > this_year else 2000 + y
    if full_year < 2020 and not is_valid_fgn_checksum(d):
        return False
    return True

def is_valid_rrn_checksum(rrn: str) -> bool:
    d = _digits(rrn)
    if len(d) != 13:
        return False
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    total = sum(int(x) * w for x, w in zip(d[:-1], weights))
    chk = (11 - (total % 11)) % 10
    return chk == int(d[-1])

def is_valid_driver_license(lic: str, opts: dict | None = None) -> bool:
    d = _digits(lic)
    if len(d) != 12:
        return False
    year = d[2:4]
    try:
        y = int(year)
        this_year = int(str(datetime.today().year)[2:])
        full_year = 1900 + y if y > this_year else 2000 + y
        if not (1960 <= full_year <= datetime.today().year):
            return False
    except ValueError:
        return False
    return True

def _luhn_ok(d: str) -> bool:
    s = 0
    alt = False
    for ch in reversed(d):
        n = ord(ch) - 48
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        s += n
        alt = not alt
    return (s % 10) == 0

def is_valid_card(number: str, options: dict | None = None) -> bool:
    opts = {"luhn": True, "iin": True}
    if options:
        opts.update(options)
    d = _digits(number)
    if len(d) not in (15, 16):
        return False
    if opts["iin"]:
        if len(d) == 16:
            prefix2 = int(d[:2])
            prefix4 = int(d[:4])
            if d[0] == "4": pass                       # Visa
            elif d[0] == "5" and 51 <= prefix2 <= 55: pass
            elif d[0] == "2" and 2221 <= prefix4 <= 2720: pass
            elif d[0] in ("6","9"): pass               # Discover / 일부 국내
            elif prefix2 == 35: pass                   # JCB
            else: return False
        else:
            if not (d.startswith("34") or d.startswith("37")):  # Amex
                return False
    return _luhn_ok(d) if opts["luhn"] else True

# --- 정규식들 --------------------------------------------------------

RRN_RE = re.compile(r"(?:\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))-?[1234]\d{6}")
FGN_RE = re.compile(r"(?:\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))-?[5678]\d{6}")

# ★ 카드번호 강화 (형태 제약 + 백업) — 실제 치환은 validator로 최종 필터
CARD_RE = re.compile(
    r"(?<!\d)("
    r"\d{4}([ -])\d{4}\2\d{4}\2\d{4}"      # 4-4-4-4
    r"|\d{4}([ -])\d{6}\3\d{5}"            # Amex 4-6-5
    r"|\d{15,16}"                          # backup
    r")(?!\d)"
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")
MOBILE_RE = re.compile(r"01[016789]-?\d{3,4}-?\d{4}")
CITY_RE   = re.compile(r"(?:02|0(?:3[1-3]|4[1-4]|5[1-5]|6[1-4]))-?\d{3,4}-?\d{4}")
PASSPORT_RE = re.compile(r"(?:(?:[MSRODG]\d{8})|(?:[MSRODG]\d{3}[A-Z]\d{4}))")
DRIVER_RE   = re.compile(r"\d{2}-?\d{2}-?\d{6}-?\d{2}")

RULES = {
    "rrn":              {"regex": RRN_RE,       "validator": is_valid_rrn},
    "fgn":              {"regex": FGN_RE,       "validator": is_valid_fgn},
    "email":            {"regex": EMAIL_RE,     "validator": is_valid_email},
    "phone_mobile":     {"regex": MOBILE_RE,    "validator": is_valid_phone_mobile},
    "phone_city":       {"regex": CITY_RE,      "validator": is_valid_phone_city},
    "card":             {"regex": CARD_RE,      "validator": is_valid_card},
    "passport":         {"regex": PASSPORT_RE,  "validator": (lambda v, _opts=None: True)},
    "driver_license":   {"regex": DRIVER_RE,    "validator": is_valid_driver_license},
}

PRESET_PATTERNS = [
    {
        "name": name,
        "regex": rule["regex"].pattern,
        "case_sensitive": False,
        "whole_word": False,
        "ensure_valid": True,  # ← 반드시 validator 통과시에만 치환
    }
    for name, rule in RULES.items()
]
