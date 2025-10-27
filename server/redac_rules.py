# -*- coding: utf-8 -*-
"""
레닥션 규칙 및 프리셋 패턴
- RULES: name -> {regex, validator}
- PRESET_PATTERNS: 라우터/클라이언트가 요청할 때 사용할 기본 패턴 목록
"""

import re
from .validators import (
    is_valid_rrn,
    is_valid_fgn,
    is_valid_phone_mobile,
    is_valid_phone_city,
    is_valid_email,
    is_valid_card,
    is_valid_driver_license,
)

# --- 정규식 정의 ---------------------------------------------------------

# 주민등록번호 (형식)
RRN_RE = re.compile(r"\d{6}-\d{7}")

# 외국인등록번호 (형식은 동일, validator에서 구분)
FGN_RE = re.compile(r"\d{6}-\d{7}")

# 카드번호 (하이픈/공백 포함 허용, 총 15~16자리)
CARD_RE = re.compile(r"(?:\d[ -]?){15,16}")

# 이메일
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")

# 휴대폰
MOBILE_RE = re.compile(r"01[016789]-?\d{3,4}-?\d{4}")

# 지역번호 전화
CITY_RE = re.compile(r"(?:02|0(?:3[1-3]|4[1-4]|5[1-5]|6[1-4]))-?\d{3,4}-?\d{4}")

# 여권번호 (구/신여권 단순 포맷)
PASSPORT_RE = re.compile(
    r"(?:"
    r"(?:[MSRODG]\d{8})"            # 구여권: M12345678
    r"|"
    r"(?:[MSRODG]\d{3}[A-Z]\d{4})"  # 신여권: M123A4567
    r")"
)

# 운전면허번호
DRIVER_RE = re.compile(r"\d{2}-?\d{2}-?\d{6}-?\d{2}")

# --- RULES: 정규식 + validator 연결 --------------------------------------

RULES = {
    "rrn": {
        "regex": RRN_RE,
        "validator": is_valid_rrn,
    },
    "fgn": {
        "regex": FGN_RE,
        "validator": is_valid_fgn,
    },
    "email": {
        "regex": EMAIL_RE,
        "validator": is_valid_email,
    },
    "phone_mobile": {
        "regex": MOBILE_RE,
        "validator": is_valid_phone_mobile,
    },
    "phone_city": {
        "regex": CITY_RE,
        "validator": is_valid_phone_city,
    },
    "card": {
        "regex": CARD_RE,
        "validator": is_valid_card,
    },
    "passport": {
        "regex": PASSPORT_RE,
        "validator": (lambda v, _opts=None: True),   # 기본 허용
    },
    "driver_license": {
        "regex": DRIVER_RE,
        "validator": is_valid_driver_license,
    },
}

# --- 프리셋 패턴(라우터/클라에서 사용) -----------------------------------

PRESET_PATTERNS = [
    {"name": "rrn",            "regex": RRN_RE.pattern,        "case_sensitive": False, "whole_word": False},
    {"name": "fgn",            "regex": FGN_RE.pattern,        "case_sensitive": False, "whole_word": False},
    {"name": "email",          "regex": EMAIL_RE.pattern,      "case_sensitive": False, "whole_word": False},
    {"name": "phone_mobile",   "regex": MOBILE_RE.pattern,     "case_sensitive": False, "whole_word": False},
    {"name": "phone_city",     "regex": CITY_RE.pattern,       "case_sensitive": False, "whole_word": False},
    {"name": "card",           "regex": CARD_RE.pattern,       "case_sensitive": False, "whole_word": False},
    {"name": "passport",       "regex": PASSPORT_RE.pattern,   "case_sensitive": False, "whole_word": False},
    {"name": "driver_license", "regex": DRIVER_RE.pattern,     "case_sensitive": False, "whole_word": False},
]
