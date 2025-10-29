# -*- coding: utf-8 -*-
"""
레닥션 규칙 및 프리셋 패턴
"""
import re
from .validators import (
    is_valid_rrn,
    is_valid_fgn,
    is_valid_phone_mobile,
    is_valid_phone_city,
    is_valid_phone_service,  # ★ 추가
    is_valid_email,
    is_valid_card,
    is_valid_driver_license,
)

# --- 정규식 정의 ---------------------------------------------------------
RRN_RE = re.compile(r"\d{6}-\d{7}")
FGN_RE = re.compile(r"\d{6}-\d{7}")
CARD_RE = re.compile(r"(?:\d[ -]?){15,16}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")
MOBILE_RE = re.compile(r"01[016789]-?\d{3,4}-?\d{4}")
CITY_RE = re.compile(r"(?:02|0(?:3[1-3]|4[1-4]|5[1-5]|6[1-4]))-?\d{3,4}-?\d{4}")

# 대표번호/특수번호(070/050/15xx/16xx/18xx)
SERVICE_RE = re.compile(
    r"(?:070-?\d{4}-?\d{4})|(?:050-?\d{3,4}-?\d{4})|(?:1[568]\d{2}-?\d{4})",
    re.IGNORECASE
)

PASSPORT_RE = re.compile(r"(?:[MSRODG]\d{8}|[MSRODG]\d{3}[A-Z]\d{4})")
DRIVER_RE = re.compile(r"\d{2}-?\d{2}-?\d{6}-?\d{2}")

# --- RULES ---------------------------------------------------------------
RULES = {
    "rrn": {"regex": RRN_RE, "validator": is_valid_rrn},
    "fgn": {"regex": FGN_RE, "validator": is_valid_fgn},
    "email": {"regex": EMAIL_RE, "validator": is_valid_email},
    "phone_mobile": {"regex": MOBILE_RE, "validator": is_valid_phone_mobile},
    "phone_city": {"regex": CITY_RE, "validator": is_valid_phone_city},
    "phone_service": {"regex": SERVICE_RE, "validator": is_valid_phone_service},  # ★ 추가
    "card": {"regex": CARD_RE, "validator": is_valid_card},
    "passport": {"regex": PASSPORT_RE, "validator": (lambda v, _opts=None: True)},
    "driver_license": {"regex": DRIVER_RE, "validator": is_valid_driver_license},
}

# --- PRESET_PATTERNS -----------------------------------------------------
PRESET_PATTERNS = [
    {"name": "rrn",            "regex": RRN_RE.pattern,        "case_sensitive": False, "whole_word": False},
    {"name": "fgn",            "regex": FGN_RE.pattern,        "case_sensitive": False, "whole_word": False},
    {"name": "email",          "regex": EMAIL_RE.pattern,      "case_sensitive": False, "whole_word": False},
    {"name": "phone_mobile",   "regex": MOBILE_RE.pattern,     "case_sensitive": False, "whole_word": False},
    {"name": "phone_city",     "regex": CITY_RE.pattern,       "case_sensitive": False, "whole_word": False},
    {"name": "phone_service",  "regex": SERVICE_RE.pattern,    "case_sensitive": False, "whole_word": False},  # ★ 추가
    {"name": "card",           "regex": CARD_RE.pattern,       "case_sensitive": False, "whole_word": False},
    {"name": "passport",       "regex": PASSPORT_RE.pattern,   "case_sensitive": False, "whole_word": False},
    {"name": "driver_license", "regex": DRIVER_RE.pattern,     "case_sensitive": False, "whole_word": False},
]
