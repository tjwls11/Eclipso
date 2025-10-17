import re
from datetime import datetime

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

# ================== 정규식 ==================

# 주민등록번호
RRN_RE = re.compile(
    r"(?:\d{2}(?:0[1-9]|1[0-2])"
    r"(?:0[1-9]|[12]\d|3[01]))"
    r"-?[1234]\d{6}"
)

# 외국인등록번호
FGN_RE = re.compile(
    r"(?:\d{2}(?:0[1-9]|1[0-2])"
    r"(?:0[1-9]|[12]\d|3[01]))"
    r"-?[5678]\d{6}"
)

# ---- 카드번호 (4-4-4-4, 4-6-5, 숫자 15~16 백업) ----
CARD_RE = re.compile(
    r"(?<!\d)("
    r"\d{4}([ -])\d{4}\2\d{4}\2\d{4}"      # 4-4-4-4
    r"|\d{4}([ -])\d{6}\3\d{5}"            # 4-6-5 (AMEX)
    r"|\d{15,16}"                          # 백업 (스페이스/대시 없는 15~16)
    r")(?!\d)"
)

# 이메일
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")

# ---- 휴대폰 / 지역번호 : 카드 중간조각과 충돌 방지 가드 추가 ----
#  - 앞이 'dddd-' 인지, 뒤가 '-dddd' 인지 확인해서 카드 일부면 매치 금지
MOBILE_RE = re.compile(
    r"(?<!\d{4}-)"          # 바로 앞이 'dddd-' 이면 제외
    r"(?:01[016789]-?\d{3,4}-?\d{4})"
    r"(?!-\d{4})"           # 바로 뒤가 '-dddd' 이면 제외
)

CITY_RE = re.compile(
    r"(?<!\d{4}-)"          # 앞 가드
    r"(?:02|0(?:3[1-3]|4[1-4]|5[1-5]|6[1-4]))-?\d{3,4}-?\d{4}"
    r"(?!-\d{4})"           # 뒤 가드
)

# (선택) 대표/서비스 번호(4-4): 15xx/16xx/18xx/050x/070x 등
#  - 카드 중간조각 방지: 뒤에 '-dddd' 이어지면 제외
PHONE_SERVICE_RE = re.compile(
    r"(?<!\d{4}-)"
    r"(?:(?:050\d|070\d|1[568]\d{2}))-\d{4}"
    r"(?!-\d{4})"
)

# 여권번호 (구/신)
PASSPORT_RE = re.compile(r"(?:(?:[MSRODG]\d{8})|(?:[MSRODG]\d{3}[A-Z]\d{4}))")

# 운전면허
DRIVER_RE = re.compile(r"\d{2}-?\d{2}-?\d{6}-?\d{2}")

# ================== RULES / PRESET ==================

RULES = {
    "rrn":              {"regex": RRN_RE,       "validator": is_valid_rrn},
    "fgn":              {"regex": FGN_RE,       "validator": is_valid_fgn},
    "email":            {"regex": EMAIL_RE,     "validator": is_valid_email},
    "phone_mobile":     {"regex": MOBILE_RE,    "validator": is_valid_phone_mobile},
    "phone_city":       {"regex": CITY_RE,      "validator": is_valid_phone_city},
    "phone_service":    {"regex": PHONE_SERVICE_RE, "validator": (lambda v, _=None: True)},
    "card":             {"regex": CARD_RE,      "validator": is_valid_card},
    "passport":         {"regex": PASSPORT_RE,  "validator": (lambda v, _=None: True)},
    "driver_license":   {"regex": DRIVER_RE,    "validator": is_valid_driver_license},
}

# 우선순위: card > email > rrn/fgn > phones > driver > passport
_PRESET_ORDER = [
    "card",
    "email",
    "rrn",
    "fgn",
    "phone_mobile",
    "phone_city",
    "phone_service",
    "driver_license",
    "passport",
]

PRESET_PATTERNS = [
    {
        "name": name,
        "regex": RULES[name]["regex"].pattern,
        "case_sensitive": False,
        "whole_word": False,
        "ensure_valid": True,
    }
    for name in _PRESET_ORDER
]
