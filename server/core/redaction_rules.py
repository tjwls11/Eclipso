import re
from server.core.validators import (
    is_valid_rrn,
    is_valid_fgn,
    is_valid_phone_mobile,
    is_valid_phone_city,
    is_valid_email,
    is_valid_card,
    is_valid_driver_license,
)


def apply_redaction_rules(text: str, rules: dict = None, mask: str = "***") -> str:
    if rules is None:
        rules = RULES


    new_text = text
    for name, info in rules.items():
        pattern = info["regex"]
        if isinstance(pattern, re.Pattern):
            new_text = pattern.sub(mask, new_text)
        else:
            new_text = re.sub(pattern, mask, new_text)
    return new_text


# 주민등록번호 (하이픈 있거나 없는 경우 모두 탐지)
RRN_RE = re.compile(
    r"(?<!\d)"      # 앞에 숫자 없음
    r"\d{6}"        # 생년월일 6자리
    r"[-\s]?"       # 하이픈 또는 공백 (선택)
    r"[0-490]\d{6}" # 7번째 자리: 1,2,3,4,9,0 / 나머지 6자리 숫자
    r"(?!\d)"       # 뒤에 숫자 없음
)
# 외국인등록번호 (하이픈 있거나 없는 경우 모두 탐지)
FGN_RE = re.compile(
    r"(?<!\d)"      # 앞에 숫자 없음
    r"\d{6}"        # 생년월일 6자리
    r"[-\s]?"       # 하이픈 또는 공백 (선택)
    r"[5-8]\d{6}"   # 7번째 자리: 5,6,7,8 (외국인) / 나머지 6자리
    r"(?!\d)"       # 뒤에 숫자 없음
)


# 카드번호
CARD_RE = re.compile(r"(?:\d[ -]?){15,16}")


# 이메일
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")


# 휴대폰
MOBILE_RE = re.compile(r"01[016789]-?\d{3,4}-?\d{4}")


# 지역번호 전화
CITY_RE = re.compile(r"(?:02|0(?:3[1-3]|4[1-4]|5[1-5]|6[1-4]))-?\d{3,4}-?\d{4}")


# 여권번호
PASSPORT_RE = re.compile(
    r"(?:"
    r"(?:[MSRODG]\d{8})"          # 구여권: M12345678
    r"|"
    r"(?:[MSRODG]\d{3}[A-Z]\d{4})" # 신여권: M123A4567
    r")"
)


# 운전면허번호
DRIVER_RE = re.compile(
    r"(?<!\d)"
    r"(?:11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26)"
    r"-?\d{2}-?\d{6}-?\d{2}"
    r"(?!\d)"
)


# RULES 정의
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
        "validator": lambda v, _opts=None: True,  
    },
    "driver_license": {
        "regex": DRIVER_RE,
        "validator": is_valid_driver_license,
    },
}


# --- 사전 정의된 패턴 ---
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

