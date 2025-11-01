# -*- coding: utf-8 -*-
from __future__ import annotations
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

# 주민등록번호: YYMMDD-XXXXXXX, 앞 6자 날짜·뒤 1자리 성별코드
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

# 카드번호 (4-4-4-4, 4-6-5, 또는 연속 15~16자리)
CARD_RE = re.compile(
    r"(?<!\d)("
    r"\d{4}([ -])\d{4}\2\d{4}\2\d{4}"      # 4-4-4-4
    r"|\d{4}([ -])\d{6}\3\d{5}"            # 4-6-5 (AMEX)
    r"|\d{15,16}"                          # 연속 15~16
    r")(?!\d)"
)

# 이메일
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")

# 휴대폰 / 지역번호 (카드조각 충돌 방지 가드 포함)
MOBILE_RE = re.compile(
    r"(?<!\d{4}-)"
    r"(?:01[016789]-?\d{3,4}-?\d{4})"
    r"(?!-\d{4})"
)

CITY_RE = re.compile(
    r"(?<!\d{4}-)"
    r"(?:02|0(?:3[1-3]|4[1-4]|5[1-5]|6[1-4]))-?\d{3,4}-?\d{4}"
    r"(?!-\d{4})"
)

# 대표/서비스 번호(4-4): 15xx/16xx/18xx/050x/070x
PHONE_SERVICE_RE = re.compile(
    r"(?<!\d{4}-)"
    r"(?:(?:050\d|070\d|1[568]\d{2}))-\d{4}"
    r"(?!-\d{4})"
)

# 여권(구/신)
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
        "ensure_valid": True,   # ✅ validator 통과분만 ‘검출/마스킹’
    }
    for name in _PRESET_ORDER
]

# ================== 호환용: apply_redaction_rules ==================
# .doc 처리 등에서 이 함수에 의존하므로 복구 (검증 통과한 것만 치환)
def _mask_email(piece: str) -> str:
    # 이메일: @, -만 보존 / 영숫자와 . _ 는 가림
    out = []
    for ch in piece:
        if ch in ("@", "-"):
            out.append(ch)
        elif ch.isalnum() or ch in "._":
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)

def _mask_keep_rules(piece: str) -> str:
    # 공통: - 보존 / 영숫자와 . _ 는 가림 / 그 외 기호·공백 보존
    out = []
    for ch in piece:
        if ch == "-":
            out.append(ch)
        elif ch.isalnum() or ch in "._":
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)

def _mask_for_rule(rule_name: str, piece: str) -> str:
    return _mask_email(piece) if rule_name.lower() == "email" else _mask_keep_rules(piece)

def apply_redaction_rules(text: str, rules: dict | None = None) -> str:
    """
    검증(validator) 통과한 매치만 마스킹.
    마스킹 규칙은 모듈 공통 정책(- 보존 / .,_ 가림 / 이메일은 @,- 보존)을 사용.
    """
    if not text:
        return text
    rules = rules or RULES

    # 우선순위대로 순차 적용 (겹침 방지)
    for name in _PRESET_ORDER:
        rx = rules[name]["regex"]
        validator = rules[name].get("validator")

        def repl(m: re.Match) -> str:
            val = m.group(0)
            ok = True
            if callable(validator):
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False
            return _mask_for_rule(name, val) if ok else val

        text = rx.sub(repl, text)

    return text
