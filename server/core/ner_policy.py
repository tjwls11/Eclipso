from __future__ import annotations

import os
from typing import Dict, Set, List

# 라벨 허용/차단
_al = os.getenv("NER_ALLOWED_LABELS", "PER,ORG,LOC,ADDR,DT")
ALLOWED_LABELS: Set[str] = {v.strip() for v in _al.split(",") if v.strip()}

QT_POLICY = os.getenv("NER_NUMERIC_POLICY", "off")
DT_POLICY = os.getenv("NER_DT_POLICY", "sensitive_only")  

# 라벨별 임계치
def _parse_thresholds(s: str) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for pair in s.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        k, v = pair.split(":", 1)
        try:
            out[k.strip()] = float(v.strip())
        except:
            pass
    return out

LABEL_THRESHOLDS: Dict[str, float] = _parse_thresholds(
    os.getenv("NER_THRESHOLDS", "PER:0.50,ORG:0.55,LOC:0.55,ADDR:0.55,DT:0.60")
)

# DT 민감 키워드
DT_SENSITIVE_TRIGGERS: List[str] = [
    v for v in os.getenv(
        "NER_DT_SENSITIVE_TRIGGERS",
        "생년월일,출생,DOB,발급,만료,입사,퇴사,가입,진료,검사,접수"
    ).split(",")
    if v.strip()
]

# 청크/성능
CHUNK_SIZE = int(os.getenv("NER_CHUNK_SIZE", "1500"))
CHUNK_OVERLAP = int(os.getenv("NER_CHUNK_OVERLAP", "50"))
