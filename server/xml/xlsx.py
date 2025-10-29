# server/xml/xlsx.py
from __future__ import annotations
import zipfile
from typing import List, Tuple
from .common import (
    cleanup_text, compile_rules, sub_text_nodes, chart_sanitize, xlsx_text_from_zip,
    chart_rels_sanitize,   # ← 이걸 임포트
)
from ..schemas import XmlMatch, XmlLocation

def xlsx_text(zipf: zipfile.ZipFile) -> str:
    return xlsx_text_from_zip(zipf)

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, _need_valid, _prio in comp:
        for m in rx.finditer(text):
            out.append(XmlMatch(
                rule=rule_name, value=m.group(0), valid=True,
                context=text[max(0, m.start()-20):min(len(text), m.end()+20)],
                location=XmlLocation(kind="xlsx", part="*merged_text*",
                                     start=m.start(), end=m.end()),
            ))
    return out, "xlsx", text

def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 1) 셀/공유문자열 텍스트 마스킹
    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        return sub_text_nodes(data, comp)[0]

    # 2) 차트 본문: 라벨만 마스킹(숫자 캐시는 절대 손대지 않음)
    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return b2

    # 3) 🔧 차트의 관계(.rels)도 정리해서 “복구” 팝업 방지
    if low.startswith("xl/charts/_rels/") and low.endswith(".rels"):
        b3, _ = chart_rels_sanitize(data)
        return b3

    return data
