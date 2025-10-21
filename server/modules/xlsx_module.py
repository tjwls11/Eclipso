# server/xml/xlsx.py
from __future__ import annotations
import zipfile
from typing import List, Tuple
from .common import cleanup_text, compile_rules, sub_text_nodes, chart_sanitize, xlsx_text_from_zip
from ..schemas import XmlMatch, XmlLocation

def xlsx_text(zipf: zipfile.ZipFile) -> str:
    return xlsx_text_from_zip(zipf)

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, need_valid, _prio in comp:
        for m in rx.finditer(text):
            out.append(XmlMatch(
                rule=rule_name, value=m.group(0), valid=True,
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="xlsx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "xlsx", text

def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()
    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        return sub_text_nodes(data, comp)[0]
    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]
    return data
