# -*- coding: utf-8 -*-
from __future__ import annotations
import io, re, zipfile
from typing import List, Tuple
from .common import (
    cleanup_text, compile_rules, sub_text_nodes, chart_sanitize,
    xlsx_text_from_zip, redact_embedded_xlsx_bytes, chart_rels_sanitize,
    sanitize_docx_content_types,
)
from server.core.schemas import XmlMatch, XmlLocation

def _collect_chart_texts(zipf: zipfile.ZipFile) -> str:
    parts = []
    for name in sorted(n for n in zipf.namelist() if n.startswith("word/charts/") and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8","ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I|re.DOTALL):
            v = (m.group(1) or m.group(2) or "")
            if v: parts.append(v)
    for name in sorted(n for n in zipf.namelist() if n.startswith("word/embeddings/") and n.lower().endswith(".xlsx")):
        try:
            with zipfile.ZipFile(io.BytesIO(zipf.read(name)), "r") as xzf:
                parts.append(xlsx_text_from_zip(xzf))
        except zipfile.BadZipFile:
            continue
        except KeyError:
            pass
    return cleanup_text("\n".join(p for p in parts if p))

def docx_text(zipf: zipfile.ZipFile) -> str:
    # 본문(document.xml)
    try:
        xml = zipf.read("word/document.xml").decode("utf-8", "ignore")
    except KeyError:
        xml = ""

    text_main = "".join(
        m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL)
    )
    text_main = cleanup_text(text_main)
    text_charts = _collect_chart_texts(zipf)
    return cleanup_text("\n".join(x for x in [text_main, text_charts] if x))

def extract_text(file_bytes: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        return docx_text(zipf)

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = docx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, _need_valid, _prio in comp:
        for m in rx.finditer(text):
            out.append(XmlMatch(
                rule=rule_name, value=m.group(0), valid=True,
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="docx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "docx", text


# ─────────────────────────────────────────────────────────────────────────────
# 파일 단위 레닥션: 각 파트별로 처리
# ─────────────────────────────────────────────────────────────────────────────
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    if low == "[content_types].xml":
        return sanitize_docx_content_types(data)

    if low == "word/document.xml":
        return sub_text_nodes(data, comp)[0]

    if low.startswith("word/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    if low.startswith("word/charts/_rels/") and low.endswith(".rels"):
        b2, _ = chart_rels_sanitize(data)
        return b2

    if low.startswith("word/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    return data
