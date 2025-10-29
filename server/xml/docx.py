# -*- coding: utf-8 -*-
from __future__ import annotations
import io, re, zipfile
from typing import List, Tuple
from .common import (
    cleanup_text, compile_rules, sub_text_nodes, chart_sanitize,
    xlsx_text_from_zip, redact_embedded_xlsx_bytes, chart_rels_sanitize,
    sanitize_docx_content_types
)
from ..schemas import XmlMatch, XmlLocation

def _collect_chart_texts(zipf: zipfile.ZipFile) -> str:
    parts = []
    # 1) 차트 XML 내부 라벨/캐시 텍스트
    for name in sorted(n for n in zipf.namelist() if n.startswith("word/charts/") and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8", "ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I | re.DOTALL):
            v = (m.group(1) or m.group(2) or "")
            if v:
                parts.append(v)
    # 2) 임베디드 XLSX 내부의 문자열/시트/차트 텍스트
    for name in sorted(n for n in zipf.namelist() if n.startswith("word/embeddings/") and n.lower().endswith(".xlsx")):
        try:
            xlsx_bytes = zipf.read(name)
            with zipfile.ZipFile(io.BytesIO(xlsx_bytes), "r") as xzf:
                parts.append(xlsx_text_from_zip(xzf))
        except KeyError:
            pass
        except zipfile.BadZipFile:
            continue
    return cleanup_text("\n".join(p for p in parts if p))

def docx_text(zipf: zipfile.ZipFile) -> str:
    # 본문
    try:
        xml = zipf.read("word/document.xml").decode("utf-8","ignore")
    except KeyError:
        xml = ""
    text_main = "".join(m.group(1) for m in re.finditer(r"<w:t[^>]*>(.*?)</w:t>", xml, re.DOTALL))
    text_main = cleanup_text(text_main)
    # 차트 + 임베디드 XLSX
    text_charts = _collect_chart_texts(zipf)
    return cleanup_text("\n".join(x for x in [text_main, text_charts] if x))

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = docx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []
    for rule_name, rx, _need_valid, _prio in comp:
        for m in rx.finditer(text):
            val = m.group(0)
            out.append(XmlMatch(
                rule=rule_name, value=val, valid=True,
                context=text[max(0,m.start()-20):min(len(text),m.end()+20)],
                location=XmlLocation(kind="docx", part="*merged_text*", start=m.start(), end=m.end()),
            ))
    return out, "docx", text

def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 0) DOCX 루트 컨텐츠 타입 정리 (externalLinks 오버라이드 제거)
    if low == "[content_types].xml":
        return sanitize_docx_content_types(data)

    # 1) 본문 XML
    if low == "word/document.xml":
        return sub_text_nodes(data, comp)[0]

    # 2) 차트 XML: 외부데이터 제거 + 라벨/캐시 마스킹 + 텍스트노드 마스킹
    if low.startswith("word/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    # 3) 차트 RELS: 외부데이터/임베딩/외부링크 링크 제거(복구 팝업 방지)
    if low.startswith("word/charts/_rels/") and low.endswith(".rels"):
        b2, _ = chart_rels_sanitize(data)
        return b2

    # 4) 임베디드 XLSX: 내부까지 무해화(외부링크 제거 포함)
    if low.startswith("word/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    # 그 외는 그대로
    return data
