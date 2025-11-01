# -*- coding: utf-8 -*-
from __future__ import annotations
import io, re, zipfile
from typing import List, Tuple
from .common import cleanup_text, compile_rules, sub_text_nodes, chart_sanitize
from server.core.schemas import XmlMatch, XmlLocation

def pptx_text(zipf: zipfile.ZipFile) -> str:
    all_txt = []
    for name in sorted(n for n in zipf.namelist() if n.startswith("ppt/slides/") and n.endswith(".xml")):
        xml = zipf.read(name).decode("utf-8","ignore")
        all_txt += [tm.group(1) for tm in re.finditer(r"<a:t[^>]*>(.*?)</a:t>", xml, re.DOTALL)]
    for name in sorted(n for n in zipf.namelist() if n.startswith("ppt/charts/") and n.endswith(".xml")):
        s = zipf.read(name).decode("utf-8","ignore")
        for m in re.finditer(r"<a:t[^>]*>(.*?)</a:t>|<c:v[^>]*>(.*?)</c:v>", s, re.I|re.DOTALL):
            v = (m.group(1) or m.group(2) or "")
            if v: all_txt.append(v)
    return cleanup_text("\n".join(all_txt))

def extract_text(file_bytes: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:
        return pptx_text(zipf)

def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = pptx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            # tuple/list 계열
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                else:
                    continue
                need_valid = bool(ent[2]) if len(ent) >= 3 else True
                validator = ent[4] if len(ent) >= 5 else None
            else:
                # 네임드 객체(SimpleNamespace 등)
                rule_name = getattr(ent, "name", getattr(ent, "rule", "unknown"))
                rx = getattr(ent, "rx", getattr(ent, "regex", None))
                need_valid = bool(getattr(ent, "need_valid", True))
                validator = getattr(ent, "validator", None)

            if rx is None:
                continue
        except Exception:
            continue

        for m in rx.finditer(text):
            val = m.group(0)
            ok = True
            if need_valid and callable(validator):
                try:
                    try:
                        ok = bool(validator(val))
                    except TypeError:
                        ok = bool(validator(val, None))
                except Exception:
                    ok = False

            out.append(
                XmlMatch(
                    rule=rule_name,
                    value=val,
                    valid=ok,
                    context=text[max(0, m.start() - 20): min(len(text), m.end() + 20)],
                    location=XmlLocation(
                        kind="pptx",
                        part="*merged_text*",
                        start=m.start(),
                        end=m.end(),
                    ),
                )
            )

    return out, "pptx", text


# ─────────────────────────────────────────────────────────────────────────────
# 파일 단위 레닥션
# ─────────────────────────────────────────────────────────────────────────────
def redact_item(filename: str, data: bytes, comp):
    low = filename.lower()

    # 1) 슬라이드 본문 XML: 텍스트 노드만 마스킹
    if low.startswith("ppt/slides/") and low.endswith(".xml"):
        return sub_text_nodes(data, comp)[0]

    # 2) 차트 XML: 라벨/값 + 텍스트 노드 마스킹
    if low.startswith("ppt/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return sub_text_nodes(b2, comp)[0]

    # 3) 차트 RELS
    if low.startswith("ppt/charts/_rels/") and low.endswith(".rels"):
        b3, _ = chart_rels_sanitize(data)
        return b3

    # 4) 임베디드 XLSX
    if low.startswith("ppt/embeddings/") and low.endswith(".xlsx"):
        return redact_embedded_xlsx_bytes(data)

    # 5) 기타 파트는 그대로 유지
    return data
