from __future__ import annotations
import io, zipfile
from typing import List, Tuple, Dict, Optional
import logging
import inspect
import os
import olefile
import re
import unicodedata
import xml.etree.ElementTree as ET
from typing import List, Tuple, Optional
try:
    from .common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
    )
except Exception:
    from server.modules.common import (
        cleanup_text,
        compile_rules,
        sub_text_nodes,
        chart_sanitize,
        xlsx_text_from_zip,
    )

from server.core.schemas import XmlMatch, XmlLocation

log = logging.getLogger("xml_redaction")

IMAGE_EXTS = (".png", ".jpg", ".jpeg", ".bmp")


def _escape_html(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _cell_to_html(cell: str) -> str:
    s = (cell or "").replace("\r\n", "\n").replace("\r", "\n")
    return _escape_html(s).replace("\n", "<br/>")


def _rows_to_html_table(rows: List[List[str]]) -> str:
    if not rows:
        return ""
    w = max((len(r) for r in rows), default=0)
    rect = [list(r) + [""] * (w - len(r)) for r in rows]
    out: List[str] = []
    out.append("<table>")
    out.append("<tbody>")
    for r in rect:
        out.append("<tr>")
        for c in r:
            out.append(f"<td>{_cell_to_html(c)}</td>")
        out.append("</tr>")
    out.append("</tbody>")
    out.append("</table>")
    return "\n".join(out)


def _col_letters_to_index(col: str) -> int:
    # A->1, B->2, ..., Z->26, AA->27 ...
    col = (col or "").strip().upper()
    n = 0
    for ch in col:
        if "A" <= ch <= "Z":
            n = n * 26 + (ord(ch) - ord("A") + 1)
    return n


_CELL_REF_RE = re.compile(r"^([A-Za-z]+)(\d+)$")


def _parse_cell_ref(a1: str) -> Optional[Tuple[int, int]]:
    m = _CELL_REF_RE.match((a1 or "").strip())
    if not m:
        return None
    c = _col_letters_to_index(m.group(1))
    try:
        r = int(m.group(2))
    except Exception:
        return None
    if r <= 0 or c <= 0:
        return None
    return r, c


def _read_shared_strings(zipf: zipfile.ZipFile) -> List[str]:
    # sharedStrings.xml은 inline richtext를 포함할 수 있으므로 <si> 단위로 안전하게 파싱
    try:
        xml_bytes = zipf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        try:
            root = ET.fromstring(xml_bytes.decode("utf-8", "ignore").encode("utf-8"))
        except Exception:
            return []

    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}", 1)[0] + "}"

    out: List[str] = []
    for si in root.findall(f".//{ns}si"):
        # si 안의 모든 t를 이어 붙임 (rich text 대응)
        parts: List[str] = []
        for t in si.findall(f".//{ns}t"):
            if t.text:
                parts.append(t.text)
        out.append("".join(parts))
    return out


def _parse_sheet_name_map(zipf: zipfile.ZipFile) -> Dict[str, str]:
    """
    worksheet 파일명(sheet1.xml 등) -> 표시용 시트명 매핑을 만든다.
    실패해도 최소한 sheetN.xml 자체를 이름으로 사용 가능.
    """
    # rId -> Target(worksheets/sheet1.xml) 매핑
    rid_to_target: Dict[str, str] = {}
    try:
        rel_bytes = zipf.read("xl/_rels/workbook.xml.rels")
        rel_root = ET.fromstring(rel_bytes)
        for rel in rel_root.findall(".//{*}Relationship"):
            rid = rel.attrib.get("Id") or rel.attrib.get("id")
            target = rel.attrib.get("Target") or rel.attrib.get("target")
            if not rid or not target:
                continue
            rid_to_target[str(rid)] = str(target).replace("\\", "/")
    except Exception:
        rid_to_target = {}

    sheetfile_to_name: Dict[str, str] = {}
    try:
        wb_bytes = zipf.read("xl/workbook.xml")
        wb_root = ET.fromstring(wb_bytes)
        sheets = wb_root.findall(".//{*}sheet")
        for sh in sheets:
            name = sh.attrib.get("name") or sh.attrib.get("Name") or ""
            rid = sh.attrib.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id") or sh.attrib.get("r:id")
            target = rid_to_target.get(str(rid)) if rid else None
            if not target:
                continue
            # target은 보통 "worksheets/sheet1.xml"
            if target.startswith("/"):
                target = target[1:]
            if not target.startswith("xl/"):
                target = "xl/" + target
            # 파일명만 뽑아서 key로 둠
            sheetfile = target.split("/")[-1]
            if sheetfile:
                sheetfile_to_name[sheetfile] = name or sheetfile
    except Exception:
        return sheetfile_to_name

    return sheetfile_to_name


def extract_markdown_tables_from_xlsx(
    file_bytes: bytes,
    *,
    max_rows: int = 200,
    max_cols: int = 50,
) -> str:
    """
    XLSX를 (Sheet별) HTML <table>로 만든 문자열을 반환.
    UI는 markdown을 그대로 렌더링하므로, XLS 모듈과 동일한 방식(HTML table)을 쓴다.
    """
    try:
        zipf = zipfile.ZipFile(io.BytesIO(file_bytes), "r")
    except Exception:
        return ""

    with zipf:
        sst = _read_shared_strings(zipf)
        name_map = _parse_sheet_name_map(zipf)

        sheet_files = sorted(
            [n for n in zipf.namelist() if n.startswith("xl/worksheets/") and n.endswith(".xml")]
        )

        out_blocks: List[str] = []
        for path in sheet_files:
            fname = path.split("/")[-1]
            sheet_name = name_map.get(fname, fname)

            try:
                xml_bytes = zipf.read(path)
                root = ET.fromstring(xml_bytes)
            except Exception:
                continue

            cells: Dict[int, Dict[int, str]] = {}
            max_r = 0
            max_c = 0

            for c in root.findall(".//{*}c"):
                a1 = c.attrib.get("r") or c.attrib.get("R")
                pos = _parse_cell_ref(a1 or "")
                if not pos:
                    continue
                r, col = pos
                if r > max_rows or col > max_cols:
                    continue

                t = (c.attrib.get("t") or "").strip().lower()

                # 값 추출: <v>, inlineStr(<is><t>)
                v_text = ""
                v_el = c.find("{*}v")
                if v_el is not None and v_el.text is not None:
                    v_text = v_el.text

                if t == "s":
                    # shared string
                    try:
                        idx = int((v_text or "").strip() or "-1")
                    except Exception:
                        idx = -1
                    val = sst[idx] if 0 <= idx < len(sst) else ""
                elif t == "inlineStr":
                    parts: List[str] = []
                    for t_el in c.findall(".//{*}is/{*}t"):
                        if t_el.text:
                            parts.append(t_el.text)
                    val = "".join(parts)
                elif t == "b":
                    val = "TRUE" if (v_text or "").strip() == "1" else "FALSE"
                else:
                    val = (v_text or "").strip()

                val = cleanup_text_keep_tabs(val) if "cleanup_text_keep_tabs" in globals() else cleanup_text(val)
                if not val:
                    continue

                cells.setdefault(r, {})[col] = val
                max_r = max(max_r, r)
                max_c = max(max_c, col)

            if not cells:
                continue

            rows: List[List[str]] = []
            for rr in range(1, max_r + 1):
                row = [cells.get(rr, {}).get(cc, "") for cc in range(1, max_c + 1)]
                if any(x.strip() for x in row):
                    rows.append(row)

            if not rows:
                continue

            out_blocks.append(f"**Sheet: {_escape_html(sheet_name)}**")
            out_blocks.append(_rows_to_html_table(rows))
            out_blocks.append("")

        return "\n\n".join(out_blocks).strip()

try:
    from .ocr_image_redactor import redact_image_bytes  # type: ignore
except Exception:
    try:
        from server.modules.ocr_image_redactor import redact_image_bytes  # type: ignore
    except Exception:

        redact_image_bytes = None  # type: ignore


def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "y", "on")


def _call_redact_image_bytes(fn, data: bytes, comp, *, filename: str, env_prefix: str, logger, debug: bool):
    kwargs = {}
    try:
        sig = inspect.signature(fn)
        params = sig.parameters
        has_varkw = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in params.values())

        def _set_kw(k: str, v):
            if v is None:
                return
            if has_varkw or (k in params):
                kwargs[k] = v

        _set_kw("filename", filename)
        _set_kw("name", filename)
        _set_kw("path", filename)

        _set_kw("env_prefix", env_prefix)
        _set_kw("prefix", env_prefix)
        _set_kw("env", env_prefix)

        _set_kw("logger", logger)
        _set_kw("log", logger)

        if debug:
            _set_kw("debug", True)
            _set_kw("verbose", True)
            _set_kw("trace", True)

        comp_kw_name = None
        for cand in ("comp", "compiled", "compiled_rules", "rules"):
            if has_varkw or (cand in params):
                comp_kw_name = cand
                break

        pos_params = [
            p for p in params.values()
            if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        pos_count = len(pos_params)

    except Exception:
        sig = None
        has_varkw = False
        comp_kw_name = None
        pos_count = 0

    last_err = None

    def _normalize_ret(ret):
        # (bytes, hit)
        if isinstance(ret, tuple) and len(ret) == 2:
            red, hit = ret
            if isinstance(red, bytearray):
                red = bytes(red)
            if isinstance(red, bytes):
                try:
                    return red, int(hit)
                except Exception:
                    return red, -1
            return None

        # bytes only
        if isinstance(ret, bytearray):
            return bytes(ret), -1
        if isinstance(ret, bytes):
            return ret, -1

        return None

    # 1) (data, comp, **kwargs)
    try:
        if sig is None or has_varkw or pos_count >= 2:
            ret = fn(data, comp, **kwargs)
            nr = _normalize_ret(ret)
            if nr is not None:
                return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    # 2) (data, **kwargs)
    try:
        ret = fn(data, **kwargs)
        nr = _normalize_ret(ret)
        if nr is not None:
            return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    # 3) (data)
    try:
        ret = fn(data)
        nr = _normalize_ret(ret)
        if nr is not None:
            return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    # 4) (data, rules/comp=<...>, **kwargs)
    try:
        if comp_kw_name is not None:
            kw2 = dict(kwargs)
            kw2[comp_kw_name] = comp
            ret = fn(data, **kw2)
            nr = _normalize_ret(ret)
            if nr is not None:
                return nr
    except TypeError as e:
        last_err = e
    except Exception as e:
        last_err = e

    raise TypeError(f"redact_image_bytes call failed: {last_err!r}")


# XLSX 텍스트 추출
def xlsx_text(zipf: zipfile.ZipFile) -> str:
    return xlsx_text_from_zip(zipf)


def extract_text(file_bytes: bytes) -> dict:
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as zipf:

        txt = xlsx_text(zipf)
    md = extract_markdown_tables_from_xlsx(file_bytes)
    return {
        "full_text": txt,
        "markdown": md if isinstance(md, str) and md.strip() else txt,
        "pages": [
            {"page": 1, "text": txt},
        ],
    }


def _get_validator(rule_name: str):
    v = None
    try:
        v = RULES.get(rule_name, {}).get("validator")
    except Exception:
        v = None
    return v if callable(v) else None


# ─────────────────────────────────────────────────────────────────────────────
# 스캔: 정규식 규칙으로 텍스트에서 민감정보 후보를 추출
# ─────────────────────────────────────────────────────────────────────────────
def scan(zipf: zipfile.ZipFile) -> Tuple[List[XmlMatch], str, str]:
    text = xlsx_text(zipf)
    comp = compile_rules()
    out: List[XmlMatch] = []

    for ent in comp:
        try:
            if isinstance(ent, (list, tuple)):
                if len(ent) >= 5:
                    rule_name, rx, need_valid, _prio, validator = ent[0], ent[1], bool(ent[2]), ent[3], ent[4]
                elif len(ent) >= 3:
                    rule_name, rx, need_valid = ent[0], ent[1], bool(ent[2])
                    validator = None
                elif len(ent) >= 2:
                    rule_name, rx = ent[0], ent[1]
                    need_valid, validator = True, None
                else:
                    continue
            else:
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
                    location=XmlLocation(kind="xlsx", part="*merged_text*", start=m.start(), end=m.end()),
                )
            )

    return out, "xlsx", text


def redact_item(filename: str, data: bytes, comp, masking_policy=None):
    low = filename.lower()
    log.info("[XLSX][RED] filename=%s low=%s size=%d", filename, low, len(data))

    if low == "xl/sharedstrings.xml" or low.startswith("xl/worksheets/"):
        b, _ = sub_text_nodes(data, comp, masking_policy=masking_policy)
        return b

    if low.startswith("xl/charts/") and low.endswith(".xml"):
        b2, _ = chart_sanitize(data, comp)
        return b2

    if low.startswith("xl/media/") and low.endswith(IMAGE_EXTS):
        log.info("[XLSX][IMG] image=%s size=%d", filename, len(data))

        if not _env_bool("XLSX_OCR_IMAGES", True):
            log.info("[XLSX][IMG][OCR] disabled by env (XLSX_OCR_IMAGES=0) image=%s", filename)
            return data

        if redact_image_bytes is None:
            log.warning("[XLSX][IMG][OCR] ocr_image_redactor not available -> skip (%s)", filename)
            return data

        debug = _env_bool("XLSX_OCR_DEBUG", False)

        log.info("[XLSX][IMG][OCR] start image=%s size=%d debug=%s", filename, len(data), debug)
        try:
            red, hit = _call_redact_image_bytes(
                redact_image_bytes,
                data,
                comp,
                filename=filename,
                env_prefix="XLSX",
                logger=log,
                debug=debug,
            )

            changed = (red != data)
            log.info(
                "[XLSX][IMG][OCR] end image=%s in=%d out=%d changed=%s hit=%s",
                filename,
                len(data),
                len(red) if isinstance(red, (bytes, bytearray)) else -1,
                changed,
                hit,
            )

            if hit == -1:
                return red
            if hit > 0:
                return red
            return data

        except Exception as e:
            log.exception("[XLSX][IMG][OCR] failed image=%s err=%r", filename, e)
            return data

    return data


def extract_images(file_bytes: bytes) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(file_bytes), "r") as z:
        for name in z.namelist():
            low = name.lower()
            if low.startswith("xl/media/") and low.endswith(IMAGE_EXTS):
                try:
                    data = z.read(name)
                    out.append((name, data))
                    log.info("[XLSX][IMG] image=%s size=%d", name, len(data))
                except KeyError:
                    pass
    return out