from __future__ import annotations

import io
import re
import base64
import unicodedata
from typing import List, Optional, Set, Dict, Any, Tuple, Iterable

import fitz 
import pymupdf4llm
import logging

from server.core.schemas import Box, PatternItem
from server.core.redaction_rules import PRESET_PATTERNS
from server.modules.ner_module import run_ner
from server.core.regex_utils import match_text

from server.modules.ocr_module import easyocr_blocks
from server.modules.ocr_qwen_post import classify_blocks_with_qwen
from PIL import Image


log_prefix = "[PDF]"
logger = logging.getLogger(__name__)


def _char_weight(ch: str) -> float:
    # bbox 슬라이싱용: 대략적인 문자 폭 가중치(한글/영문/숫자/기호)
    o = ord(ch) if ch else 0
    if not ch or ch.isspace():
        return 0.18
    # Hangul
    if (0xAC00 <= o <= 0xD7A3) or (0x1100 <= o <= 0x11FF) or (0x3130 <= o <= 0x318F):
        return 1.05
    # CJK
    if 0x4E00 <= o <= 0x9FFF:
        return 1.00
    # digits
    if "0" <= ch <= "9":
        return 0.62
    # latin
    if ("A" <= ch <= "Z") or ("a" <= ch <= "z"):
        return 0.68
    # punctuation-ish
    if ch in ":：-‐–—._/\\|()[]{},@":
        return 0.28
    return 0.55


def _weighted_prefix(text: str) -> List[float]:
    pref = [0.0]
    s = 0.0
    for ch in (text or ""):
        s += _char_weight(ch)
        pref.append(s)
    return pref


def _slice_bbox_by_char_span(block_text: str, start: int, end: int, bbox: List[float]) -> List[float]:
    try:
        x0, y0, x1, y1 = map(float, bbox)
    except Exception:
        return bbox

    t = str(block_text or "")
    n = len(t)
    if n <= 0:
        return bbox

    s0 = max(0, min(n, int(start)))
    s1 = max(0, min(n, int(end)))
    if s1 <= s0:
        return bbox

    w = max(1.0, x1 - x0)
    pref = _weighted_prefix(t)
    total = max(1e-6, pref[-1])

    r0 = pref[s0] / total
    r1 = pref[s1] / total

    nx0 = x0 + w * r0
    nx1 = x0 + w * r1
    if nx1 - nx0 < 1.0:
        return bbox
    return [nx0, y0, nx1, y1]


def _tighten_overwide_bbox(text: str, bbox: List[float], *, char_px_factor: float = 0.55, slack: float = 0.30) -> List[float]:
    try:
        x0, y0, x1, y1 = map(float, bbox)
    except Exception:
        return bbox

    w = max(1.0, x1 - x0)
    h = max(1.0, y1 - y0)
    t = str(text or "").strip()
    if not t:
        return bbox

    tw = 0.0
    for ch in t:
        tw += _char_weight(ch)

    expected_w = max(8.0, h * float(char_px_factor) * tw)
    limit_w = expected_w * (1.0 + max(0.0, float(slack)))
    if w <= limit_w:
        return bbox

    cx = (x0 + x1) * 0.5
    half = limit_w * 0.5
    return [cx - half, y0, cx + half, y1]


def _digits(s: str) -> str:
    return re.sub(r"\D+", "", s or "")


def _mask_value_with_policy(rule: str, value: str, masking_policy: Optional[dict]) -> Optional[str]:

    pol = masking_policy or {}
    r = str(rule or "").lower()
    s = str(value or "")
    if not s:
        return None

    # email은 정책 적용 안 함(기존처럼 전체 마스킹 경로)
    if r == "email":
        return None

    # 주민/외국인: 앞 6 digit만 유지
    if r == "rrn" and str(pol.get("rrn") or "") == "keep_birth6":
        out = []
        dcnt = 0
        for ch in s:
            if ch.isdigit():
                dcnt += 1
                out.append(ch if dcnt <= 6 else "*")
            else:
                out.append(ch)
        return "".join(out)

    if r == "fgn" and str(pol.get("fgn") or "") == "keep_birth6":
        out = []
        dcnt = 0
        for ch in s:
            if ch.isdigit():
                dcnt += 1
                out.append(ch if dcnt <= 6 else "*")
            else:
                out.append(ch)
        return "".join(out)

    # 전화: 첫 digit 그룹만 유지(이후 digit만 마스킹)
    if r in ("phone_mobile", "phone_city") and str(pol.get("phone") or "") == "keep_first_group":
        m = re.search(r"\d+", s)
        if not m:
            return None
        cut = m.end()
        out = []
        for i, ch in enumerate(s):
            if i >= cut and ch.isdigit():
                out.append("*")
            else:
                out.append(ch)
        return "".join(out)

    # 카드: 앞4/뒤4 유지
    if r == "card" and str(pol.get("card") or "") == "keep_first4_last4":
        digit_pos = [i for i, ch in enumerate(s) if ch.isdigit()]
        if len(digit_pos) <= 8:
            return None
        keep = set(digit_pos[:4] + digit_pos[-4:])
        out = []
        for i, ch in enumerate(s):
            if ch.isdigit() and i not in keep:
                out.append("*")
            else:
                out.append(ch)
        return "".join(out)

    # 이름(PS): 첫 한글 글자만 유지
    if r == "ps" and str(pol.get("ps") or "") == "keep_first_char":
        hangul_re = re.compile(r"^[\uAC00-\uD7A3]+$")
        hangul_pos = [i for i, ch in enumerate(s) if hangul_re.fullmatch(ch or "")]
        if len(hangul_pos) <= 1:
            return None
        keep_i = hangul_pos[0]
        out = []
        for i, ch in enumerate(s):
            if hangul_re.fullmatch(ch or "") and i != keep_i:
                out.append("*")
            else:
                out.append(ch)
        return "".join(out)

    return None


def _masked_runs_from_replacement(original: str, replacement: Optional[str]) -> List[Tuple[int, int]]:
    s = str(original or "")
    if not s:
        return []

    if replacement is None or not isinstance(replacement, str) or len(replacement) != len(s):
        return [(0, len(s))]

    idxs = [i for i, ch in enumerate(replacement) if ch == "*" and (i < len(s))]
    if not idxs:
        return []

    idxs.sort()
    runs: List[Tuple[int, int]] = []
    cur0 = idxs[0]
    cur1 = idxs[0] + 1
    for i in idxs[1:]:
        if i == cur1:
            cur1 += 1
        else:
            runs.append((cur0, cur1))
            cur0 = i
            cur1 = i + 1
    runs.append((cur0, cur1))
    return runs


def extract_text(file_bytes: bytes) -> dict:
    doc = fitz.open(stream=file_bytes, filetype="pdf")
    try:
        pages = []
        all_chunks: List[str] = []

        for idx, page in enumerate(doc):
            raw = page.get_text("text") or ""
            cleaned = raw.replace("\r", "")
            pages.append({"page": idx + 1, "text": cleaned})
            if cleaned:
                all_chunks.append(cleaned)

        full_text = "\n\n".join(all_chunks)
        return {"full_text": full_text, "pages": pages}
    finally:
        doc.close()


def _blocks_to_reading_text(blocks: List[Dict[str, Any]], *, row_tol: float = 18.0) -> str:

    if not blocks:
        return ""

    # _group_rows_by_y는 아래에 이미 존재(페이지 OCR 박스용)하므로 재사용
    rows = _group_rows_by_y(blocks, row_tol=row_tol)
    lines: List[str] = []

    for row in rows:
        parts: List[str] = []
        for b in row:
            t = str(b.get("text") or "").strip()
            if not t:
                continue
            parts.append(t)
        line = " ".join(parts).strip()
        if line:
            lines.append(line)

    return "\n".join(lines).strip()


def extract_text_ocr(
    pdf_bytes: bytes,
    *,
    dpi: int = 220,
    min_conf: float = 0.25,
    max_pages: int = 50,
    row_tol: float = 18.0,
    gpu: bool = False,
) -> dict:

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        pages: List[dict] = []
        full_parts: List[str] = []

        limit = min(int(max_pages), int(doc.page_count))
        for idx in range(limit):
            page = doc.load_page(idx)
            img = _page_to_pil(page, dpi=int(dpi))
            blocks = easyocr_blocks(img, min_conf=float(min_conf), gpu=bool(gpu)) or []
            text = _blocks_to_reading_text(blocks, row_tol=float(row_tol))
            pages.append({"page": idx + 1, "text": text})
            if text:
                full_parts.append(text)

        return {"full_text": "\n\n".join(full_parts).strip(), "pages": pages, "ocr": True}
    finally:
        doc.close()

def extract_table_layout(pdf_bytes: bytes) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    tables: List[dict] = []

    try:
        for page_idx, page in enumerate(doc):
            finder = page.find_tables()
            if not finder or not finder.tables:
                continue

            for t in finder.tables:
                rect = fitz.Rect(t.bbox)
                tables.append(
                    {
                        "page": page_idx + 1,
                        "bbox": [rect.x0, rect.y0, rect.x1, rect.y1],
                        "row_count": t.row_count,
                        "col_count": t.col_count,
                    }
                )
    finally:
        doc.close()

    return {"tables": tables}


def extract_markdown(pdf_bytes: bytes, by_page: bool = True) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        if by_page:
            chunks = pymupdf4llm.to_markdown(doc=doc, page_chunks=True)
            pages: List[dict] = []

            for idx, ch in enumerate(chunks, start=1):
                meta = ch.get("metadata", {}) or {}
                page_no = meta.get("page_number") or idx

                md = (ch.get("text") or "").replace("<br>", "")
                raw_tables = ch.get("tables", []) or []
                tables: List[dict] = []

                for t in raw_tables:
                    bbox = t.get("bbox")
                    rows = t.get("rows") or t.get("row_count")
                    cols = t.get("columns") or t.get("col_count")
                    if not bbox or rows is None or cols is None:
                        continue
                    tables.append(
                        {
                            "bbox": list(bbox),
                            "row_count": int(rows),
                            "col_count": int(cols),
                        }
                    )

                pages.append({"page": page_no, "markdown": md, "tables": tables})

            full_md = "\n\n".join(p["markdown"] for p in pages if p["markdown"])
            return {"markdown": full_md, "pages": pages}

        md = pymupdf4llm.to_markdown(doc=doc).replace("<br>", "\n")
        return {"markdown": md, "pages": []}
    finally:
        doc.close()


def _normalize_pattern_names(patterns: List[PatternItem] | None) -> Optional[Set[str]]:
    if not patterns:
        return None
    names: Set[str] = set()
    for p in patterns:
        nm = getattr(p, "name", None) or getattr(p, "rule", None)
        if nm:
            names.add(nm)
    return names or None


def _is_valid_value(need_valid: bool, validator, value: str) -> bool:
    if not need_valid or not callable(validator):
        return True
    try:
        try:
            return bool(validator(value))
        except TypeError:
            return bool(validator(value, None))
    except Exception:
        print(f"{log_prefix} VALIDATOR ERROR", repr(value))
        return False


def detect_boxes_from_patterns(pdf_bytes: bytes, patterns: List[PatternItem] | None) -> List[Box]:
    from server.modules.common import compile_rules  # lazy import

    comp = compile_rules()
    allowed_names = _normalize_pattern_names(patterns)

    print(
        f"{log_prefix} detect_boxes_from_patterns: rules 준비 완료",
        "allowed_names=",
        sorted(allowed_names) if allowed_names else "ALL",
    )

    stats_ok: Dict[str, int] = {}
    stats_fail: Dict[str, int] = {}

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    try:
        for pno, page in enumerate(doc):
            text = page.get_text("text") or ""
            if not text:
                continue

            for (rule_name, rx, need_valid, _prio, validator) in comp:
                if allowed_names and rule_name not in allowed_names:
                    continue

                try:
                    it = rx.finditer(text)
                except Exception:
                    continue

                for m in it:
                    val = m.group(0)
                    if not val:
                        continue

                    ok = _is_valid_value(need_valid, validator, val)

                    if ok:
                        stats_ok[rule_name] = stats_ok.get(rule_name, 0) + 1
                    else:
                        stats_fail[rule_name] = stats_fail.get(rule_name, 0) + 1

                    print(
                        f"{log_prefix} MATCH",
                        "page=",
                        pno + 1,
                        "rule=",
                        rule_name,
                        "need_valid=",
                        need_valid,
                        "ok=",
                        ok,
                        "value=",
                        repr(val),
                    )

                    if not ok:
                        continue

                    rects = page.search_for(val)
                    for r in rects:
                        print(
                            f"{log_prefix} BOX",
                            "page=",
                            pno + 1,
                            "rule=",
                            rule_name,
                            "rect=",
                            (r.x0, r.y0, r.x1, r.y1),
                        )
                        boxes.append(Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
    finally:
        doc.close()

    print(
        f"{log_prefix} detect summary",
        "OK=",
        {k: v for k, v in sorted(stats_ok.items())},
        "FAIL=",
        {k: v for k, v in sorted(stats_fail.items())},
        "boxes=",
        len(boxes),
    )

    return boxes


def _page_to_pil(page: fitz.Page, dpi: int = 120) -> Image.Image:
    mat = fitz.Matrix(dpi / 72, dpi / 72)
    pix = page.get_pixmap(matrix=mat, alpha=False)
    return Image.frombytes("RGB", (pix.width, pix.height), pix.samples)


def _group_rows_by_y(blocks: List[Dict[str, Any]], row_tol: float = 35.0) -> List[List[Dict[str, Any]]]:
    if not blocks:
        return []

    enriched: List[Dict[str, Any]] = []
    for b in blocks:
        x0, y0, x1, y1 = b.get("bbox", [0, 0, 0, 0])
        cy = 0.5 * (float(y0) + float(y1))
        bb = dict(b)
        bb["_cy"] = cy
        enriched.append(bb)

    enriched.sort(key=lambda b: b["_cy"])

    rows: List[List[Dict[str, Any]]] = []
    current: List[Dict[str, Any]] = []
    last_cy: Optional[float] = None

    for b in enriched:
        cy = b["_cy"]
        if last_cy is None or abs(cy - last_cy) <= row_tol:
            current.append(b)
        else:
            rows.append(current)
            current = [b]
        last_cy = cy

    if current:
        rows.append(current)

    for row in rows:
        for b in row:
            b.pop("_cy", None)

    for row in rows:
        row.sort(key=lambda b: float((b.get("bbox") or [0, 0, 0, 0])[0]))

    return rows


def _text_for_post(b: Dict[str, Any]) -> str:
    return str(b.get("normalized") or b.get("text") or "").strip()


def _count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)


def _looks_value_like(s: str) -> bool:
    if not s:
        return False
    if "@" in s:
        return True
    d = _count_digits(s)
    if d >= 2:
        return True
    if "-" in s or "." in s:
        return d >= 1
    if 2 <= len(s) <= 4 and s.isalpha():
        return True
    return False


def _is_incomplete_sensitive(kind: str, text: str) -> bool:
    t = text.strip()
    if not t:
        return False

    if kind == "card":
        digits = _count_digits(t)
        return 10 <= digits <= 15
    if kind == "email":
        if "@" not in t:
            return False
        return t.endswith(".") or (re.search(r"\.[A-Za-z]{2,4}$", t) is None)
    return False


def _promote_value_like_in_rows(blocks: List[Dict[str, Any]]) -> None:
    SENSITIVE = {"card", "phone", "email", "id"}

    rows = _group_rows_by_y(blocks, row_tol=35.0)
    for row in rows:
        sens = [b for b in row if (b.get("kind") in SENSITIVE)]
        if not sens:
            continue

        sens_min_x0 = min(float((b.get("bbox") or [0, 0, 0, 0])[0]) for b in sens)

        for b in row:
            if (b.get("kind") in (None, "", "none")):
                t = _text_for_post(b)
                if not _looks_value_like(t):
                    continue

                x0 = float((b.get("bbox") or [0, 0, 0, 0])[0])
                if x0 + 3.0 < sens_min_x0:
                    continue

                b["kind"] = sens[0].get("kind") or "row_sensitive"


def _promote_multiline_continuations(blocks: List[Dict[str, Any]]) -> None:
    rows = _group_rows_by_y(blocks, row_tol=35.0)
    if len(rows) < 2:
        return

    def x_overlap_ratio(a: List[float], b: List[float]) -> float:
        ax0, _, ax1, _ = a
        bx0, _, bx1, _ = b
        inter = max(0.0, min(ax1, bx1) - max(ax0, bx0))
        denom = max(1.0, min(ax1 - ax0, bx1 - bx0))
        return inter / denom

    for i in range(len(rows) - 1):
        cur = rows[i]
        nxt = rows[i + 1]

        for a in cur:
            kind = a.get("kind") or "none"
            if kind not in ("card", "email"):
                continue

            at = _text_for_post(a)
            if not _is_incomplete_sensitive(kind, at):
                continue

            ab = list(map(float, (a.get("bbox") or [0, 0, 0, 0])))
            ax0, ay0, ax1, ay1 = ab
            acx = 0.5 * (ax0 + ax1)

            best = None
            best_score = 0.0

            for b in nxt:
                if (b.get("kind") or "none") != "none":
                    continue

                bt = _text_for_post(b)
                if not bt:
                    continue

                bb = list(map(float, (b.get("bbox") or [0, 0, 0, 0])))
                bx0, by0, bx1, by1 = bb
                bcx = 0.5 * (bx0 + bx1)

                if by0 - ay1 > 40.0:
                    continue

                ov = x_overlap_ratio(ab, bb)
                if ov < 0.25 and abs(bcx - acx) > 80.0:
                    continue

                if kind == "card":
                    if not bt.replace("-", "").replace(" ", "").isdigit():
                        continue
                    if _count_digits(bt) > 6:
                        continue
                else:
                    if not (2 <= len(bt) <= 6 and bt.isalpha()):
                        continue

                score = ov - (abs(bcx - acx) / 1000.0)
                if score > best_score:
                    best_score = score
                    best = b

            if best is not None:
                best["kind"] = kind


def extract_embedded_images(pdf_bytes: bytes, include_bytes: bool = False) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    out: List[dict] = []
    try:
        for pno in range(len(doc)):
            page = doc[pno]
            imgs = page.get_images(full=True) or []
            for it in imgs:
                xref = int(it[0])
                info = doc.extract_image(xref)
                ext = str(info.get("ext") or "")
                w = int(info.get("width") or 0)
                h = int(info.get("height") or 0)
                size = int(info.get("size") or 0)

                item = {
                    "page": pno + 1,
                    "xref": xref,
                    "ext": ext,
                    "width": w,
                    "height": h,
                    "size": size,
                }
                if include_bytes:
                    b = info.get("image") or b""
                    item["image_b64"] = base64.b64encode(b).decode("ascii")

                out.append(item)

        print(f"{log_prefix} extract_embedded_images count=", len(out))
        return {"images": out}
    finally:
        doc.close()


def _load_pil_from_extracted(info: dict) -> Optional[Image.Image]:
    b = info.get("image")
    if not b:
        return None
    try:
        im = Image.open(io.BytesIO(b))
        if im.mode not in ("RGB", "L"):
            im = im.convert("RGB")
        return im
    except Exception:
        return None


def _map_bbox_px_to_page_rect(
    bbox_px: List[float],
    img_w: int,
    img_h: int,
    rect: fitz.Rect,
) -> fitz.Rect:
    x0, y0, x1, y1 = map(float, bbox_px)
    if img_w <= 0 or img_h <= 0:
        return fitz.Rect(0, 0, 0, 0)

    rx0 = rect.x0 + (x0 / img_w) * rect.width
    rx1 = rect.x0 + (x1 / img_w) * rect.width
    ry0 = rect.y0 + (y0 / img_h) * rect.height
    ry1 = rect.y0 + (y1 / img_h) * rect.height

    return fitz.Rect(rx0, ry0, rx1, ry1)


def detect_boxes_from_embedded_images(
    pdf_bytes: bytes,
    *,
    use_llm: bool = True,
    min_conf: float = 0.3,
) -> List[Box]:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    try:
        for pno in range(len(doc)):
            page = doc[pno]
            imgs = page.get_images(full=True) or []
            if not imgs:
                continue

            for it in imgs:
                xref = int(it[0])

                try:
                    rects_raw = page.get_image_rects(xref)
                except Exception:
                    rects_raw = []

                rects: List[fitz.Rect] = []
                for rr in rects_raw or []:
                    if isinstance(rr, fitz.Rect):
                        rects.append(rr)
                    elif isinstance(rr, (list, tuple)) and rr and isinstance(rr[0], fitz.Rect):
                        rects.append(rr[0])

                if not rects:
                    continue

                try:
                    info = doc.extract_image(xref)
                except Exception:
                    continue

                pil = _load_pil_from_extracted(info)
                if pil is None:
                    continue

                img_w, img_h = pil.size[0], pil.size[1]

                ocr_blocks = easyocr_blocks(pil, min_conf=min_conf, gpu=False) or []
                print(f"{log_prefix} EMBED_OCR page={pno+1} xref={xref} rects={len(rects)} blocks={len(ocr_blocks)}")

                llm_ok = False
                if use_llm and ocr_blocks:
                    try:
                        ocr_blocks = classify_blocks_with_qwen(ocr_blocks) or ocr_blocks
                        _promote_value_like_in_rows(ocr_blocks)
                        _promote_multiline_continuations(ocr_blocks)
                        llm_ok = True

                        kinds: Dict[str, int] = {}
                        for b in ocr_blocks:
                            k = (b.get("kind") or "none")
                            kinds[k] = kinds.get(k, 0) + 1
                        print(f"{log_prefix} EMBED_LLM page={pno+1} xref={xref} ok=1 kind_counts={kinds}")
                    except Exception as e:
                        llm_ok = False
                        print(f"{log_prefix} EMBED_LLM page={pno+1} xref={xref} ok=0 err={e}")

                added = 0
                for blk in ocr_blocks:
                    kind = blk.get("kind") or "none"

                    if llm_ok:
                        if kind == "none":
                            continue
                    else:
                        t = _text_for_post(blk)
                        if not _looks_value_like(t):
                            continue

                    bbox_px = blk.get("bbox") or [0, 0, 0, 0]
                    if not isinstance(bbox_px, (list, tuple)) or len(bbox_px) != 4:
                        continue

                    for rect in rects:
                        r = _map_bbox_px_to_page_rect(list(bbox_px), img_w, img_h, rect) & page.rect
                        if r.is_empty:
                            continue

                        boxes.append(Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
                        added += 1

                print(f"{log_prefix} EMBED_BOX page={pno+1} xref={xref} added={added}")
    finally:
        doc.close()

    print(f"{log_prefix} detect_boxes_from_embedded_images summary boxes=", len(boxes))
    return boxes


def detect_boxes_from_ocr(
    pdf_bytes: bytes,
    *,
    dpi: int = 120,
    use_llm: bool = True,
    min_conf: float = 0.3,
) -> List[Box]:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    scale = dpi / 72.0
    inv_scale = 1.0 / scale

    try:
        for pno, page in enumerate(doc):
            words = page.get_text("words") or []
            text_rects = [fitz.Rect(w[0], w[1], w[2], w[3]) for w in words]

            def overlaps_text_layer(r: fitz.Rect) -> bool:
                for tr in text_rects:
                    if not r.intersects(tr):
                        continue
                    inter = r & tr
                    if inter.get_area() > 0:
                        return True
                return False

            img = _page_to_pil(page, dpi=dpi)

            ocr_blocks = easyocr_blocks(img, min_conf=min_conf, gpu=False) or []
            print(f"{log_prefix} OCR page={pno + 1} blocks=", len(ocr_blocks))

            llm_ok = False
            if use_llm and ocr_blocks:
                try:
                    ocr_blocks = classify_blocks_with_qwen(ocr_blocks) or ocr_blocks
                    _promote_value_like_in_rows(ocr_blocks)
                    _promote_multiline_continuations(ocr_blocks)
                    llm_ok = True
                except Exception as e:
                    llm_ok = False
                    print(f"{log_prefix} LLM fail page={pno+1} err={e}")

            for blk in ocr_blocks:
                kind = blk.get("kind") or "none"
                if llm_ok:
                    if kind == "none":
                        continue
                else:
                    t = _text_for_post(blk)
                    if not _looks_value_like(t):
                        continue

                x0_px, y0_px, x1_px, y1_px = blk["bbox"]

                x0 = float(x0_px) * inv_scale
                y0 = float(y0_px) * inv_scale
                x1 = float(x1_px) * inv_scale
                y1 = float(y1_px) * inv_scale

                width = x1 - x0
                height = y1 - y0

                if height > 1.0:
                    pad_y = min(max(height * 0.15, 0.6), 3.0)
                    y0 -= pad_y
                    y1 += pad_y

                if width > 1.0:
                    pad_x_left = min(max(width * 0.01, 0.2), 1.2)
                    pad_x_right = min(max(width * 0.06, 0.8), 6.0)
                    x0 -= pad_x_left
                    x1 += pad_x_right

                rect_pdf = fitz.Rect(x0, y0, x1, y1) & page.rect
                if overlaps_text_layer(rect_pdf):
                    continue

                print(
                    f"{log_prefix} OCR BOX",
                    "page=",
                    pno + 1,
                    "kind=",
                    kind,
                    "text=",
                    repr(_text_for_post(blk)),
                    "bbox_px=",
                    (x0_px, y0_px, x1_px, y1_px),
                    "bbox_pdf=",
                    (rect_pdf.x0, rect_pdf.y0, rect_pdf.x1, rect_pdf.y1),
                )

                boxes.append(
                    Box(
                        page=pno,
                        x0=rect_pdf.x0,
                        y0=rect_pdf.y0,
                        x1=rect_pdf.x1,
                        y1=rect_pdf.y1,
                    )
                )
    finally:
        doc.close()

    print(f"{log_prefix} detect_boxes_from_ocr summary", "boxes=", len(boxes))
    return boxes


def detect_sensitive_boxes_from_ocr(
    pdf_bytes: bytes,
    *,
    dpi: int = 220,
    min_conf: float = 0.25,
    allowed_rules: Optional[Set[str]] = None,
    masking_policy: Optional[dict] = None,
    max_pages: int = 50,
) -> List[Box]:
    from server.modules.common import compile_rules 

    comp = compile_rules()
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    scale = float(dpi) / 72.0
    inv_scale = 1.0 / scale

    try:
        for pno, page in enumerate(doc):
            if max_pages and pno >= int(max_pages):
                break
            words = page.get_text("words") or []
            text_rects = [fitz.Rect(w[0], w[1], w[2], w[3]) for w in words]

            def overlaps_text_layer(r: fitz.Rect) -> bool:
                for tr in text_rects:
                    if not r.intersects(tr):
                        continue
                    inter = r & tr
                    if inter.get_area() > 0:
                        return True
                return False

            img = _page_to_pil(page, dpi=int(dpi))
            ocr_blocks = easyocr_blocks(img, min_conf=float(min_conf), gpu=False) or []

            added = 0
            for blk in ocr_blocks:
                txt = str(blk.get("text") or "").strip()
                if not txt:
                    continue

                bbox_px0 = blk.get("bbox") or [0, 0, 0, 0]
                if not isinstance(bbox_px0, (list, tuple)) or len(bbox_px0) != 4:
                    continue
                bbox_px0 = list(map(float, bbox_px0))

                # 정규식 매칭: "블록 전체"가 아니라 "매칭된 substring"만 bbox로 슬라이스
                for (rule_name, rx, need_valid, _prio, validator) in comp:
                    rlow = str(rule_name or "").lower()
                    if allowed_rules and rlow not in allowed_rules:
                        continue

                    try:
                        it = rx.finditer(txt)
                    except Exception:
                        it = []

                    for m in it:
                        val = m.group(0)
                        if not val:
                            continue
                        if not _is_valid_value(need_valid, validator, val):
                            continue

                        # 1) 기본: 매칭 span으로 bbox 좁히기
                        base_px = _slice_bbox_by_char_span(txt, m.start(), m.end(), bbox_px0)
                        base_px = _tighten_overwide_bbox(val, base_px, char_px_factor=0.55, slack=0.25)

                        repl = _mask_value_with_policy(rlow, val, masking_policy)
                        runs = _masked_runs_from_replacement(val, repl)
                        if not runs:

                            continue

                        for a, b in runs:
                            # val 내부 run -> txt 내부 절대 span
                            abs0 = m.start() + int(a)
                            abs1 = m.start() + int(b)
                            sub_px = _slice_bbox_by_char_span(txt, abs0, abs1, bbox_px0)
                            sub_px = _tighten_overwide_bbox(val[a:b], sub_px, char_px_factor=0.55, slack=0.20)

                            x0_px, y0_px, x1_px, y1_px = sub_px
                            x0 = float(x0_px) * inv_scale
                            y0 = float(y0_px) * inv_scale
                            x1 = float(x1_px) * inv_scale
                            y1 = float(y1_px) * inv_scale

                            rect_pdf = fitz.Rect(x0, y0, x1, y1) & page.rect
                            if rect_pdf.is_empty:
                                continue
                            if overlaps_text_layer(rect_pdf):
                                continue

                            # 최소 패딩(과마스킹 방지)
                            w = rect_pdf.x1 - rect_pdf.x0
                            h = rect_pdf.y1 - rect_pdf.y0
                            if h > 0.5:
                                py = min(max(h * 0.08, 0.4), 1.6)
                            else:
                                py = 0.0
                            if w > 0.5:
                                px = min(max(w * 0.01, 0.2), 0.8)
                            else:
                                px = 0.0

                            rect_pdf = fitz.Rect(
                                rect_pdf.x0 - px,
                                rect_pdf.y0 - py,
                                rect_pdf.x1 + px,
                                rect_pdf.y1 + py,
                            ) & page.rect
                            if rect_pdf.is_empty:
                                continue

                            boxes.append(
                                Box(
                                    page=pno,
                                    x0=rect_pdf.x0,
                                    y0=rect_pdf.y0,
                                    x1=rect_pdf.x1,
                                    y1=rect_pdf.y1,
                                )
                            )
                            added += 1

            if added > 0:
                print(f"{log_prefix} OCR_SENSITIVE page={pno+1} added={added}")

    finally:
        doc.close()

    print(f"{log_prefix} detect_sensitive_boxes_from_ocr summary boxes=", len(boxes))
    return boxes


def detect_sensitive_boxes_from_embedded_images(
    pdf_bytes: bytes,
    *,
    min_conf: float = 0.25,
    allowed_rules: Optional[Set[str]] = None,
    masking_policy: Optional[dict] = None,
) -> List[Box]:
    from server.modules.common import compile_rules  # lazy import

    comp = compile_rules()
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    try:
        for pno in range(len(doc)):
            page = doc[pno]
            imgs = page.get_images(full=True) or []
            if not imgs:
                continue

            for it in imgs:
                xref = int(it[0])

                try:
                    rects_raw = page.get_image_rects(xref)
                except Exception:
                    rects_raw = []

                rects: List[fitz.Rect] = []
                for rr in rects_raw or []:
                    if isinstance(rr, fitz.Rect):
                        rects.append(rr)
                    elif isinstance(rr, (list, tuple)) and rr and isinstance(rr[0], fitz.Rect):
                        rects.append(rr[0])

                if not rects:
                    continue

                try:
                    info = doc.extract_image(xref)
                except Exception:
                    continue

                pil = _load_pil_from_extracted(info)
                if pil is None:
                    continue

                img_w, img_h = pil.size[0], pil.size[1]
                ocr_blocks = easyocr_blocks(pil, min_conf=float(min_conf), gpu=False) or []

                added = 0
                for blk in ocr_blocks:
                    txt = str(blk.get("text") or "").strip()
                    if not txt:
                        continue

                    bbox_px0 = blk.get("bbox") or [0, 0, 0, 0]
                    if not isinstance(bbox_px0, (list, tuple)) or len(bbox_px0) != 4:
                        continue
                    bbox_px0 = list(map(float, bbox_px0))

                    for (rule_name, rx, need_valid, _prio, validator) in comp:
                        rlow = str(rule_name or "").lower()
                        if allowed_rules and rlow not in allowed_rules:
                            continue
                        try:
                            it = rx.finditer(txt)
                        except Exception:
                            it = []

                        for m in it:
                            val = m.group(0)
                            if not val:
                                continue
                            if not _is_valid_value(need_valid, validator, val):
                                continue

                            repl = _mask_value_with_policy(rlow, val, masking_policy)
                            runs = _masked_runs_from_replacement(val, repl)
                            if not runs:
                                continue

                            for a, b in runs:
                                abs0 = m.start() + int(a)
                                abs1 = m.start() + int(b)
                                sub_px = _slice_bbox_by_char_span(txt, abs0, abs1, bbox_px0)
                                sub_px = _tighten_overwide_bbox(val[a:b], sub_px, char_px_factor=0.55, slack=0.20)

                                for rect in rects:
                                    r = _map_bbox_px_to_page_rect(list(sub_px), img_w, img_h, rect) & page.rect
                                    if r.is_empty:
                                        continue

                                    # 최소 패딩(과마스킹 방지)
                                    w = r.x1 - r.x0
                                    h = r.y1 - r.y0
                                    py = min(max(h * 0.08, 0.4), 1.6) if h > 0.5 else 0.0
                                    px = min(max(w * 0.01, 0.2), 0.8) if w > 0.5 else 0.0
                                    r2 = fitz.Rect(r.x0 - px, r.y0 - py, r.x1 + px, r.y1 + py) & page.rect
                                    if r2.is_empty:
                                        continue

                                    boxes.append(Box(page=pno, x0=r2.x0, y0=r2.y0, x1=r2.x1, y1=r2.y1))
                                    added += 1

                if added > 0:
                    print(f"{log_prefix} EMBED_OCR_SENSITIVE page={pno+1} xref={xref} added={added}")

    finally:
        doc.close()

    print(f"{log_prefix} detect_sensitive_boxes_from_embedded_images summary boxes=", len(boxes))
    return boxes


def _norm_ocr_match(s: str) -> str:
    s = str(s or "").strip()
    if not s:
        return ""
    try:
        s = unicodedata.normalize("NFKC", s)
    except Exception:
        pass
    s = s.lower()
    # OCR 매칭용
    s = re.sub(r"[\s\-\‐–—\.\,:;\/\\\(\)\[\]\{\}]+", "", s)
    return s


def _compact_nospace_with_map(s: str) -> Tuple[str, List[int]]:
    out_chars: List[str] = []
    idx_map: List[int] = []
    for i, ch in enumerate(str(s or "")):
        if ch.isspace():
            continue
        out_chars.append(ch)
        idx_map.append(i)
    return "".join(out_chars), idx_map


def _find_target_span_in_block(raw: str, target: str) -> Optional[Tuple[int, int]]:
    # raw 텍스트 안에서 target을 찾아 (start,end) 반환. 실패 시 None
    raw0 = str(raw or "")
    tgt0 = str(target or "").strip()
    if len(tgt0) < 2 or not raw0:
        return None

    # 1) 그대로 검색
    j = raw0.find(tgt0)
    if j >= 0:
        return j, j + len(tgt0)

    # 2) NFKC + 대소문자 무시
    try:
        r2 = unicodedata.normalize("NFKC", raw0).lower()
        t2 = unicodedata.normalize("NFKC", tgt0).lower()
    except Exception:
        r2 = raw0.lower()
        t2 = tgt0.lower()

    j = r2.find(t2)
    if j >= 0 and len(r2) == len(raw0):
        return j, j + len(t2)

    # 3) 공백 제거 버전으로 검색(매핑 유지)
    rc, mp = _compact_nospace_with_map(raw0)
    tc, _ = _compact_nospace_with_map(tgt0)
    if len(tc) < 2 or not rc:
        return None
    k = rc.find(tc)
    if k < 0:
        return None
    s0 = mp[k]
    s1 = mp[k + len(tc) - 1] + 1
    if s1 <= s0:
        return None
    return s0, s1


def detect_boxes_from_ocr_targets(
    pdf_bytes: bytes,
    *,
    targets: List[str],
    dpi: int = 220,
    min_conf: float = 0.25,
    max_pages: int = 50,
) -> List[Box]:

    if not targets:
        return []

    norm_targets = []
    seen = set()
    for t in targets:
        nt = _norm_ocr_match(t)
        if len(nt) < 2:
            continue
        if nt in seen:
            continue
        seen.add(nt)
        norm_targets.append(nt)

    if not norm_targets:
        return []

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    scale = float(dpi) / 72.0
    inv_scale = 1.0 / scale

    try:
        for pno, page in enumerate(doc):
            if max_pages and pno >= int(max_pages):
                break
            words = page.get_text("words") or []
            text_rects = [fitz.Rect(w[0], w[1], w[2], w[3]) for w in words]

            def overlaps_text_layer(r: fitz.Rect) -> bool:
                for tr in text_rects:
                    if not r.intersects(tr):
                        continue
                    inter = r & tr
                    if inter.get_area() > 0:
                        return True
                return False

            img = _page_to_pil(page, dpi=int(dpi))
            ocr_blocks = easyocr_blocks(img, min_conf=float(min_conf), gpu=False) or []

            added = 0
            for blk in ocr_blocks:
                raw = str(blk.get("text") or "").strip()
                if not raw:
                    continue
                nb = _norm_ocr_match(raw)
                if len(nb) < 2:
                    continue

                bbox_px = blk.get("bbox") or [0, 0, 0, 0]
                if not isinstance(bbox_px, (list, tuple)) or len(bbox_px) != 4:
                    continue
                bbox_px0 = list(map(float, bbox_px))

                # target이 block 안의 일부만 매칭되면 bbox를 그 부분으로 슬라이스해서 과마스킹을 줄임
                best_span = None
                for t in targets:
                    span = _find_target_span_in_block(raw, str(t or ""))
                    if span:
                        best_span = span
                        break

                if best_span:
                    s0, s1 = best_span
                    sub_px = _slice_bbox_by_char_span(raw, s0, s1, bbox_px0)
                    sub_px = _tighten_overwide_bbox(raw[s0:s1], sub_px, char_px_factor=0.55, slack=0.20)
                else:
                    # fallback: 기존처럼 넓게 잡히는 것을 최소화하기 위해 overwide만 축소
                    sub_px = _tighten_overwide_bbox(raw, bbox_px0, char_px_factor=0.55, slack=0.15)

                x0_px, y0_px, x1_px, y1_px = sub_px
                x0 = float(x0_px) * inv_scale
                y0 = float(y0_px) * inv_scale
                x1 = float(x1_px) * inv_scale
                y1 = float(y1_px) * inv_scale

                rect_pdf = fitz.Rect(x0, y0, x1, y1) & page.rect
                if rect_pdf.is_empty:
                    continue
                if overlaps_text_layer(rect_pdf):
                    continue

                # 최소 패딩
                w = rect_pdf.x1 - rect_pdf.x0
                h = rect_pdf.y1 - rect_pdf.y0
                px = min(max(w * 0.01, 0.15), 0.7) if w > 0.5 else 0.0
                py = min(max(h * 0.08, 0.35), 1.4) if h > 0.5 else 0.0
                rect_pdf = fitz.Rect(rect_pdf.x0 - px, rect_pdf.y0 - py, rect_pdf.x1 + px, rect_pdf.y1 + py) & page.rect

                boxes.append(Box(page=pno, x0=rect_pdf.x0, y0=rect_pdf.y0, x1=rect_pdf.x1, y1=rect_pdf.y1))
                added += 1

            if added > 0:
                print(f"{log_prefix} OCR_TARGETS page={pno+1} added={added}")

    finally:
        doc.close()

    print(f"{log_prefix} detect_boxes_from_ocr_targets summary boxes=", len(boxes))
    return boxes


def detect_boxes_from_embedded_image_targets(
    pdf_bytes: bytes,
    *,
    targets: List[str],
    min_conf: float = 0.25,
) -> List[Box]:
    # PDF 내 임베드 이미지(xref) OCR 결과에서 targets(text 목록)와 매칭되는 블록만 Box 생성
    if not targets:
        return []

    norm_targets = []
    seen = set()
    for t in targets:
        nt = _norm_ocr_match(t)
        if len(nt) < 2:
            continue
        if nt in seen:
            continue
        seen.add(nt)
        norm_targets.append(nt)

    if not norm_targets:
        return []

    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    boxes: List[Box] = []

    try:
        for pno in range(len(doc)):
            page = doc[pno]
            imgs = page.get_images(full=True) or []
            if not imgs:
                continue

            for it in imgs:
                xref = int(it[0])

                try:
                    rects_raw = page.get_image_rects(xref)
                except Exception:
                    rects_raw = []

                rects: List[fitz.Rect] = []
                for rr in rects_raw or []:
                    if isinstance(rr, fitz.Rect):
                        rects.append(rr)
                    elif isinstance(rr, (list, tuple)) and rr and isinstance(rr[0], fitz.Rect):
                        rects.append(rr[0])

                if not rects:
                    continue

                try:
                    info = doc.extract_image(xref)
                except Exception:
                    continue

                pil = _load_pil_from_extracted(info)
                if pil is None:
                    continue

                img_w, img_h = pil.size[0], pil.size[1]
                ocr_blocks = easyocr_blocks(pil, min_conf=float(min_conf), gpu=False) or []

                added = 0
                for blk in ocr_blocks:
                    raw = str(blk.get("text") or "").strip()
                    if not raw:
                        continue
                    nb = _norm_ocr_match(raw)
                    if len(nb) < 2:
                        continue

                    bbox_px = blk.get("bbox") or [0, 0, 0, 0]
                    if not isinstance(bbox_px, (list, tuple)) or len(bbox_px) != 4:
                        continue
                    bbox_px0 = list(map(float, bbox_px))

                    best_span = None
                    for t in targets:
                        span = _find_target_span_in_block(raw, str(t or ""))
                        if span:
                            best_span = span
                            break

                    if best_span:
                        s0, s1 = best_span
                        sub_px = _slice_bbox_by_char_span(raw, s0, s1, bbox_px0)
                        sub_px = _tighten_overwide_bbox(raw[s0:s1], sub_px, char_px_factor=0.55, slack=0.20)
                    else:
                        sub_px = _tighten_overwide_bbox(raw, bbox_px0, char_px_factor=0.55, slack=0.15)

                    for rect in rects:
                        r = _map_bbox_px_to_page_rect(list(sub_px), img_w, img_h, rect) & page.rect
                        if r.is_empty:
                            continue

                        w = r.x1 - r.x0
                        h = r.y1 - r.y0
                        px = min(max(w * 0.01, 0.15), 0.7) if w > 0.5 else 0.0
                        py = min(max(h * 0.08, 0.35), 1.4) if h > 0.5 else 0.0
                        r = fitz.Rect(r.x0 - px, r.y0 - py, r.x1 + px, r.y1 + py) & page.rect
                        if r.is_empty:
                            continue

                        boxes.append(Box(page=pno, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))
                        added += 1

                if added > 0:
                    print(f"{log_prefix} EMBED_OCR_TARGETS page={pno+1} xref={xref} added={added}")

    finally:
        doc.close()

    print(f"{log_prefix} detect_boxes_from_embedded_image_targets summary boxes=", len(boxes))
    return boxes

def _fill_color(fill: str):
    f = (fill or "black").strip().lower()
    return (0, 0, 0) if f == "black" else (1, 1, 1)


def apply_redaction(pdf_bytes: bytes, boxes: List[Box], fill: str = "black") -> bytes:
    print(f"{log_prefix} apply_redaction: boxes=", len(boxes), "fill=", fill)
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        color = _fill_color(fill)
        for b in boxes:
            page = doc.load_page(int(b.page))
            rect = fitz.Rect(float(b.x0), float(b.y0), float(b.x1), float(b.y1))
            page.add_redact_annot(rect, fill=color)

        for page in doc:
            page.apply_redactions()

        out = io.BytesIO()
        doc.save(out)
        return out.getvalue()
    finally:
        doc.close()


def apply_text_redaction(pdf_bytes: bytes, extra_spans: List[dict] | None = None) -> bytes:
    patterns = [PatternItem(**p) for p in PRESET_PATTERNS]
    boxes = detect_boxes_from_patterns(pdf_bytes, patterns)

    ocr_boxes = detect_boxes_from_ocr(pdf_bytes, dpi=120, use_llm=True, min_conf=0.3)
    embed_boxes = detect_boxes_from_embedded_images(pdf_bytes, use_llm=True, min_conf=0.3)

    print(
        f"{log_prefix} apply_text_redaction: pattern_boxes=",
        len(boxes),
        "ocr_boxes=",
        len(ocr_boxes),
        "embedded_boxes=",
        len(embed_boxes),
    )

    boxes.extend(ocr_boxes)
    boxes.extend(embed_boxes)

    if extra_spans:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        try:
            page_texts: List[str] = []
            page_offsets: List[int] = []
            current_offset = 0

            for page in doc:
                text = page.get_text("text") or ""
                page_texts.append(text)
                page_offsets.append(current_offset)
                current_offset += len(text) + 1

            full_text = "\n".join(page_texts)

            for span in extra_spans:
                start = span.get("start", 0)
                end = span.get("end", 0)
                if end <= start or start >= len(full_text):
                    continue

                span_text = full_text[start: min(end, len(full_text))]
                if not span_text or not span_text.strip():
                    continue

                search_text = span_text.strip()
                if not search_text:
                    continue

                for page_idx, page_offset in enumerate(page_offsets):
                    next_offset = page_offsets[page_idx + 1] if page_idx + 1 < len(page_offsets) else len(full_text)
                    if start >= page_offset and start < next_offset:
                        page = doc[page_idx]
                        rects = page.search_for(search_text)

                        if rects:
                            for r in rects:
                                boxes.append(Box(page=page_idx, x0=r.x0, y0=r.y0, x1=r.x1, y1=r.y1))

                            print(
                                f"{log_prefix} NER BOX",
                                "page=",
                                page_idx + 1,
                                "label=",
                                span.get("label", "unknown"),
                                "text=",
                                repr(search_text[:50]),
                                "matches=",
                                len(rects),
                            )
                        break
        finally:
            doc.close()

    return apply_redaction(pdf_bytes, boxes)

def extract_text_indexed(pdf_bytes: bytes, *, row_tol: float = 8.0) -> dict:
    doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    try:
        full_parts: List[str] = []
        char_index: List[dict] = []
        pages_out: List[dict] = []

        offset = 0

        for pno, page in enumerate(doc):
            words = page.get_text("words") or []
            if not words:
                pages_out.append({
                    "page": pno + 1,
                    "text": "",
                    "start": offset,
                    "end": offset,
                })
                continue

            # 단어들을 Y좌표 기준으로 그룹화하여 줄(row)로 분리
            word_data: List[Tuple[float, float, float, float, str]] = []
            for w in words:
                try:
                    x0, y0, x1, y1, txt = float(w[0]), float(w[1]), float(w[2]), float(w[3]), str(w[4])
                    if txt:
                        word_data.append((x0, y0, x1, y1, txt))
                except Exception:
                    continue

            if not word_data:
                pages_out.append({
                    "page": pno + 1,
                    "text": "",
                    "start": offset,
                    "end": offset,
                })
                continue

            # Y좌표 (중심) 기준으로 정렬
            word_data.sort(key=lambda wd: (0.5 * (wd[1] + wd[3]), wd[0]))

            # 줄(row)로 그룹화
            rows: List[List[Tuple[float, float, float, float, str]]] = []
            current_row: List[Tuple[float, float, float, float, str]] = []
            last_cy: Optional[float] = None

            for wd in word_data:
                x0, y0, x1, y1, txt = wd
                cy = 0.5 * (y0 + y1)
                if last_cy is None or abs(cy - last_cy) <= row_tol:
                    current_row.append(wd)
                else:
                    if current_row:
                        rows.append(current_row)
                    current_row = [wd]
                last_cy = cy

            if current_row:
                rows.append(current_row)

            # 각 줄 내에서 X좌표로 정렬
            for row in rows:
                row.sort(key=lambda wd: wd[0])

            page_start = offset
            page_text_parts: List[str] = []
            is_first_word_in_page = True

            for row_idx, row in enumerate(rows):
                # 줄 사이에 줄바꿈 삽입
                if row_idx > 0:
                    page_text_parts.append("\n")
                    char_index.append({"page": pno, "bbox": None})
                    full_parts.append("\n")
                    offset += 1

                is_first_word_in_row = True

                for wd in row:
                    x0, y0, x1, y1, txt = wd

                    # 같은 줄의 단어 사이에 공백 삽입
                    if not is_first_word_in_row:
                        page_text_parts.append(" ")
                        char_index.append({"page": pno, "bbox": None})
                        full_parts.append(" ")
                        offset += 1

                    bbox = (x0, y0, x1, y1)
                    page_text_parts.append(txt)
                    full_parts.append(txt)

                    # 부분 마스킹을 위해 "단어 bbox"를 문자 단위로 x축 분할하여 저장한다.
                    try:
                        n = len(txt)
                        wpx = max(0.0, float(x1) - float(x0))
                        if n > 1 and wpx > 0.0 and n <= 128:
                            cw = wpx / float(n)
                            for i in range(n):
                                bx0 = float(x0) + cw * i
                                bx1 = float(x0) + cw * (i + 1)
                                char_index.append({"page": pno, "bbox": (bx0, y0, bx1, y1)})
                        else:
                            for _ch in txt:
                                char_index.append({"page": pno, "bbox": bbox})
                    except Exception:
                        for _ch in txt:
                            char_index.append({"page": pno, "bbox": bbox})
                    offset += len(txt)

                    is_first_word_in_row = False
                    is_first_word_in_page = False

            page_text = "".join(page_text_parts)

            pages_out.append(
                {
                    "page": pno + 1,
                    "text": page_text,
                    "start": page_start,
                    "end": offset,
                }
            )

            # 페이지 사이에 줄바꿈 삽입
            full_parts.append("\n")
            char_index.append({"page": pno, "bbox": None})
            offset += 1

        full_text = "".join(full_parts).rstrip("\n")
        if len(char_index) > len(full_text):
            char_index = char_index[: len(full_text)]

        return {"full_text": full_text, "pages": pages_out, "char_index": char_index}
    finally:
        doc.close()


def _boxes_from_index_span(index: dict, start: int, end: int) -> List[Box]:
    chars = index.get("char_index") or []
    if not chars:
        return []

    s = max(0, int(start))
    e = min(len(chars), int(end))
    if e <= s:
        return []

    rects: List[Tuple[int, float, float, float, float]] = []
    for i in range(s, e):
        ch = chars[i]
        bbox = ch.get("bbox")
        page = ch.get("page")
        if bbox is None or page is None:
            continue
        try:
            rects.append((int(page), float(bbox[0]), float(bbox[1]), float(bbox[2]), float(bbox[3])))
        except Exception:
            continue

    if not rects:
        return []

    # 정렬 후, 같은 줄(유사 y)에서 x 인접한 박스는 병합해서 annotation 개수를 줄임
    rects.sort(key=lambda t: (t[0], t[2], t[1]))

    merged: List[Tuple[int, float, float, float, float]] = []
    y_tol = 1.2
    gap_tol = 0.9

    for p, x0, y0, x1, y1 in rects:
        if not merged:
            merged.append((p, x0, y0, x1, y1))
            continue

        mp, mx0, my0, mx1, my1 = merged[-1]
        same_line = (p == mp) and (abs(y0 - my0) <= y_tol) and (abs(y1 - my1) <= y_tol)
        close_x = x0 <= (mx1 + gap_tol)

        if same_line and close_x:
            merged[-1] = (mp, min(mx0, x0), min(my0, y0), max(mx1, x1), max(my1, y1))
        else:
            merged.append((p, x0, y0, x1, y1))

    out: List[Box] = [Box(page=p, x0=x0, y0=y0, x1=x1, y1=y1) for (p, x0, y0, x1, y1) in merged]
    return out
