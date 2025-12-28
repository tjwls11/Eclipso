import os
import re
import struct
import hashlib
import tempfile
from io import BytesIO
from typing import List, Dict, Any, Tuple, Optional

import olefile

from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans
from server.modules.doc_chart import redact_workbooks, extract_chart_text


DOC_DEBUG_IMAGES_ALWAYS = True
DOC_DEBUG_MAX_IMAGES = 64

_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_JPG_SIG = b"\xFF\xD8\xFF"
_BMP_SIG = b"BM"


def _dbg(msg: str) -> None:
    if DOC_DEBUG_IMAGES_ALWAYS:
        print(f"[DOC][DBG] {msg}")


def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _find_all(data: bytes, sig: bytes, limit: int = 100_000) -> List[int]:
    out: List[int] = []
    start = 0
    while True:
        i = data.find(sig, start)
        if i < 0:
            break
        out.append(i)
        if len(out) >= limit:
            break
        start = i + 1
    return out


def _scan_image_sigs(buf: bytes) -> List[Tuple[str, int]]:
    hits: List[Tuple[str, int]] = []
    for p in _find_all(buf, _PNG_SIG, limit=50_000):
        hits.append(("PNG", p))
    for p in _find_all(buf, _JPG_SIG, limit=50_000):
        hits.append(("JPG", p))
    for p in _find_all(buf, _BMP_SIG, limit=50_000):
        hits.append(("BMP", p))
    hits.sort(key=lambda x: x[1])
    return hits


def _png_end_by_chunks(data: bytes, start: int) -> Optional[int]:
    n = len(data)
    if start + 8 > n or data[start:start + 8] != _PNG_SIG:
        return None
    p = start + 8
    try:
        while p + 12 <= n:
            length = struct.unpack_from(">I", data, p)[0]
            ctype = data[p + 4:p + 8]
            p_next = p + 12 + length
            if p_next > n:
                return None
            if ctype == b"IEND":
                return p_next
            p = p_next
    except Exception:
        return None
    return None


def _jpg_end_by_eoi(data: bytes, start: int) -> Optional[int]:
    n = len(data)
    if start + 3 > n or data[start:start + 3] != _JPG_SIG:
        return None
    j = data.find(b"\xFF\xD9", start + 3)
    if j < 0:
        return None
    return j + 2


def _bmp_end_by_header(data: bytes, start: int) -> Optional[int]:
    n = len(data)
    if start + 14 > n or data[start:start + 2] != _BMP_SIG:
        return None
    try:
        size = struct.unpack_from("<I", data, start + 2)[0]
    except Exception:
        return None
    if size <= 0:
        return None
    end = start + size
    return end if end <= n else None


def _read_stream_safe(ole: olefile.OleFileIO, name: str) -> bytes:
    try:
        if ole.exists(name):
            return ole.openstream(name).read()
    except Exception:
        pass
    return b""


def get_table_stream(word_data: bytes, ole: olefile.OleFileIO) -> Optional[str]:
    fib_flags = le16(word_data, 0x000A)
    f_which_tbl = (fib_flags & 0x0200) != 0
    tbl_name = "1Table" if f_which_tbl and ole.exists("1Table") else "0Table"
    return tbl_name if ole.exists(tbl_name) else None


def read_streams(file_bytes: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    try:
        with olefile.OleFileIO(BytesIO(file_bytes)) as ole:
            if not ole.exists("WordDocument"):
                return None, None
            word_data = ole.openstream("WordDocument").read()
            tbl_name = get_table_stream(word_data, ole)
            table_data = ole.openstream(tbl_name).read() if tbl_name else None
            return word_data, table_data
    except Exception:
        return None, None


def get_clx_data(word_data: bytes, table_data: bytes) -> Optional[bytes]:
    fc_clx, lcb_clx = le32(word_data, 0x01A2), le32(word_data, 0x01A6)
    if not table_data or fc_clx + lcb_clx > len(table_data):
        return None
    return table_data[fc_clx:fc_clx + lcb_clx]


def extract_plcpcd(clx: bytes) -> bytes:
    i = 0
    while i < len(clx):
        tag = clx[i]
        i += 1
        if tag == 0x01:
            cb = struct.unpack_from("<H", clx, i)[0]
            i += 2 + cb
        elif tag == 0x02:
            lcb = struct.unpack_from("<I", clx, i)[0]
            i += 4
            return clx[i:i + lcb]
        else:
            break
    return b""


def parse_plcpcd(plcpcd: bytes) -> List[Dict[str, Any]]:
    size = len(plcpcd)
    if size < 4 or (size - 4) % 12 != 0:
        return []
    n = (size - 4) // 12
    a_cp = [le32(plcpcd, 4 * i) for i in range(n + 1)]
    pcd_off = 4 * (n + 1)

    pieces: List[Dict[str, Any]] = []
    for k in range(n):
        pcd_bytes = plcpcd[pcd_off + 8 * k:pcd_off + 8 * (k + 1)]
        fc_raw = le32(pcd_bytes, 2)
        fc = fc_raw & 0x3FFFFFFF
        f_compressed = (fc_raw & 0x40000000) != 0
        cp_start, cp_end = a_cp[k], a_cp[k + 1]
        char_count = cp_end - cp_start
        byte_count = char_count if f_compressed else char_count * 2
        pieces.append(
            {
                "index": k,
                "fc": fc,
                "byte_count": byte_count,
                "fCompressed": f_compressed,
                "cp_start": cp_start,
                "cp_end": cp_end,
            }
        )
    return pieces


def decode_piece(chunk: bytes, f_compressed: bool) -> str:
    try:
        return chunk.decode("cp1252" if f_compressed else "utf-16le", errors="ignore")
    except Exception:
        return ""


def build_image_loc_summary_and_print(file_bytes: bytes) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "found": False,
        "streams": {},
        "data": {"exists": False, "len": 0, "sig_hits": 0, "by_type": {}},
        "objectpool": {"exists": False, "streams": 0, "sig_hits": 0, "by_type": {}},
        "sprmCPicLocation": {"hits": 0},
        "images": [],
    }

    try:
        with olefile.OleFileIO(BytesIO(file_bytes)) as ole:
            for p in ole.listdir(streams=True, storages=False):
                key = "/".join(p)
                try:
                    summary["streams"][key] = ole.get_size(p)
                except Exception:
                    summary["streams"][key] = -1

            if not ole.exists("WordDocument"):
                _dbg("WordDocument stream not found")
                return summary

            word_data = _read_stream_safe(ole, "WordDocument")
            tbl = _read_stream_safe(ole, "1Table") or _read_stream_safe(ole, "0Table")
            data = _read_stream_safe(ole, "Data")

            if data:
                summary["data"]["exists"] = True
                summary["data"]["len"] = len(data)

                hits = _scan_image_sigs(data)
                by: Dict[str, int] = {}
                for k, _off in hits:
                    by[k] = by.get(k, 0) + 1
                summary["data"]["sig_hits"] = len(hits)
                summary["data"]["by_type"] = by

                # sprmCPicLocation opcode 0x6A03 (little-endian bytes: 03 6A)
                summary["sprmCPicLocation"]["hits"] = (word_data + tbl).count(b"\x03\x6A")

                n = len(data)
                for idx, (kind, start) in enumerate(hits[:DOC_DEBUG_MAX_IMAGES]):
                    if kind == "PNG":
                        end = _png_end_by_chunks(data, start)
                    elif kind == "JPG":
                        end = _jpg_end_by_eoi(data, start)
                    else:
                        end = _bmp_end_by_header(data, start)

                    if end is None:
                        next_start = hits[idx + 1][1] if idx + 1 < len(hits) else n
                        end = next_start if next_start > start else n

                    blob = data[start:end]
                    sha1 = hashlib.sha1(blob).hexdigest()
                    summary["images"].append(
                        {
                            "index": idx,
                            "type": kind,
                            "offset": f"0x{start:X}",
                            "end": f"0x{end:X}",
                            "length": len(blob),
                            "sha1": sha1,
                            "source": "Data",
                        }
                    )

            obj_streams = [p for p in ole.listdir(streams=True, storages=False) if p and p[0] == "ObjectPool"]
            if obj_streams:
                summary["objectpool"]["exists"] = True
                summary["objectpool"]["streams"] = len(obj_streams)

                hit2 = 0
                by2: Dict[str, int] = {}
                for p in obj_streams:
                    try:
                        raw = ole.openstream(p).read()
                    except Exception:
                        continue
                    hs = _scan_image_sigs(raw)
                    hit2 += len(hs)
                    for k, _off in hs:
                        by2[k] = by2.get(k, 0) + 1

                summary["objectpool"]["sig_hits"] = hit2
                summary["objectpool"]["by_type"] = by2

        summary["found"] = bool(summary["data"]["sig_hits"] or summary["objectpool"]["sig_hits"])

        _dbg(
            "image_loc: "
            f"{{'found': {summary['found']}, 'streams': {len(summary['streams'])}, "
            f"'Data': {summary['data']}, 'ObjectPool': {summary['objectpool']}, "
            f"'sprmCPicLocation': {summary['sprmCPicLocation']}}}"
        )

        if summary["images"]:
            _dbg(f"images(Data) count={len(summary['images'])} (show up to {DOC_DEBUG_MAX_IMAGES})")
            for it in summary["images"]:
                _dbg(
                    f"  · #{it['index']} {it['type']} {it['offset']}..{it['end']} "
                    f"bytes={it['length']} sha1={it['sha1'][:12]}..."
                )
        else:
            _dbg("images(Data) count=0")

        return summary

    except Exception as e:
        _dbg(f"image_loc build failed: {repr(e)}")
        summary["error"] = repr(e)
        return summary


def split_matches(matches, text):
    new_matches = []
    for s, e, val, meta in matches:
        snippet = text[s:e]
        if "\r\r" in snippet or "\n\n" in snippet:
            parts = re.split(r"[\r\n]{2,}", snippet)
            cp_cursor = s
            for part in parts:
                if not part.strip():
                    cp_cursor += len(part) + 2
                    continue
                new_matches.append((cp_cursor, cp_cursor + len(part), part, meta))
                cp_cursor += len(part) + 2
        else:
            new_matches.append((s, e, val, meta))
    return new_matches


def _mask_keep_rules(v: str) -> str:
    out = []
    for ch in v:
        if ch == "-":
            out.append(ch)
        elif ch.isalnum() or ch in "._":
            out.append("*")
        else:
            out.append(ch)
    return "".join(out)


def _mask_email(v: str) -> str:
    out = []
    in_entity = False
    for ch in v:
        if ch == "&":
            in_entity = True
            out.append(ch)
            continue
        if in_entity:
            out.append(ch)
            if ch == ";":
                in_entity = False
            continue
        if ch in ("@", "-", "＠"):
            out.append(ch)
        else:
            out.append("*")
    return "".join(out)


def _mask_value(rule: str, v: str) -> str:
    r = (rule or "").lower()
    if r == "email" or "email" in r:
        return _mask_email(v)
    return _mask_keep_rules(v)


def extract_text(file_bytes: bytes) -> dict:
    try:
        word_data, table_data = read_streams(file_bytes)
        if not word_data or not table_data:
            out = {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}
            out["image_loc"] = build_image_loc_summary_and_print(file_bytes)
            return out

        clx = get_clx_data(word_data, table_data)
        plcpcd = extract_plcpcd(clx or b"")
        pieces = parse_plcpcd(plcpcd)

        texts: List[str] = []
        for p in pieces:
            start, end = p["fc"], p["fc"] + p["byte_count"]
            if end > len(word_data):
                continue
            texts.append(decode_piece(word_data[start:end], p["fCompressed"]))

        raw_word_text = "".join(texts)
        chart_texts = extract_chart_text(file_bytes)
        raw_text = raw_word_text + ("\n" + "\n".join(chart_texts) if chart_texts else "")
        normalized = normalization_text(raw_text)

        out = {
            "full_text": normalized,
            "raw_text": raw_text,
            "pages": [{"page": 1, "text": normalized}],
        }

        out["image_loc"] = build_image_loc_summary_and_print(file_bytes)
        return out

    except Exception as e:
        print(f"[ERR] DOC 추출 중 예외: {e}")
        out = {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}
        out["image_loc"] = {"found": False, "error": repr(e)}
        return out


def replace_text(file_bytes: bytes, targets: List[Tuple[int, int, str]], replacement_char: str = "*") -> bytes:
    try:
        word_data, table_data = read_streams(file_bytes)
        if not word_data or not table_data:
            raise ValueError("WordDocument 또는 Table 스트림을 읽을 수 없습니다")

        plcpcd = extract_plcpcd(get_clx_data(word_data, table_data) or b"")
        pieces = parse_plcpcd(plcpcd)

        piece_spans = []
        cur = 0
        for p in pieces:
            fc_base = p["fc"]
            bpc = 1 if p["fCompressed"] else 2
            cp_len = p["cp_end"] - p["cp_start"]
            piece_spans.append((cur, cur + cp_len, fc_base, bpc))
            cur += cp_len

        replaced = bytearray(word_data)

        for s, e, rule in targets:
            if e <= s:
                continue
            for text_start, text_end, fc_base, bpc in piece_spans:
                if s >= text_end or e <= text_start:
                    continue
                local_start, local_end = max(s, text_start), min(e, text_end)
                byte_start = fc_base + (local_start - text_start) * bpc
                byte_len = (local_end - local_start) * bpc

                seg_bytes = bytes(replaced[byte_start:byte_start + byte_len])
                if bpc == 2:
                    seg_text = seg_bytes.decode("utf-16le", errors="replace")
                    masked_text = _mask_value(rule, seg_text)
                    masked_bytes = masked_text.encode("utf-16le")
                else:
                    seg_text = seg_bytes.decode("latin-1", errors="replace")
                    masked_text = _mask_value(rule, seg_text)
                    masked_bytes = masked_text.encode("latin-1", errors="replace")

                if len(masked_bytes) != byte_len:
                    mask = (
                        replacement_char.encode("utf-16le")[:2] * (byte_len // 2)
                        if bpc == 2
                        else replacement_char.encode("latin-1")[:1] * byte_len
                    )
                    replaced[byte_start:byte_start + byte_len] = mask
                else:
                    replaced[byte_start:byte_start + byte_len] = masked_bytes

        return create_new_ole_file(file_bytes, bytes(replaced))
    except Exception as e:
        print(f"[ERR] 텍스트 치환 중 오류: {e}")
        return file_bytes


def create_new_ole_file(original_file_bytes: bytes, new_word_data: bytes) -> bytes:
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
            tmp.write(original_file_bytes)
            tmp_path = tmp.name

        with olefile.OleFileIO(tmp_path, write_mode=True) as ole:
            if not ole.exists("WordDocument"):
                return original_file_bytes
            old_len = len(ole.openstream("WordDocument").read())
            if len(new_word_data) != old_len:
                return original_file_bytes
            ole.write_stream("WordDocument", new_word_data)

        with open(tmp_path, "rb") as f:
            result = f.read()
        os.remove(tmp_path)
        return result
    except Exception as e:
        print(f"[ERR] OLE 교체 중 오류: {e}")
        return original_file_bytes


def redact_word_document(file_bytes: bytes) -> bytes:
    try:
        data = extract_text(file_bytes)
        raw_text = data.get("raw_text", "")
        if not raw_text:
            return file_bytes

        norm_text, index_map = normalization_index(raw_text)
        matches = find_sensitive_spans(norm_text)
        matches = split_matches(matches, norm_text)

        targets = []
        for s, e, val, rule in matches:
            if s in index_map and (e - 1) in index_map:
                start = index_map[s]
                end = index_map.get(e - 1, start) + 1
                if end <= start:
                    end = start + (e - s)
                targets.append((start, end, rule))

        return replace_text(file_bytes, targets)

    except Exception as e:
        print(f"[ERR] WordDocument 레닥션 중 예외: {e}")
        return file_bytes

def redact(file_bytes: bytes) -> bytes:
    redacted_doc = redact_word_document(file_bytes)
    redacted_doc = redact_workbooks(redacted_doc)
    return redacted_doc
