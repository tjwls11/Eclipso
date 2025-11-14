import io
import os
import re
import struct
import tempfile
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans
from server.modules.doc_chart import redact_workbooks, extract_chart_texts


# 리틀엔디언 헬퍼
def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


# ─────────────────────────────
# Word 구조 읽기
# ─────────────────────────────
def get_table_stream(word_data: bytes, ole: olefile.OleFileIO) -> Optional[str]:
    fib_flags = le16(word_data, 0x000A)
    fWhichTblStm = (fib_flags & 0x0200) != 0
    tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"
    return tbl_name if ole.exists(tbl_name) else None


def read_streams(file_bytes: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    """WordDocument / Table 스트림 모두 읽기"""
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("WordDocument"):
                return None, None
            word_data = ole.openstream("WordDocument").read()
            tbl_name = get_table_stream(word_data, ole)
            table_data = ole.openstream(tbl_name).read() if tbl_name else None
            return word_data, table_data
    except Exception:
        return None, None


# ─────────────────────────────
# PlcPcd / CLX 파싱
# ─────────────────────────────
def get_clx_data(word_data: bytes, table_data: bytes) -> Optional[bytes]:
    fcClx, lcbClx = le32(word_data, 0x01A2), le32(word_data, 0x01A6)
    if not table_data or fcClx + lcbClx > len(table_data):
        return None
    return table_data[fcClx:fcClx + lcbClx]


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
    """PlcPcd 구조를 CP 구간 / fc 기반으로 파싱"""
    size = len(plcpcd)
    if size < 4 or (size - 4) % 12 != 0:
        return []
    n = (size - 4) // 12
    aCp = [le32(plcpcd, 4 * i) for i in range(n + 1)]
    pcd_off = 4 * (n + 1)

    pieces = []
    for k in range(n):
        pcd_bytes = plcpcd[pcd_off + 8*k : pcd_off + 8*(k+1)]
        fc_raw = le32(pcd_bytes, 2)
        fc = fc_raw & 0x3FFFFFFF
        fCompressed = (fc_raw & 0x40000000) != 0
        cp_start, cp_end = aCp[k], aCp[k + 1]
        char_count = cp_end - cp_start
        byte_count = char_count if fCompressed else char_count * 2
        pieces.append({
            "index": k,
            "fc": fc,
            "byte_count": byte_count,
            "fCompressed": fCompressed,
            "cp_start": cp_start,
            "cp_end": cp_end
        })
    return pieces


def decode_piece(chunk: bytes, fCompressed: bool) -> str:
    try:
        return chunk.decode("cp1252" if fCompressed else "utf-16le", errors="ignore")
    except Exception:
        return ""



# Word 텍스트 추출
def extract_text(file_bytes: bytes) -> dict:
    try:
        word_data, table_data = read_streams(file_bytes)
        if not word_data or not table_data:
            return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}

        # Word 본문
        clx = get_clx_data(word_data, table_data)
        plcpcd = extract_plcpcd(clx or b"")
        pieces = parse_plcpcd(plcpcd)

        texts = []
        for p in pieces:
            start, end = p["fc"], p["fc"] + p["byte_count"]
            if end > len(word_data):
                continue
            texts.append(decode_piece(word_data[start:end], p["fCompressed"]))

        raw_word_text = "".join(texts)


        # Chart 텍스트 합치기
        chart_texts = extract_chart_texts(file_bytes)
        if chart_texts:
            print(f"[INFO] extracted {len(chart_texts)} chart texts")
            raw_text = raw_word_text + "\n" + "\n".join(chart_texts)
        else:
            raw_text = raw_word_text

        normalized = normalization_text(raw_text)

        return {
            "full_text": normalized,
            "raw_text": raw_text,
            "pages": [{"page": 1, "text": normalized}]
        }

    except Exception as e:
        print(f"[ERR] DOC 추출 중 예외: {e}")
        return {"full_text": "", "raw_text": "", "pages": [{"page": 1, "text": ""}]}




# 탐지 span 보정(분리)
def split_matches(matches, text):
    new_matches = []
    for s, e, val, meta in matches:
        snippet = text[s:e]
        if "\r\r" in snippet or "\n\n" in snippet:
            parts = re.split(r'[\r\n]{2,}', snippet)
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



# Word 본문 레닥션
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
        for s, e, _ in targets:
            for text_start, text_end, fc_base, bpc in piece_spans:
                if s >= text_end or e <= text_start:
                    continue
                local_start, local_end = max(s, text_start), min(e, text_end)
                byte_start = fc_base + (local_start - text_start) * bpc
                byte_len = (local_end - local_start) * bpc
                mask = (replacement_char.encode("utf-16le")[:2] * (byte_len // 2)
                        if bpc == 2 else replacement_char.encode("latin-1")[:1] * byte_len)
                replaced[byte_start:byte_start + byte_len] = mask

        return create_new_ole_file(file_bytes, bytes(replaced))
    except Exception as e:
        print(f"[ERR] 텍스트 치환 중 오류: {e}")
        return file_bytes



# OLE 파일 교체
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


# 전체 레닥션 프로세스
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
        for s, e, val, _ in matches:
            if s in index_map and (e - 1) in index_map:
                start = index_map[s]
                end = index_map.get(e - 1, start) + 1
                if end <= start:
                    end = start + (e - s)
                targets.append((start, end, val))
        return replace_text(file_bytes, targets)
    except Exception as e:
        print(f"[ERR] WordDocument 레닥션 중 예외: {e}")
        return file_bytes


def redact(file_bytes: bytes) -> bytes:
    """1) Word 본문 레닥션 → 2) ObjectPool Workbook(BIFF) 레닥션"""
    redacted_doc = redact_word_document(file_bytes)
    redacted_doc = redact_workbooks(redacted_doc)
    return redacted_doc
