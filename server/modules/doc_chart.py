import io
import os
import re
import struct
import tempfile
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.redaction_rules import apply_redaction_rules
from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans

# ─────────────────────────────
# 유틸: 리틀엔디언 헬퍼
# ─────────────────────────────
def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


# ─────────────────────────────
# 차트(BIFF) 처리
# ─────────────────────────────
def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        off += 4
        payload = data[off:off + length]
        off += length
        yield opcode, payload

def decode_chart_string(chunk: bytes) -> str:
    """차트 BIFF 문자열 디코딩 (다중 인코딩 탐색)"""
    encodings = ["utf-16le", "cp1252"]
    decoded = ""
    for enc in encodings:
        try:
            txt = chunk.decode(enc, errors="ignore").strip("\x00").strip()
            if len(re.findall(r"[가-힣A-Za-z0-9]", txt)) >= 2:
                decoded = txt
                break
        except Exception:
            continue
    # fallback: UTF-16 패턴 감지 (\x00 비율 높으면)
    if not decoded and chunk.count(0) / max(len(chunk), 1) > 0.3:
        try:
            decoded = chunk.decode("utf-16le", errors="ignore").strip("\x00").strip()
        except Exception:
            pass
    if decoded:
        print(f"[CHART] 문자열 추출 성공: {repr(decoded)} , encording : {enc}")
    return decoded


def redact_biff_stream(biff_bytes: bytes) -> bytes:
    """BIFF 문자열을 동일 길이 마스킹 포함하여 레닥션"""
    try:
        wb = bytearray(biff_bytes)
        off = 0
        while off + 4 < len(wb):
            opcode, length = struct.unpack_from("<HH", wb, off)
            off += 4
            payload_off = off
            payload_end = off + length

            if opcode in (0x00FC, 0x00FD, 0x0204, 0x100D, 0x1025, 0x104B):
                chunk = wb[payload_off:payload_end]
                text = decode_chart_string(chunk)
                if not text:
                    off = payload_end
                    continue

                # --- 정규화 & 탐지 ---
                normalized = normalization_text(text)
                matches = find_sensitive_spans(normalized)

                if not matches:
                    off = payload_end
                    continue

                print(f"[CHART] 정규화 텍스트: {repr(normalized)}")
                print(f"[CHART] 탐지된 매칭 수: {len(matches)}")

                # --- 동일 길이 마스킹 ---
                red = "*" * len(text)
                print(f"[CHART] opcode=0x{opcode:04X} 레닥션 적용됨: {repr(text)} → {repr(red)}")

                enc = red.encode("utf-16le", errors="ignore")
                wb[payload_off:payload_end] = enc[:length].ljust(length, b"\x00")

            off = payload_end
        return bytes(wb)
    except Exception as e:
        print(f"[ERR] BIFF 레닥션 중 예외: {e}")
        return biff_bytes


def redact_workbooks(file_bytes: bytes) -> bytes:
    """ObjectPool 내 Workbook 스트림 찾아 레닥션 (OLE로 DOC만 열고 내부는 raw BIFF)"""
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            modified = file_bytes
            for entry in ole.listdir():
                if len(entry) >= 2 and entry[0] == "ObjectPool" and entry[-1] in ("Workbook", "\x01Workbook"):
                    print(f"[INFO] 발견된 Workbook 스트림: {entry}")
                    wb_data = ole.openstream(entry).read()
                    modified_biff = redact_biff_stream(wb_data)
                    modified = replace_workbook_stream(modified, entry, modified_biff)
            return modified
    except Exception as e:
        print(f"[ERR] ObjectPool 처리 중 예외: {e}")
        return file_bytes


def replace_workbook_stream(original_doc: bytes, entry_path, new_data: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
        tmp.write(original_doc)
        tmp_path = tmp.name
    try:
        with olefile.OleFileIO(tmp_path, write_mode=True) as ole:
            if not ole.exists(entry_path):
                return original_doc
            ole.write_stream(entry_path, new_data)
        with open(tmp_path, "rb") as f:
            result = f.read()
        return result
    finally:
        os.remove(tmp_path)
