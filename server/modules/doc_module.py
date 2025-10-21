import io
import struct
import tempfile
import os
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.redaction_rules import apply_redaction_rules
from server.core.normalize import normalize_text


def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]

def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


# WordDocument/Table Stream 처리
def _get_table_stream_name(word_data: bytes, ole: olefile.OleFileIO) -> Optional[str]:
    """테이블 스트림 이름 반환"""
    fib_flags = le16(word_data, 0x000A)
    fWhichTblStm = (fib_flags & 0x0200) != 0
    tbl_name = "1Table" if fWhichTblStm and ole.exists("1Table") else "0Table"
    return tbl_name if ole.exists(tbl_name) else None


def _read_word_and_table_streams(file_bytes: bytes) -> Tuple[Optional[bytes], Optional[bytes], Optional[str]]:
    """WordDocument와 Table 스트림 읽기"""
    try:
        buffer = io.BytesIO(file_bytes)
        buffer.seek(0)
        with olefile.OleFileIO(buffer) as ole:
            if not ole.exists("WordDocument"):
                return None, None, None
            word_data = ole.openstream("WordDocument").read()
            tbl_name = _get_table_stream_name(word_data, ole)
            if not tbl_name:
                return word_data, None, None
            table_data = ole.openstream(tbl_name).read()
            return word_data, table_data, tbl_name
    except Exception:
        return None, None, None


def _get_clx_data(word_data: bytes, table_data: bytes) -> Optional[bytes]:
    """CLX 데이터 추출"""
    fcClx = le32(word_data, 0x01A2)
    lcbClx = le32(word_data, 0x01A6)
    if fcClx + lcbClx > len(table_data):
        return None
    return table_data[fcClx:fcClx + lcbClx]

# CLX / PlcPcd 파서
def _extract_plcpcd(clx: bytes) -> bytes:
    """CLX 블록에서 PlcPcd 서브블록 추출"""
    i = 0
    while i < len(clx):
        tag = clx[i]
        i += 1
        if tag == 0x01:
            if i + 2 > len(clx): break
            cb = struct.unpack_from("<H", clx, i)[0]
            i += 2 + cb
        elif tag == 0x02:
            if i + 4 > len(clx): break
            lcb = struct.unpack_from("<I", clx, i)[0]
            i += 4
            return clx[i:i + lcb]
        else:
            break
    return b""



def _parse_plcpcd(plcpcd: bytes) -> List[Dict[str, Any]]:
    """PlcPcd에서 조각 정보 추출"""
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
        cp_start = aCp[k]
        cp_end = aCp[k+1]
        char_count = cp_end - cp_start
        byte_count = char_count if fCompressed else char_count * 2
        pieces.append({
            "index": k,
            "fc": fc,
            "byte_count": byte_count,
            "fCompressed": fCompressed
        })
    return pieces


def _decode_piece(chunk: bytes, fCompressed: bool) -> str:
    """조각 디코딩"""
    try:
        return chunk.decode("cp1252" if fCompressed else "utf-16le", errors="ignore")
    except Exception:
        return ""


# 텍스트 추출 (정규화 포함)
def extract_text(file_bytes: bytes) -> dict:
    """DOC 본문 텍스트 추출"""
    try:
        word_data, table_data, tbl_name = _read_word_and_table_streams(file_bytes)
        if not word_data:
            print("WordDocument 스트림 없음 → 빈 텍스트 반환")
            return {"full_text": "", "pages": [{"page": 1, "text": ""}]}
        if not table_data:
            print("Table 스트림 없음:", tbl_name)
            return {"full_text": "", "pages": [{"page": 1, "text": ""}]}
        clx = _get_clx_data(word_data, table_data)
        if not clx:
            print("CLX 범위 초과 → 무시")
            return {"full_text": "", "pages": [{"page": 1, "text": ""}]}
        plcpcd = _extract_plcpcd(clx)
        if not plcpcd:
            print("PlcPcd 없음")
            return {"full_text": "", "pages": [{"page": 1, "text": ""}]}
        pieces = _parse_plcpcd(plcpcd)

        texts = []
        for p in pieces:
            start, end = p["fc"], p["fc"] + p["byte_count"]
            if end > len(word_data): continue
            chunk = word_data[start:end]
            texts.append(_decode_piece(chunk, p["fCompressed"]))

        full_text = "\n".join(texts)
        normalized_text = normalize_text(full_text)
        return {"full_text": normalized_text, "pages": [{"page": 1, "text": normalized_text}]}
    except Exception as e:
        print("DOC 추출 중 예외:", e)
        return {"full_text": "", "pages": [{"page": 1, "text": ""}]}


# 동일 길이 치환 (*)
def replace_text(file_bytes: bytes, targets: List[str], replacement_char: str = "*") -> bytes:
    """정규화 기반 탐지 결과를 반영하여 동일 길이 '*'로 치환"""
    try:
        word_data, table_data, tbl_name = _read_word_and_table_streams(file_bytes)
        if not word_data or not table_data:
            raise ValueError("WordDocument 또는 Table 스트림을 읽을 수 없습니다")
        clx = _get_clx_data(word_data, table_data)
        if not clx:
            raise ValueError("CLX 데이터를 추출할 수 없습니다")
        plcpcd = _extract_plcpcd(clx)
        if not plcpcd:
            raise ValueError("PlcPcd 데이터를 추출할 수 없습니다")

        pieces = _parse_plcpcd(plcpcd)
        replaced_word_data = bytearray(word_data)
        total_replacement = 0

        for target_text in targets:
            replacement_text = "".join(c if c == "-" else replacement_char for c in target_text)
            for p in pieces:
                start_pos = p["fc"]
                end_pos = p["fc"] + p["byte_count"]
                if end_pos > len(word_data): continue
                chunk = word_data[start_pos:end_pos]
                original_text = _decode_piece(chunk, p["fCompressed"])
                search_start = 0
                while True:
                    idx = original_text.find(target_text, search_start)
                    if idx == -1: break
                    bytes_per_char = 1 if p["fCompressed"] else 2
                    byte_start = start_pos + idx * bytes_per_char
                    byte_len = len(target_text) * bytes_per_char
                    if p["fCompressed"]:
                        replacement_bytes = b"*" * byte_len
                    else:
                        replacement_bytes = (b"*\x00") * (byte_len // 2)
                    replaced_word_data[byte_start:byte_start + byte_len] = replacement_bytes
                    total_replacement += 1
                    search_start = idx + len(target_text)

        print(f"총 {total_replacement}개 치환 완료")
        return _create_new_ole_file(file_bytes, bytes(replaced_word_data))
    except Exception as e:
        print(f"텍스트 치환 중 오류: {e}")
        return file_bytes


# WordDocument 스트림 교체
def _create_new_ole_file(original_file_bytes: bytes, new_word_data: bytes) -> bytes:
    """olefile 공식 write_stream()을 사용해 WordDocument만 교체"""
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
            tmp.write(original_file_bytes)
            tmp_path = tmp.name
        with olefile.OleFileIO(tmp_path, write_mode=True) as ole:
            if not ole.exists("WordDocument"):
                print("[WARN] WordDocument 스트림 없음")
                return original_file_bytes
            old_data = ole.openstream("WordDocument").read()
            if len(old_data) != len(new_word_data):
                print(f"[WARN] WordDocument 길이 불일치 → 교체 중단 ({len(new_word_data)} vs {len(old_data)})")
                return original_file_bytes
            ole.write_stream("WordDocument", new_word_data)
            print("[OK] WordDocument 스트림 교체 완료")
        with open(tmp_path, "rb") as f:
            result = f.read()
        os.remove(tmp_path)
        return result
    except Exception as e:
        print(f"OLE 파일 생성 중 오류: {e}")
        return original_file_bytes

# 레닥션
def redact(file_bytes: bytes) -> bytes:
    try:
        extracted_data = extract_text(file_bytes)
        normalized_text = extracted_data["full_text"]
        if not normalized_text:
            print("추출된 텍스트가 없어 레닥션을 건너뜀")
            return file_bytes
        redacted_text = apply_redaction_rules(normalized_text)
        if redacted_text == normalized_text:
            print("민감정보가 발견되지 않아 원본 파일 반환")
            return file_bytes

        # apply_redaction_rules 결과에서 마스킹된 구간을 추출하는 대신,
        # 탐지된 문자열을 '*'로 치환하도록 replace_text 호출
        targets = []
        for match in apply_redaction_rules(normalized_text).split("*"):
            if match and match in normalized_text:
                targets.append(match)

        return replace_text(file_bytes, targets)
    except Exception as e:
        print(f"DOC 레닥션 중 오류: {e}")
        return file_bytes
