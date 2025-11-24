import io, os, re
import struct
import tempfile
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.redaction_rules import apply_redaction_rules
from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans

SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD
LABEL = 0x0204

def le16(b, off): return struct.unpack_from("<H", b, off)[0]
def le32(b, off): return struct.unpack_from("<I", b, off)[0]

def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        header_off = off
        off += 4
        payload = data[off:off + length]
        off += length
        yield opcode, length, payload, header_off


def get_sst_payload(wb: bytes) -> bytes:
    print("[DEBUG] Workbook 스트림에서 SST 레코드 탐색중...")
    for opcode, length, payload, header_off in iter_biff_records(wb):
        if opcode == SST:
            print(f"[OK] SST 레코드 발견! payload_length={length}")
            return payload
    print("[WARN] SST 레코드 없음")
    return None


# =====================================
# SST Parser
# =====================================
class SSTParser:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.pos = 0
        self.n = len(payload)
        self.cstTotal = 0
        self.cstUnique = 0
        print(f"[DEBUG] SSTParser 초기화: payload_len={self.n}")

    def read_n(self, n):
        if self.pos + n > self.n:
            raise EOFError
        b = self.payload[self.pos:self.pos + n]
        self.pos += n
        return b

    def read_sst_header(self):
        self.cstTotal = le32(self.read_n(4),0)
        self.cstUnique = le32(self.read_n(4),0)
        print(f"[OK] SST Header: total={self.cstTotal}, unique={self.cstUnique}")

    def read_XLUCS(self):
        start = self.pos
        cch = le16(self.read_n(2), 0)
        flags = self.read_n(1)[0]
        fHigh = flags & 0x01
        fExtSt = flags & 0x04
        fRichSt = flags & 0x08

        cRun = le16(self.read_n(2),0) if fRichSt else 0
        cbExt = le32(self.read_n(4),0) if fExtSt else 0

        char_size = 2 if fHigh else 1
        raw = self.read_n(cch * char_size)
        text = raw.decode('utf-16le' if fHigh else 'latin1', errors='ignore')

        if cRun:
            self.read_n(4 * cRun)
        if cbExt:
            self.read_n(cbExt)

        print(f"[DEBUG] XLUCS 문자열 파싱: pos={start}->{self.pos}, text='{text[:50]}'")
        return text.strip()

    def parse(self):
        self.read_sst_header()
        strings = []
        for i in range(self.cstUnique):
            try:
                txt = self.read_XLUCS()
                strings.append(txt)
            except EOFError:
                print("[WARN] SSTParser: EOF 도달")
                break

        print(f"[OK] 총 {len(strings)}개의 SST 문자열 파싱 완료")
        return strings


# =====================================
# 문자열 추출
# =====================================
def extract_text_from_xls(file_bytes: bytes):
    print("[INFO] XLS 문자 추출 시작")

    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("Workbook"):
                print("[ERROR] Workbook 스트림 없음")
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}

            wb = ole.openstream("Workbook").read()
            print(f"[OK] Workbook 스트림 로드 완료 (size={len(wb)})")

        sst_payload = get_sst_payload(wb)
        if not sst_payload:
            strings = []
        else:
            strings = SSTParser(sst_payload).parse()

        print(f"[INFO] SST 문자열 리스트 길이={len(strings)}")

        # LABELSST / LABEL 처리
        texts = []
        for opcode, length, payload, header_off in iter_biff_records(wb):
            if opcode == LABELSST and len(payload) >= 10:
                idx = le32(payload, 6)
                if 0 <= idx < len(strings):
                    texts.append(strings[idx])

            elif opcode == LABEL and len(payload) > 8:
                try:
                    txt = payload[8:].decode("cp949", errors="ignore").strip()
                    if txt:
                        texts.append(txt)
                except:
                    pass

        full_text = "\n".join(t for t in texts if t)
        print(f"[OK] 추출된 셀 텍스트 개수={len(texts)}")

        return {"full_text": full_text, "pages":[{"page":1,"text":full_text}]}

    except Exception as e:
        print("[ERROR] XLS 추출 중 예외:", e)
        return {"full_text":"","pages":[{"page":1,"text":""}]}


# =====================================
# 레닥션 부분
# =====================================
def build_xlucs(s: str) -> bytes:
    raw = s.encode("utf-16le")
    cch = len(s)
    flags = 0x01

    out = bytearray()
    out += struct.pack("<H", cch)
    out.append(flags)
    out += raw
    return bytes(out)


def rebuild_sst_payload(redacted_strings: List[str]) -> bytes:
    print(f"[INFO] SST 재구성 시작 (문자열 {len(redacted_strings)}개)")
    out = bytearray()
    out += struct.pack("<I", len(redacted_strings))
    out += struct.pack("<I", len(redacted_strings))
    for s in redacted_strings:
        out += build_xlucs(s)
    print("[OK] SST payload 재구성 완료")
    return bytes(out)


def redact(file_bytes: bytes) -> bytes:
    print("[INFO] XLS 레닥션 시작")

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("Workbook"):
            print("[ERROR] Workbook 없음")
            return file_bytes
        wb = bytearray(ole.openstream("Workbook").read())

    sst_payload = get_sst_payload(wb)
    strings = SSTParser(sst_payload).parse() if sst_payload else []
    print(f"[INFO] 원본 SST 문자열 개수 = {len(strings)}")

    redacted_strings = [apply_redaction_rules(s) for s in strings]
    print("[INFO] redaction 규칙 적용 완료")

    new_sst = rebuild_sst_payload(redacted_strings)

    off = 0
    n = len(wb)

    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", wb, off)
        off += 4
        payload_off = off
        payload_end = off + length

        if opcode == SST:
            print(f"[PATCH] SST payload 패치 (offset={payload_off}, length={length})")
            wb[payload_off:payload_end] = new_sst[:length].ljust(length, b"\x00")

        elif opcode == LABEL:
            try:
                old_text = wb[payload_off+8:payload_end].decode("cp949", errors="ignore").strip()
                red = apply_redaction_rules(old_text)
                enc = red.encode("cp949",errors="ignore")
                wb[payload_off+8:payload_end] = enc[:(length-8)].ljust((length-8),b"\x00")
                print(f"[PATCH] LABEL 텍스트 패치='{old_text}' → '{red}'")
            except:
                pass

        off = payload_end

    print("[OK] XLS 레닥션 완료")
    return bytes(wb)
