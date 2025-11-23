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
LABELSST = 0x00FD  # UI에 나타내기 위해 필요함
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


def get_sst_payload(wb:bytes)-> bytes:
    for opcode, length, payload, header_off in iter_biff_records(wb):
        if opcode == SST:
            return payload
    return None

# SST 파서 클래스
class SSTParser:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.pos = 0
        self.n = len(payload)

        self.cstTotal = 0
        self.cstUnique = 0

    def read_n(self, n):
        if self.pos + n > self.n:
            raise EOFError
        b = self.payload[self.pos:self.pos + n]
        self.pos += n
        return b

    def read_sst_header(self):
        self.cstTotal = le32(self.read_n(4),0)
        self.cstUnique = le32(self.read_n(4),0)

    def read_XLUCS(self):
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

        return text.strip()

    def parse(self):
        self.read_sst_header()
        strings = []
        for _ in range(self.cstUnique):
            try:
                txt = self.read_XLUCS()
            except EOFError:
                break
            strings.append(txt)
        return strings


def extract_text_from_xls(file_bytes: bytes):
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("Workbook"):
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}
            wb = ole.openstream("Workbook").read()

        sst_payload = get_sst_payload(wb)
        if not sst_payload:
            strings = []
        else:
            strings = SSTParser(sst_payload).parse()

        texts = []
        for opcode, length, payload, header_off in iter_biff_records(wb):
            if opcode == LABELSST and len(payload) >= 10:
                idx = struct.unpack_from("<I", payload, 6)[0]   # <-- safer
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
        return {"full_text": full_text, "pages":[{"page":1,"text":full_text}]}

    except Exception as e:
        print("XLS 추출 중 예외:", e)
        return {"full_text":"","pages":[{"page":1,"text":""}]}


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
    out = bytearray()
    out += struct.pack("<I", len(redacted_strings))
    out += struct.pack("<I", len(redacted_strings))
    for s in redacted_strings:
        out += build_xlucs(s)
    return bytes(out)


def redact(file_bytes: bytes) -> bytes:
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("Workbook"):
            return file_bytes
        wb = bytearray(ole.openstream("Workbook").read())

    sst_payload = get_sst_payload(wb)
    strings = SSTParser(sst_payload).parse() if sst_payload else []
    redacted_strings = [apply_redaction_rules(s) for s in strings]

    new_sst = rebuild_sst_payload(redacted_strings)

    off = 0
    n = len(wb)

    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", wb, off)
        off += 4
        payload_off = off
        payload_end = off + length

        if opcode == SST:
            wb[payload_off:payload_end] = new_sst[:length].ljust(length, b"\x00")

        elif opcode == LABEL:
            try:
                old_text = wb[payload_off+8:payload_end].decode("cp949", errors="ignore").strip()
                red = apply_redaction_rules(old_text)
                enc = red.encode("cp949",errors="ignore")
                wb[payload_off+8:payload_end] = enc[:(length-8)].ljust((length-8),b"\x00")
            except:
                pass

        off = payload_end

    return bytes(wb)
