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

    # 페이로드에서 n바이트 읽고 pos 이동
    def read_n(self,n):
        if self.pos + n > self.n:
            raise EOFError
        b = self.payload[self.pos:self.pos + n]
        self.pos += n
        return b

    def read_sst_header(self):
        self.cstTotal = le32(self.read_n(4),0)
        self.cstUnique = le32(self.read_n(4),0)

    def read_XLUCS(self):
        cch = le16(self.read_n(2),0)
        flags = self.read_n(1)[0]
        fHigh = flags & 0x01
        fExtSt = flags & 0x04
        fRichSt = flags & 0x08

        cRun = le16(self.read_n(2),0)if fRichSt else 0
        cbExt = le32(self.read_n(4),0)if fExtSt else 0


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

def parse_sst(wb: bytes):
    sst_payload = get_sst_payload(wb)
    if not sst_payload:
        return []
    
    parser = SSTParser(sst_payload)
    return parser.parse()

