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


# SST 파서 클래스
class SSTParser:
    def __init__(self, wb: bytes, start_off: int):
        self.wb = wb
        self.n = len(wb)
        self.off = start_off   # 현재 BIFF 레코드 헤더 오프셋

        self.cur = b""   # 현재 읽고있는 페이로드 상태 (SST 또는 CONTINUE)
        self.pos = 0     # 페이로드 내에서 현재 읽고있는 위치

        self.cst_total = 0   # SST 전체 문자열 수
        self.cst_unique = 0  # SST 고유 문자열 수

        self.cur_fHighByte: int | None = None # 현재 문자열의 인코딩 상태

    # BIFF 레코드 헤더 읽기
    def read_biff_header(self, off):
        opcode, length = struct.unpack_from("<HH", self.wb, off)
        payload_off = off + 4
        payload_end = payload_off + length
        return opcode, length, payload_off, payload_end

    # 다음 BIFF 레코드 읽기
    def next_record(self):
        opcode, length, payload_off, payload_end = self.read_biff_header(self.off)
        payload = self.wb[payload_off:payload_end]
        self.off = payload_end # 다음 레코드 헤더 위치
        return opcode, payload

    # CONTINUE 레코드 처리
    def next_continue(self):
        # 다음 BIFF 헤더조차 없으면 더 이상 읽을 수 없음
        if self.off + 4 > self.n:
            self.cur = b""
            self.pos = 0
            return

        # "peek"만 한다 (off를 바로 움직이지 않음)
        opcode, length = struct.unpack_from("<HH", self.wb, self.off)
        payload_off = self.off + 4
        payload_end = payload_off + length
        if payload_end > self.n:
            self.cur = b""
            self.pos = 0
            return

        if opcode != CONTINUE:   # CONTINUE가 아니면 종료
            self.cur = b""
            self.pos = 0
            return

        # 진짜 CONTINUE인 경우 진행
        payload = self.wb[payload_off:payload_end]
        self.off = payload_end  # 다음 레코드는 CONTINUE 뒤

        if len(payload) > 0:
            # payload[0] = fHighByte
            cont_flag = payload[0]
            self.current_fHighByte = cont_flag & 0x01
            self.cur = payload
            self.pos = 1  # payload[1:]부터 텍스트
        else:
            self.cur = payload
            self.pos = 0

    # 바이트 N개 읽기 (CONTINUE 처리 포함)
    def take(self, num: int) -> bytes:
        out = bytearray()
        while num > 0:
            if self.pos >= len(self.cur):
                # payload 끝 -> CONTINUE로 넘어가기
                self.refill_continue()
                if not self.cur: # 더 이상 읽을 데이터가 없음
                    break

            take_n = min(num, len(self.cur) - self.pos)
            out.extend(self.cur[self.pos:self.pos + take_n])
            self.pos += take_n
            num -= take_n

        return bytes(out)

    def read_u8(self) -> int:
        b = self.take(1)
        if len(b) < 1:
            raise EOFError("SSTParser.read_u8: EOF")
        return b[0]

    def read_u16(self) -> int:
        b = self.take(2)
        if len(b) < 2:
            raise EOFError("SSTParser.read_u16: EOF")
        return struct.unpack("<H", b)[0]

    def read_u32(self) -> int:
        b = self.take(4)
        if len(b) < 4:
            raise EOFError("SSTParser.read_u32: EOF")
        return struct.unpack("<I", b)[0]

    # XLUnicodeRichExtendedString 파싱
    def parse_xlucs(self):
        try:
            cch = self.read_u16()
        except EOFError:
            return None

        try:
            flags = self.read_u8()
        except EOFError:
            return None

        fHighByte = flags & 0x01
        fExtSt    = flags & 0x04
        fRichSt   = flags & 0x08

        # optional fields
        if fRichSt:
            try:
                cRun = self.read_u16()
            except EOFError:
                return None
        else:
            cRun = 0

        if fExtSt:
            try:
                cbExtRst = self.read_u32()
            except EOFError:
                return None
        else:
            cbExtRst = 0

        # text
        char_size = 2 if fHighByte else 1
        raw = self.take(cch * char_size)
        if len(raw) < cch * char_size:
            text = ""
        else:
            try:
                text = raw.decode("utf-16le" if fHighByte else "latin1", errors="ignore")
            except Exception:
                text = ""

        # skip runs
        if fRichSt:
            _ = self.take(4 * cRun)

        # skip extrst
        if fExtSt:
            _ = self.take(cbExtRst)

        return text.strip()


    def parse(self):
        # 현재 off 지점이 SST라고 가정
        opcode, payload = self.next_record()
        if opcode != SST:
            return [], self.off

        if len(payload) < 8:
            return [], self.off

        self.cst_total  = le32(payload, 0)
        self.cst_unique = le32(payload, 4)

        # 문자열 데이터 시작
        self.cur = payload
        self.pos = 8

        strings = []

        for _ in range(self.cst_unique):
            txt = self.parse_xlucs()
            if txt is None:
                break
            strings.append(txt)

        return strings, self.off
