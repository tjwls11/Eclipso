# -*- coding: utf-8 -*-
import io, os, re, struct, tempfile, olefile
from typing import Optional
from server.core.normalize import normalization_text
from server.core.matching import find_sensitive_spans

def le16(b, off): return struct.unpack_from("<H", b, off)[0]
def le32(b, off): return struct.unpack_from("<I", b, off)[0]

def iter_biff_records(data: bytes):
    off, n = 0, len(data); idx = 0
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        off += 4
        payload = data[off:off + length]
        print(f"[CHART] record#{idx} opcode=0x{opcode:04X}, length={length}")
        yield off - 4, opcode, length, payload
        off += length; idx += 1

class XLUCS:
    __slots__ = ("base","end","cch","flags","fHigh","fExt","fRich","cRun","cbExtRst","text_lo","text_hi")
    def try_parse_at(self, payload: bytes, start: int) -> bool:
        n = len(payload); pos = start
        if pos + 3 > n: return False
        cch = le16(payload, pos); pos += 2
        flags = payload[pos]; pos += 1
        if not (0 <= cch <= 65535): return False
        fHigh = flags & 0x01; fExt = 1 if (flags & 0x04) else 0; fRich = 1 if (flags & 0x08) else 0
        cRun = cbExtRst = 0
        if fRich:
            if pos + 2 > n: return False
            cRun = le16(payload, pos); pos += 2
        if fExt:
            if pos + 4 > n: return False
            cbExtRst = le32(payload, pos); pos += 4
        need = cch * (2 if fHigh else 1)
        text_lo, text_hi = pos, pos + need
        if text_hi > n: return False
        pos = text_hi + (cRun * 4) + cbExtRst
        if pos > n: return False
        self.base, self.end, self.cch, self.flags, self.fHigh = start, pos, cch, flags, fHigh
        self.text_lo, self.text_hi = text_lo, text_hi
        print(f"[XLUCS] parse OK at {start} cch={cch}, flags=0x{flags:02X}, fHigh={fHigh}")
        return True
    def decode_text(self, payload: bytes, cp="cp1252") -> str:
        raw = payload[self.text_lo:self.text_hi]
        try:
            return raw.decode("utf-16le" if self.fHigh else cp, errors="ignore")
        except Exception:
            return ""

def redact_payload_ascii(wb: bytearray, payload_off: int, length: int, codepage="cp1252") -> int:
    seg = wb[payload_off:payload_off+length]
    ascii_texts = re.findall(rb"[ -~]{5,}", seg)
    utf16_texts = re.findall(rb"(?:[\x20-\x7E]\x00){5,}", seg)
    red = 0
    for seq in ascii_texts + utf16_texts:
        try:
            text = seq.decode("utf-16le" if b"\x00" in seq else codepage, errors="ignore")
            if not text.strip(): continue
            if find_sensitive_spans(normalization_text(text)):
                s = seg.find(seq)
                if s != -1:
                    e = s + len(seq)
                    wb[payload_off+s:payload_off+e] = b"*"*len(seq)
                    red += 1
                    print(f"[FALLBACK] ASCII 레닥션: {repr(text)} → {'*'*len(text)}")
        except Exception:
            pass
    return red


CHART_STRING_LIKE = {0x0004, 0x041E, 0x100D, 0x1025, 0x104B, 0x105C, 0x1024, 0x1026}

def _scan_and_redact_xlucs_in_payload(wb: bytearray, payload_off: int, length: int, codepage="cp1252") -> int:
    end = payload_off + length; pos = payload_off; red=0; seen=False
    while pos < end:
        x = XLUCS()
        if not x.try_parse_at(wb[payload_off:end], start=(pos - payload_off)):
            pos += 1; continue
        seen = True
        text = x.decode_text(wb[payload_off:end], codepage)
        if text.strip():
            if find_sensitive_spans(normalization_text(text)):
                masked = ("*"*len(text)).encode("utf-16le" if x.fHigh else codepage)
                raw_len = x.text_hi - x.text_lo
                wb[payload_off + x.text_lo : payload_off + x.text_hi] = masked[:raw_len].ljust(raw_len, b'*')
                red += 1
                print(f"[CHART] 레닥션 적용: {repr(text)} → {'*'*len(text)}")
            else:
                print(f"[CHART] 매칭 없음: {repr(text)}")
        else:
            print(f"[XLUCS] 빈 문자열 at pos={pos}")
        pos = payload_off + x.end
    if not seen:
        red += redact_payload_ascii(wb, payload_off, length, codepage)
    return red

def redact_biff_stream(biff_bytes: bytes, codepage="cp1252") -> bytes:
    wb = bytearray(biff_bytes); total=0
    for rec_off, opcode, length, payload in iter_biff_records(wb):
        if opcode in CHART_STRING_LIKE and length>0:
            try:
                cnt = _scan_and_redact_xlucs_in_payload(wb, rec_off+4, length, codepage)
                total += cnt
                print(f"[CHART] opcode=0x{opcode:04X}에서 {cnt}개 문자열 레닥션")
            except Exception as e:
                print(f"[WARN] opcode=0x{opcode:04X} 처리 중 예외: {e}")
    print(f"[CHART] 총 {total}개 문자열 레닥션 완료")
    return bytes(wb)


def redact_workbooks(file_bytes: bytes, codepage="cp1252") -> bytes:
    """
    1) ObjectPool/*/(Workbook | \x01Workbook) 내 BIFF 텍스트 레닥션
    """
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            modified = file_bytes
            for entry in ole.listdir():
                if len(entry)>=2 and entry[0]=="ObjectPool" and entry[-1] in ("Workbook","\x01Workbook"):
                    print(f"[INFO] 발견된 Workbook 스트림: {entry}")
                    wb_data = ole.openstream(entry).read()
                    new_biff = redact_biff_stream(wb_data, codepage)
                    # 임시 파일로 열어 쓰기
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
                        tmp.write(modified)
                        path = tmp.name
                    try:
                        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole_debug:
                            print("[DEBUG] 전체 OLE 스트림 목록:")
                            for e in ole_debug.listdir():
                                print("  ", e)
                        with olefile.OleFileIO(path, write_mode=True) as olew:
                            # 1) 워크북 덮어쓰기
                            olew.write_stream("/".join(entry), new_biff)
                            print(f"[WRITE] {'/'.join(entry)} 스트림 덮어쓰기")
                        with open(path, "rb") as f: modified = f.read()
                    finally:
                        os.remove(path)
            return modified
    except Exception as e:
        print(f"[ERR] ObjectPool 처리 중 예외: {e}")
        return file_bytes
