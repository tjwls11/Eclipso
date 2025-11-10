# -*- coding: utf-8 -*-
import io, os, re, struct, tempfile, olefile
from typing import Optional, List, Tuple
from server.core.normalize import normalization_text
from server.core.matching import find_sensitive_spans

# ─────────────────────────────
# 유틸: 리틀엔디언 헬퍼
# ─────────────────────────────
def le16(b, off): return struct.unpack_from("<H", b, off)[0]
def le32(b, off): return struct.unpack_from("<I", b, off)[0]

# ─────────────────────────────
# BIFF 레코드 반복자 + CONTINUE 병합
# ─────────────────────────────
def iter_biff_records(data: bytes):
    off, n = 0, len(data); idx = 0
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        off += 4
        payload = data[off:off + length]
        yield off - 4, opcode, length, payload
        off += length; idx += 1

def coalesce_with_continue(biff_bytes: bytes, off: int) -> Tuple[bytes, List[Tuple[int, int]], int]:
    """하나의 BIFF 레코드와 뒤따르는 CONTINUE(0x003C) 레코드를 병합"""
    merged = b''
    segs = []
    n = len(biff_bytes)
    cur_off = off
    while cur_off + 4 <= n:
        op, length = struct.unpack_from("<HH", biff_bytes, cur_off)
        if op == 0x003C and not segs:  # 첫 CONTINUE는 앞 레코드가 있어야 함
            break
        payload_off = cur_off + 4
        payload = biff_bytes[payload_off:payload_off+length]
        merged += payload
        segs.append((payload_off, payload_off+length))
        cur_off += 4 + length
        # 다음 레코드 opcode 확인
        if cur_off + 4 > n:
            break
        next_op = struct.unpack_from("<H", biff_bytes, cur_off)[0]
        if next_op != 0x003C:
            break
    return merged, segs, cur_off

# ─────────────────────────────
# Excel 문자열 구조체 파서
# ─────────────────────────────
class XLUCS:
    __slots__ = ("base","end","cch","flags","fHigh","fExt","fRich","cRun","cbExtRst","text_lo","text_hi")

    def try_parse_at(self, payload: bytes, start: int) -> bool:
        n = len(payload); pos = start
        if pos + 3 > n: return False
        try:
            cch = le16(payload, pos); pos += 2
            flags = payload[pos]; pos += 1
            fHigh = flags & 0x01
            fExt  = 1 if (flags & 0x04) else 0
            fRich = 1 if (flags & 0x08) else 0
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
            print(f"[XLUCS] OK start={start}, cch={cch}, flags=0x{flags:02X}, fHigh={fHigh}")
            return True
        except Exception as e:
            print(f"[XLUCS] parse fail at {start}: {e}")
            return False

    def decode_text(self, payload: bytes, single_byte_codec="cp1252") -> str:
        raw = payload[self.text_lo:self.text_hi]
        # fHigh 플래그 불일치 보정 (휴리스틱)
        if not self.fHigh and len(raw) >= 4 and raw[1] == 0x00 and raw[3] == 0x00:
            enc = "utf-16le"
        else:
            enc = "utf-16le" if self.fHigh else single_byte_codec
        try:
            return raw.decode(enc, errors="ignore")
        except Exception as e:
            print(f"[XLUCS] decode fail: {e}")
            return ""

# ─────────────────────────────
# ASCII / UTF-16 fallback 마스킹
# ─────────────────────────────
def fallback_redact(wb: bytearray, off: int, length: int, single_byte_codec="cp1252") -> int:
    seg = wb[off:off+length]
    patterns = [
        (re.compile(rb"[ -~]{5,}"), single_byte_codec),
        (re.compile(rb"(?:[\x20-\x7E]\x00){5,}"), "utf-16le"),
    ]
    red = 0
    for pat, codec in patterns:
        for m in pat.finditer(seg):
            seq = m.group(0)
            try:
                text = seq.decode(codec, errors="ignore")
                if not text.strip():
                    continue
                if find_sensitive_spans(normalization_text(text)):
                    if codec == "utf-16le":
                        repl = ("*" * len(text)).encode("utf-16le")
                        repl = repl[:len(seq)]
                    else:
                        repl = b"*" * len(seq)
                    s = m.start(); e = m.end()
                    wb[off+s:off+e] = repl
                    red += 1
                    print(f"[FALLBACK] redact {repr(text)} at {off+s}")
            except Exception:
                pass
    return red

# ─────────────────────────────
# 메인 스캔 함수
# ─────────────────────────────
CHART_STRING_LIKE = {0x0004, 0x041E, 0x100D, 0x1025, 0x104B, 0x105C, 0x1024, 0x1026}

def scan_and_redact_payload(wb: bytearray, off: int, length: int, opcode: int, single_byte_codec="cp1252") -> int:
    merged, segs, next_off = coalesce_with_continue(wb, off)
    end = len(merged)
    pos = 0
    red = 0
    seen = False
    while pos < end:
        x = XLUCS()
        # SeriesText류는 2바이트 offset 보정
        start = pos
        if opcode in (0x100D, 0x1025, 0x1026) and start == 0:
            start += 2
        if not x.try_parse_at(merged, start):
            pos += 1; continue
        seen = True
        text = x.decode_text(merged, single_byte_codec)
        if text.strip():
            norm = normalization_text(text)
            spans = find_sensitive_spans(norm)
            if spans:
                masked = ("*"*len(text)).encode("utf-16le" if x.fHigh else single_byte_codec)
                raw_len = x.text_hi - x.text_lo
                # 실제 스트림 오프셋 계산
                wb_lo = segs[0][0] + x.text_lo
                wb_hi = wb_lo + raw_len
                wb[wb_lo:wb_hi] = masked[:raw_len].ljust(raw_len,b'*')
                print(f"[CHART] redact {repr(text)} → {'*'*len(text)} (opcode=0x{opcode:04X})")
                red += 1
            else:
                print(f"[CHART] no match: {repr(text)}")
        pos = x.end
    if not seen:
        red += fallback_redact(wb, off, length, single_byte_codec)
    return red

# ─────────────────────────────
# BIFF 스트림 전체 처리
# ─────────────────────────────
def redact_biff_stream(biff_bytes: bytes, single_byte_codec="cp1252") -> bytes:
    wb = bytearray(biff_bytes)
    total = 0
    for rec_off, opcode, length, payload in iter_biff_records(wb):
        if opcode in CHART_STRING_LIKE and length > 0:
            print(f"[REC] opcode=0x{opcode:04X} len={length}")
            try:
                cnt = scan_and_redact_payload(wb, rec_off+4, length, opcode, single_byte_codec)
                total += cnt
                print(f"[CHART] opcode=0x{opcode:04X} → {cnt} texts redacted")
            except Exception as e:
                print(f"[WARN] opcode=0x{opcode:04X} exception: {e}")
    if total:
        print(f"[CHART] total {total} strings redacted")
    else:
        print("[CHART] no redactions")
    # 전후 diff 체크
    diff = next((i for i,(a,b) in enumerate(zip(biff_bytes,wb)) if a!=b), None)
    if diff is not None:
        print(f"[DEBUG] first diff at {diff}")
    else:
        print("[DEBUG] no byte difference!")
    return bytes(wb)

# ─────────────────────────────
# OLE 레벨 Workbook 스트림 처리
# ─────────────────────────────
def redact_workbooks(file_bytes: bytes, single_byte_codec="cp1252") -> bytes:
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            modified = file_bytes
            for entry in ole.listdir():
                if len(entry) >= 2 and entry[0] == "ObjectPool" and entry[-1] in ("Workbook", "\x01Workbook"):
                    path_str = "/".join(entry)
                    print(f"[INFO] found workbook stream: {path_str}")
                    wb_data = ole.openstream(entry).read()
                    print(f"  [INFO] workbook size={len(wb_data)} bytes")

                    new_biff = redact_biff_stream(wb_data, single_byte_codec)
                    if new_biff == wb_data:
                        print("  [INFO] stream unchanged, skip write")
                        continue

                    # 임시 파일에 전체 복사
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
                        tmp.write(modified)
                        temp_path = tmp.name

                    with olefile.OleFileIO(temp_path, write_mode=True) as olew:
                        olew.write_stream(path_str, new_biff)
                        print(f"  [WRITE] replaced {path_str}")

                    # 쓰기 검증
                    with olefile.OleFileIO(temp_path) as ole_chk:
                        after = ole_chk.openstream(path_str).read()
                    if after == new_biff:
                        print("  [VERIFY] write_stream OK")
                    else:
                        print("  [ERROR] write_stream mismatch!")

                    with open(temp_path,"rb") as f: modified = f.read()
                    os.remove(temp_path)
            return modified
    except Exception as e:
        print(f"[ERR] redact_workbooks exception: {e}")
        return file_bytes
