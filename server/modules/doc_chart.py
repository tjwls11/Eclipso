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
    __slots__ = ("base","end","cch","flags","fHigh","fExt","fRich", "cRun","cbExtRst","text_lo","text_hi","_text_data")

    def try_parse_at(self, payloads: list[bytes], start_index: int, start_offset: int) -> bool:
        data = payloads[start_index]
        n = len(data); pos = start_offset
        if pos + 3 > n: return False

        cch   = le16(data, pos); pos += 2
        flags = data[pos];       pos += 1
        fHigh = flags & 0x01
        fExt  = (flags >> 2) & 1
        fRich = (flags >> 3) & 1

        cRun = cbExtRst = 0
        if fRich:
            if pos + 2 > n: return False
            cRun = le16(data, pos); pos += 2
        if fExt:
            if pos + 4 > n: return False
            cbExtRst = le32(data, pos); pos += 4

        total_chars    = cch
        text_bytes     = bytearray()
        chars_remain   = cch
        cur_fHigh      = fHigh
        cur_payload    = data
        i              = start_index
        pos_in_record  = pos

        while chars_remain > 0:
            need_bytes = chars_remain * (2 if cur_fHigh else 1)
            avail      = len(cur_payload) - pos_in_record

            if avail >= need_bytes:
                text_bytes.extend(cur_payload[pos_in_record:pos_in_record+need_bytes])
                pos_in_record += need_bytes
                chars_remain = 0
            else:
                # 남은 만큼 채우고 CONTINUE로 이동
                take = avail - (avail % (2 if cur_fHigh else 1))
                if take > 0:
                    text_bytes.extend(cur_payload[pos_in_record:pos_in_record+take])
                    chars_remain -= (take // (2 if cur_fHigh else 1))
                i += 1
                if i >= len(payloads): break
                cur_payload   = payloads[i]
                # CONTINUE 첫 1바이트: 새 fHighByte
                cur_fHigh     = payloads[i][0] & 0x01
                pos_in_record = 1

        self.base      = start_offset
        self.cch       = total_chars
        self.flags     = flags
        self.fHigh     = fHigh
        self.text_lo   = 0
        self.text_hi   = len(text_bytes)
        self._text_data = bytes(text_bytes)
        return True

    def decode_text(self, single_byte_codec: str = "cp949") -> str:
        raw = self._text_data
        # fHigh=0인데 UTF-16 패턴이면 보정
        if not self.fHigh and len(raw) >= 4 and raw[1] == 0x00 and raw[3] == 0x00:
            enc = "utf-16le"
        else:
            enc = "utf-16le" if self.fHigh else single_byte_codec
        return raw.decode(enc, errors="ignore")


# ─────────────────────────────
# ASCII / UTF-16 fallback 마스킹
# ─────────────────────────────
def fallback_redact(wb: bytearray, off: int, length: int, single_byte_codec="cp949") -> int:
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

def scan_and_redact_payload(wb: bytearray, payload_off: int, length: int, single_byte_codec="cp949") -> int:
    """
    BIFF payload 내에서 문자열(XLUnicodeRichExtendedString) 단위로 스캔하고 레닥션 적용
    CONTINUE(0x003C) 레코드가 있을 경우 자동 병합 처리
    """
    end = payload_off + length
    payloads = [wb[payload_off:end]]

    # 이어지는 CONTINUE(0x003C) 수집
    next_off = end
    while next_off + 4 <= len(wb):
        next_op, next_len = struct.unpack_from("<HH", wb, next_off)
        if next_op != 0x003C:
            break
        payloads.append(wb[next_off+4: next_off+4+next_len])
        next_off += 4 + next_len

    pos = 0  # 첫 payload 내 오프셋
    red = 0

    while pos < len(payloads[0]):
        x = XLUCS()
        # 문자열 파싱 시도
        if not x.try_parse_at(payloads, 0, pos):
            pos += 1
            continue

        # 문자열 복원 및 디버깅
        text = x.decode_text(single_byte_codec).strip()
        print(f"[DEBUG] opcode text candidate: {repr(text)} (len={len(text)} fHigh={x.fHigh})")

        # 민감정보 매칭
        if text and find_sensitive_spans(normalization_text(text)):
            print(f"[DEBUG!!!] match found in: {repr(text)}")

            # 동일 길이 마스킹 생성
            masked = ("*" * len(text)).encode("utf-16le" if x.fHigh else single_byte_codec)
            masked = masked[:x.text_hi - x.text_lo].ljust(x.text_hi - x.text_lo, b'*')

            # 여러 payload에 걸쳐 나눠 쓰기
            remain = len(masked)
            to_write = memoryview(masked)
            for i, seg in enumerate(payloads):
                if remain <= 0:
                    break
                # 첫 payload는 text_lo부터, 이후 CONTINUE는 0부터 시작
                write_pos = x.text_lo if i == 0 else 0
                can = min(remain, max(0, len(seg) - write_pos))
                if can > 0:
                    seg[write_pos:write_pos + can] = to_write[:can]
                    to_write = to_write[can:]
                    remain -= can

            print(f"[DEBUG] wrote {len(masked)} bytes across {len(payloads)} payloads (remain={remain})")
            red += 1

        # 다음 문자열 시작 위치로 이동 
        header_len = 3 + (2 if (x.flags & 0x08) else 0) + (4 if (x.flags & 0x04) else 0)
        text_bytes = x.cch * (2 if x.fHigh else 1)
        total_len = header_len + text_bytes + (x.cRun * 4 if hasattr(x, "cRun") else 0) + (x.cbExtRst if hasattr(x, "cbExtRst") else 0)
        next_pos = pos + total_len

        # 혹시라도 계산 상 전진이 없으면 1바이트 전진
        if next_pos <= pos:
            next_pos = pos + 1
        pos = next_pos

    # 첫 payload를 실제 wb에 반영
    wb[payload_off:end] = payloads[0]
    # 이어지는 CONTINUE들도 wb에 반영
    cur = end
    for k in range(1, len(payloads)):
        op, ln = struct.unpack_from("<HH", wb, cur)
        wb[cur+4:cur+4+ln] = payloads[k]
        cur += 4 + ln

    # fallback: ASCII/UTF-16 패턴 기반 마스킹
    if red == 0:
        red += fallback_redact(wb, payload_off, end - payload_off, single_byte_codec)

    return red



# ─────────────────────────────
# BIFF 스트림 전체 처리
# ─────────────────────────────
def redact_biff_stream(biff_bytes: bytes, single_byte_codec="cp949") -> bytes:
    wb = bytearray(biff_bytes)
    total = 0
    for rec_off, opcode, length, payload in iter_biff_records(wb):
        if opcode in CHART_STRING_LIKE and length > 0:
            print(f"[REC] opcode=0x{opcode:04X} len={length}")
            try:
                cnt = scan_and_redact_payload(wb, rec_off+4, length, single_byte_codec)
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
def redact_workbooks(file_bytes: bytes, single_byte_codec="cp949") -> bytes:
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

