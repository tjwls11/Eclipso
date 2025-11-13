import io, os, re, struct, tempfile, olefile
from typing import Optional, List, Tuple
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
        yield off - 4, opcode, length, payload
        off += length; idx += 1


def coalesce_with_continue(biff_bytes: bytes, off: int) -> Tuple[bytes, List[Tuple[int, int]], int]:
    merged = b''
    segs = []
    n = len(biff_bytes)
    cur_off = off
    while cur_off + 4 <= n:
        op, length = struct.unpack_from("<HH", biff_bytes, cur_off)
        if op == 0x003C and not segs:
            break
        payload_off = cur_off + 4
        payload = biff_bytes[payload_off:payload_off+length]
        merged += payload
        segs.append((payload_off, payload_off+length))
        cur_off += 4 + length
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
                take = avail - (avail % (2 if cur_fHigh else 1))
                if take > 0:
                    text_bytes.extend(cur_payload[pos_in_record:pos_in_record+take])
                    chars_remain -= (take // (2 if cur_fHigh else 1))
                i += 1
                if i >= len(payloads): break
                cur_payload   = payloads[i]
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
# EPRINT 레닥션 부분
# ─────────────────────────────
EMR_EXTTEXTOUTA  = 0x53
EMR_EXTTEXTOUTW  = 0x54
EMR_POLYTEXTOUTA = 0x60
EMR_POLYTEXTOUTW = 0x61
EMR_SMALLTEXTOUT = 0x6C


# EMF 레코드 반복
def iter_emf_records(data: bytearray):
    off = 0
    n = len(data)
    while off + 8 <= n:
        rec_type = le32(data, off)
        rec_size  = le32(data, off + 4)
        if rec_size <= 0 or off + rec_size > n:
            break  # 손상
        payload_off = off + 8
        payload = data[payload_off: off + rec_size]
        yield off, rec_type, rec_size, payload
        off += rec_size


def parse_emr_polytextout(emf: bytearray, rec_off: int, rec_size: int, is_unicode: bool):
    base = rec_off

    size = le32(emf, base+4)
    if size != rec_size:
        return []

    pos = base + 8

    # Bounds(16)
    pos += 16

    # iGraphicsMode(4), exScale(4), eyScale(4)
    pos += 12

    # cStrings(4)
    cStrings = le32(emf, pos); pos += 4

    segments = []
    ETO_NO_RECT = 0x100

    for _ in range(cStrings):
        # Reference POINTL (8)
        pos += 8

        chars = le32(emf, pos); pos += 4
        offString = le32(emf, pos); pos += 4
        options = le32(emf, pos); pos += 4

        # Rectangle 존재 여부
        if not (options & ETO_NO_RECT):
            pos += 16

        # offDx
        pos += 4

        if chars == 0 or offString == 0:
            continue

        if is_unicode:
            bpc = 2
            encoding = "utf-16le"
        else:
            bpc = 1
            encoding = "cp949"

        str_start = base + offString
        str_len = chars * bpc
        str_end = str_start + str_len

        if not (base <= str_start < str_end <= base + rec_size):
            continue

        segments.append((str_start, str_len, encoding))

    return segments


def parse_emr_smalltextout(emf: bytearray, rec_off: int, rec_size: int):
    base = rec_off

    rec_type = le32(emf, base)
    size = le32(emf, base+4)
    if rec_type != EMR_SMALLTEXTOUT or size != rec_size:
        return None

    pos = base + 8

    x = le32(emf, pos); pos += 4
    y = le32(emf, pos); pos += 4
    cChars = le32(emf, pos); pos += 4
    fuOptions = le32(emf, pos); pos += 4
    iGraphicsMode = le32(emf, pos); pos += 4

    # exScale, eyScale
    pos += 8

    ETO_NO_RECT = 0x100
    if not (fuOptions & ETO_NO_RECT):
        pos += 16

    ETO_SMALL_CHARS = 0x8000

    text_start = pos

    if fuOptions & ETO_SMALL_CHARS:
        byte_len = cChars
        encoding = "cp949"  #ASCII라고 나와있긴 한데 일단 cp949로 처리
    else:
        byte_len = cChars * 2
        encoding = "utf-16le"

    if text_start + byte_len > base + rec_size:
        return None

    return (text_start, byte_len, encoding)




def redact_emr_block(emf: bytearray, rec_off: int, is_unicode: bool) -> int:
    rec_type = le32(emf, rec_off)
    rec_size = le32(emf, rec_off + 4)

    emrtext_off = rec_off + 0x24
    if emrtext_off + 8 > rec_off + rec_size:
        return 0

    chars = le32(emf, emrtext_off + 8)
    off_string = le32(emf, emrtext_off + 12)

    if chars == 0 or off_string == 0:
        return 0

    str_start = rec_off + off_string
    bpc = 2 if is_unicode else 1
    str_bytes_len = chars * bpc
    str_end = str_start + str_bytes_len

    rec_end = rec_off + rec_size
    if str_end > rec_end:
        return 0

    raw = bytes(emf[str_start:str_end])
    enc = "utf-16le" if is_unicode else "cp949"

    try:
        text = raw.decode(enc, errors="ignore")
    except:
        return 0

    norm = normalization_text(text)
    if not find_sensitive_spans(norm):
        return 0

    redacted = ("*" * len(text)).encode(enc)
    redacted = redacted[:len(raw)].ljust(len(raw), b'*')

    emf[str_start:str_end] = redacted
    print(f"[EMR] redacted text: {repr(text)} at 0x{str_start:08X}")
    return 1



def redact_emf_stream(emf_bytes: bytes) -> bytes:
    emf = bytearray(emf_bytes)
    total = 0

    for rec_off, rec_type, rec_size, payload in iter_emf_records(emf):
        
        # 1) EXTTEXTOUT(A/W)
        if rec_type == EMR_EXTTEXTOUTA:
            total += redact_emr_block(emf, rec_off, False)

        elif rec_type == EMR_EXTTEXTOUTW:
            total += redact_emr_block(emf, rec_off, True)


        # 2) POLYTEXTOUT 계열
        elif rec_type in (EMR_POLYTEXTOUTA, EMR_POLYTEXTOUTW):
            is_unicode = (rec_type == EMR_POLYTEXTOUTW)
            segs = parse_emr_polytextout(emf, rec_off, rec_size, is_unicode)

            for start, length, enc in segs:
                raw = bytes(emf[start:start+length])

                try:
                    text = raw.decode(enc, errors="ignore")
                except:
                    continue

                if find_sensitive_spans(normalization_text(text)):
                    red = ("*" * len(text)).encode(enc)
                    red = red[:length].ljust(length, b'*')
                    emf[start:start+length] = red
                    total += 1
                    print(f"[EMR-POLY] redacted {repr(text)} at 0x{start:08X}")


        # 3) SMALLTEXTOUT (0x6C)
        elif rec_type == EMR_SMALLTEXTOUT:
            seg = parse_emr_smalltextout(emf, rec_off, rec_size)
            if seg:
                start, length, enc = seg
                raw = bytes(emf[start:start+length])

                try:
                    text = raw.decode(enc, errors="ignore")
                except:
                    continue

                if find_sensitive_spans(normalization_text(text)):
                    red = ("*" * len(text)).encode(enc)
                    red = red[:length].ljust(length, b'*')
                    emf[start:start+length] = red
                    total += 1
                    print(f"[EMR-SMALL] redacted {repr(text)} at 0x{start:08X}")

    if total:
        print(f"[EMR] total {total} text(s) redacted in EMF")
    else:
        print("[EMR] no redactions in EMF")

    return bytes(emf)


# ─────────────────────────────
# 메인 스캔 함수
# ─────────────────────────────
CHART_STRING_LIKE = {0x0004, 0x041E, 0x100D, 0x1025, 0x104B, 0x105C, 0x1024, 0x1026}

def scan_and_redact_payload(wb: bytearray, payload_off: int, length: int, single_byte_codec="cp949") -> int:
    end = payload_off + length
    payloads = [wb[payload_off:end]]

    next_off = end
    while next_off + 4 <= len(wb):
        next_op, next_len = struct.unpack_from("<HH", wb, next_off)
        if next_op != 0x003C:
            break
        payloads.append(wb[next_off+4: next_off+4+next_len])
        next_off += 4 + next_len

    pos = 0
    red = 0

    while pos < len(payloads[0]):
        x = XLUCS()

        if not x.try_parse_at(payloads, 0, pos):
            pos += 1
            continue

        text = x.decode_text(single_byte_codec).strip()
        print(f"[DEBUG] opcode text candidate: {repr(text)} (len={len(text)} fHigh={x.fHigh})")

        if text and find_sensitive_spans(normalization_text(text)):
            print(f"[DEBUG!!!] match found in: {repr(text)}")

            masked = ("*" * len(text)).encode("utf-16le" if x.fHigh else single_byte_codec)
            masked = masked[:x.text_hi - x.text_lo].ljust(x.text_hi - x.text_lo, b'*')

            remain = len(masked)
            to_write = memoryview(masked)
            for i, seg in enumerate(payloads):
                if remain <= 0:
                    break
                write_pos = x.text_lo if i == 0 else 0
                can = min(remain, max(0, len(seg) - write_pos))
                if can > 0:
                    seg[write_pos:write_pos + can] = to_write[:can]
                    to_write = to_write[can:]
                    remain -= can

            print(f"[DEBUG] wrote {len(masked)} bytes across {len(payloads)} payloads (remain={remain})")
            red += 1

        header_len = 3
        if x.flags & 0x08:
            header_len += 2
        if x.flags & 0x04:
            header_len += 4

        text_bytes = x.cch * (2 if x.fHigh else 1)
        pos += max(1, header_len + text_bytes)

    wb[payload_off:end] = payloads[0]

    cur = end
    for k in range(1, len(payloads)):
        op, ln = struct.unpack_from("<HH", wb, cur)
        wb[cur+4:cur+4+ln] = payloads[k]
        cur += 4 + ln

    if red == 0:
        red += fallback_redact(wb, payload_off, end - payload_off, single_byte_codec)

    return red


# ─────────────────────────────
# BIFF 전체 처리
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
    return bytes(wb)


# ─────────────────────────────
# Workbook 처리 (BIFF + EPRINT)
# ─────────────────────────────
def redact_workbooks(file_bytes: bytes, single_byte_codec="cp949") -> bytes:
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            modified = file_bytes

            for entry in ole.listdir():
                if len(entry) < 2:
                    continue

                top = entry[0]
                name = entry[-1]

                # 1) Workbook
                if top == "ObjectPool" and name in ("Workbook", "\x01Workbook"):
                    path_str = "/".join(entry)
                    print(f"[INFO] found Workbook stream: {path_str}")
                    wb_data = ole.openstream(entry).read()

                    new_biff = redact_biff_stream(wb_data, single_byte_codec)

                    if new_biff != wb_data:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
                            tmp.write(modified)
                            temp_path = tmp.name

                        with olefile.OleFileIO(temp_path, write_mode=True) as olew:
                            olew.write_stream(path_str, new_biff)
                            print(f"  [WRITE] replaced Workbook: {path_str}")

                        with open(temp_path,"rb") as f:
                            modified = f.read()
                        os.remove(temp_path)

                # 2) EPRINT
                if top == "ObjectPool" and name == "\x03EPRINT":
                    path_str = "/".join(entry)
                    print(f"[INFO] found EPRINT stream: {path_str}")
                    emf_data = ole.openstream(entry).read()

                    new_emf = redact_emf_stream(emf_data)

                    if new_emf != emf_data:
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
                            tmp.write(modified)
                            temp_path = tmp.name

                        with olefile.OleFileIO(temp_path, write_mode=True) as olew:
                            olew.write_stream(path_str, new_emf)
                            print(f"  [WRITE] replaced EPRINT: {path_str}")

                        with open(temp_path,"rb") as f:
                            modified = f.read()
                        os.remove(temp_path)

            return modified

    except Exception as e:
        print(f"[ERR] redact_workbooks exception: {e}")
        return file_bytes
