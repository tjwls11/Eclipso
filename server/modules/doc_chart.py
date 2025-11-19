import io, os, re, struct, tempfile, olefile
from typing import Optional, List, Tuple
from server.core.normalize import normalization_text
from server.core.matching import find_sensitive_spans


def le16(b, off):
    return struct.unpack_from("<H", b, off)[0]

def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]


# BIFF 레코드 반복자
def iter_biff_records(data: bytes):
    off, n = 0, len(data)

    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        off += 4
        payload = data[off:off + length]
        yield off - 4, opcode, length, payload
        off += length


# TEXT 계열 레코드 + CONTINUE 조각 모으기
def collect_continue_chuncks(biff: bytes, off: int):
    chunks: List[bytes] = []
    segs: List[Tuple[int, int]] = []

    cur_off = off
    n = len(biff)

    # first TEXT_LIKE payload
    op, ln = struct.unpack_from("<HH", biff, cur_off)
    # 첫 레코드가 CONTINUE면 비정상
    if op == 0x003C:
        return [], []

    payload_off = cur_off + 4
    payload_end = payload_off + ln
    chunks.append(biff[payload_off:payload_end])
    segs.append((payload_off, payload_end))

    cur_off = payload_end

    # CONTINUE 레코드들 이어서 수집
    while cur_off + 4 <= n:
        op, ln = struct.unpack_from("<HH", biff, cur_off)
        if op != 0x003C:  # CONTINUE 아님 → 종료
            break

        payload_off = cur_off + 4
        payload_end = payload_off + ln

        chunks.append(biff[payload_off:payload_end])
        segs.append((payload_off, payload_end))

        cur_off = payload_end

    return chunks, segs


# 여러 청크를 하나의 연속 버퍼처럼 읽기
def read_bytes_fChunks(chunks: List[bytes], pos: int, need: int) -> Optional[bytes]:
    out = bytearray()
    ch_idx = 0
    local = pos  # 논리 오프셋

    # pos 가 속한 청크 찾기
    while ch_idx < len(chunks):
        if local < len(chunks[ch_idx]):
            break
        local -= len(chunks[ch_idx])
        ch_idx += 1

    if ch_idx >= len(chunks):
        return None

    # need 바이트 채울 때까지 이어 붙이기
    while ch_idx < len(chunks) and len(out) < need:
        remain_chunk = len(chunks[ch_idx]) - local
        take = min(need - len(out), remain_chunk)
        out.extend(chunks[ch_idx][local:local+take])
        ch_idx += 1
        local = 0

    if len(out) < need:
        return None

    return bytes(out)


class XLUCS:
    __slots__ = (
        "cch", "flags", "fHigh", "fExt", "fRich",
        "cRun", "cbExtRst",
        "text_lo", "text_hi",  # 시작 offset, 끝 offset
        "buf", "chunks"
    )

    def try_parse_chunks(self, chunks: List[bytes], pos: int) -> bool:
        # 최소 3바이트( cch(2) + flags(1) )
        n_header = read_bytes_fChunks(chunks, pos, 3)
        if n_header is None:
            return False

        cch = le16(n_header, 0)
        flags = n_header[2]

        fHigh = flags & 0x01        # 0: 1바이트 코드페이지, 1: UTF-16LE
        fExt  = (flags >> 2) & 0x01 # ExtRst 존재 여부
        fRich = (flags >> 3) & 0x01 # Rich Text Run 존재 여부

        pos_cur = pos + 3

        # Rich Text Run 개수
        cRun = 0
        if fRich:
            raw = read_bytes_fChunks(chunks, pos_cur, 2)
            if raw is None:
                return False
            cRun = le16(raw, 0)
            pos_cur += 2

        # ExtRst 길이
        cbExtRst = 0
        if fExt:
            raw = read_bytes_fChunks(chunks, pos_cur, 4)
            if raw is None:
                return False
            cbExtRst = le32(raw, 0)
            pos_cur += 4

        # 본문 텍스트
        bpc = 2 if fHigh else 1
        text_bytes = cch * bpc

        raw_text = read_bytes_fChunks(chunks, pos_cur, text_bytes)
        if raw_text is None:
            return False

        # 필드 세팅
        self.cch      = cch
        self.flags    = flags
        self.fHigh    = fHigh
        self.fExt     = fExt
        self.fRich    = fRich
        self.cRun     = cRun
        self.cbExtRst = cbExtRst

        # 텍스트의 논리 오프셋(시작/끝)
        self.text_lo = pos_cur
        self.text_hi = pos_cur + text_bytes  # 끝 offset

        self.buf    = bytearray(raw_text)
        self.chunks = chunks

        return True

    def decode_text(self, single_bytes_enc: str = "cp949") -> str:
        raw = bytes(self.buf)

        # fHigh=0 인데도 사실상 UTF-16 패턴인 경우 방어
        if not self.fHigh and len(raw) >= 4 and raw[1] == 0x00 and raw[3] == 0x00:
            enc = "utf-16le"
        else:
            enc = "utf-16le" if self.fHigh else single_bytes_enc

        return raw.decode(enc, errors="ignore")


# ─────────────────────────────
# 차트 텍스트 추출 (UI용)
# ─────────────────────────────

CHART_STRING_LIKE = {0x100D, 0x1025, 0x0004}


def extract_chart_text(file_bytes: bytes, single_byte_enc: str = "cp949") -> List[str]:
    texts: List[str] = []

    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            for entry in ole.listdir():
                if len(entry) < 2:
                    continue

                top = entry[0]
                name = entry[-1]

                if top == "ObjectPool" and name in ("Workbook", "\x01Workbook"):
                    wb_data = ole.openstream(entry).read()
                    wb = bytearray(wb_data)

                    for rec_off, opcode, length, _payload in iter_biff_records(wb):
                        if opcode not in CHART_STRING_LIKE or length <= 0:
                            continue

                        # TEXT + CONTINUE 조각을 모아서 하나의 논리 스트림처럼 다룸
                        chunks, _segs = collect_continue_chuncks(wb, rec_off)
                        if not chunks:
                            continue

                        total_len = sum(len(c) for c in chunks)
                        pos = 0

                        while pos < total_len:
                            x = XLUCS()
                            if not x.try_parse_chunks(chunks, pos):
                                pos += 1
                                continue

                            txt = x.decode_text(single_byte_enc).strip()
                            if txt:
                                texts.append(txt)

                            # 다음 문자열까지 건너뛰기
                            header_len = 3
                            if x.fRich:
                                header_len += 2
                                header_len += x.cRun * 4
                            if x.fExt:
                                header_len += 4
                                header_len += x.cbExtRst

                            text_bytes = x.cch * (2 if x.fHigh else 1)
                            advance = header_len + text_bytes
                            pos += advance

                # EPRINT는 여기서는 추출 안 함 (별도 EMF 파서 사용)
                if top == "ObjectPool" and name == "\x03EPRINT":
                    pass

    except Exception as e:
        print(f"[ERR] extract_chart_text: {e}")

    return texts


# ─────────────────────────────
# 차트 XLUCS 레닥션 관련 유틸
# ─────────────────────────────

def write_chunk_mask(chunks: List[bytearray], lo: int, masked: bytes):
    remain = len(masked)
    ch_idx = 0
    local = lo

    # lo가 속한 청크 찾기
    while ch_idx < len(chunks) and local >= len(chunks[ch_idx]):
        local -= len(chunks[ch_idx])
        ch_idx += 1

    while ch_idx < len(chunks) and remain > 0:
        take = min(remain, len(chunks[ch_idx]) - local)
        chunks[ch_idx][local:local+take] = masked[:take]
        masked = masked[take:]
        remain -= take
        ch_idx += 1
        local = 0


def fallback_redact(buf: bytearray, single_byte_enc="cp949") -> int:
    seg = buf[:]  # 검색용 복사본

    patterns = [
        (re.compile(rb"[ -~]{5,}"), single_byte_enc),           # ASCII 5자 이상
        (re.compile(rb"(?:[\x20-\x7E]\x00){5,}"), "utf-16le"),  # UTF-16LE 5자 이상
    ]

    red = 0

    for pat, enc in patterns:
        for m in pat.finditer(seg):
            seq = m.group(0)
            try:
                text = seq.decode(enc, errors="ignore")
                if not text.strip():
                    continue

                if find_sensitive_spans(normalization_text(text)):
                    if enc == "utf-16le":
                        repl = ("*" * len(text)).encode("utf-16le")
                        repl = repl[:len(seq)]
                    else:
                        repl = b"*" * len(seq)

                    s, e = m.start(), m.end()
                    buf[s:e] = repl
                    red += 1
            except Exception:
                pass

    return red


def write_back_fallback(chunks: List[bytearray], fb_buf: bytearray):
    p = 0
    for i, c in enumerate(chunks):
        ln = len(c)
        chunks[i] = bytearray(fb_buf[p:p+ln])
        p += ln


def write_chunks_back_to_wb(wb: bytearray, chunks: List[bytearray], segs: List[Tuple[int, int]]):
    merged = b"".join(chunks)
    p = 0
    for lo, hi in segs:
        ln = hi - lo
        wb[lo:hi] = merged[p:p+ln]
        p += ln


def scan_and_redact_payload(wb: bytearray, payload_off: int, length: int, single_byte_codec="cp949") -> int:
    rec_off = payload_off - 4

    # TEXT + CONTINUE 레코드 조각 모으기
    chunks_bytes, segs = collect_continue_chuncks(wb, rec_off)
    if not chunks_bytes:
        return 0

    # bytearray 로 변환
    chunks: List[bytearray] = [bytearray(c) for c in chunks_bytes]

    total_len = sum(len(c) for c in chunks)
    pos = 0
    red = 0

    while pos < total_len:
        x = XLUCS()
        if not x.try_parse_chunks(chunks, pos):
            pos += 1
            continue

        text = x.decode_text(single_byte_codec).strip()

        if text and find_sensitive_spans(normalization_text(text)):
            print(f"[MERGED-CHUNK] matched: {repr(text)} at pos={pos}")

            enc = "utf-16le" if x.fHigh else single_byte_codec
            masked = ("*" * len(text)).encode(enc)
            raw_len = x.text_hi - x.text_lo  # 실제 텍스트 바이트 길이
            masked = masked[:raw_len].ljust(raw_len, b'*')

            write_chunk_mask(chunks, x.text_lo, masked)
            red += 1

        header_len = 3
        if x.fRich:
            header_len += 2
            header_len += x.cRun * 4
        if x.fExt:
            header_len += 4
            header_len += x.cbExtRst

        text_bytes = x.cch * (2 if x.fHigh else 1)
        advance = header_len + text_bytes

        pos += advance

    # XLUCS 기반에서 아무 것도 못 찾았으면 fallback
    if red == 0:
        fb_buf = bytearray(b"".join(chunks))
        fb = fallback_redact(fb_buf, single_byte_codec)
        print("[FALLBACK ! ! !]")
        red += fb
        if fb > 0:
            write_back_fallback(chunks, fb_buf)

    write_chunks_back_to_wb(wb, chunks, segs)

    return red


def redact_biff_stream(biff_bytes: bytes, single_byte_codec="cp949") -> bytes:
    wb = bytearray(biff_bytes)
    total = 0

    for rec_off, opcode, length, payload in iter_biff_records(wb):
        if opcode in CHART_STRING_LIKE and length > 0:
            print(f"[REC] opcode=0x{opcode:04X} len={length}")
            try:
                cnt = scan_and_redact_payload(wb, rec_off + 4, length, single_byte_codec)
                total += cnt
                print(f"[CHART] opcode=0x{opcode:04X} → {cnt} texts redacted")
            except Exception as e:
                print(f"[WARN] opcode=0x{opcode:04X} exception: {e}")

    if total:
        print(f"[CHART] total {total} strings redacted")
    else:
        print("[CHART] no redactions")

    return bytes(wb)


# ───────────────────────────────────────────────
# EPRINT (EMF) 레닥션
# ───────────────────────────────────────────────

EMR_EXTTEXTOUTA  = 0x53
EMR_EXTTEXTOUTW  = 0x54
EMR_POLYTEXTOUTA = 0x60
EMR_POLYTEXTOUTW = 0x61
EMR_SMALLTEXTOUT = 0x6C


def iter_emf_records(data: bytearray):
    off = 0
    n = len(data)

    while off + 8 <= n:
        rec_type = le32(data, off)
        rec_size = le32(data, off + 4)

        if rec_size <= 0 or off + rec_size > n:
            break

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

    # Bounds RECT
    pos += 16

    # iGraphicsMode(4), exScale(4), eyScale(4)
    pos += 12

    cStrings = le32(emf, pos)
    pos += 4

    segments = []
    ETO_NO_RECT = 0x100

    for _ in range(cStrings):
        pos += 8  # POINTL

        chars = le32(emf, pos); pos += 4
        offString = le32(emf, pos); pos += 4
        options = le32(emf, pos); pos += 4

        if not (options & ETO_NO_RECT):
            pos += 16

        pos += 4  # offDx

        if chars == 0 or offString == 0:
            continue

        if is_unicode:
            bpc = 2
            encoding = "utf-16le"
        else:
            bpc = 1
            encoding = "cp949"

        str_start = base + offString
        str_len   = chars * bpc
        str_end   = str_start + str_len

        if not (base <= str_start < str_end <= base + rec_size):
            continue

        segments.append((str_start, str_len, encoding))

    return segments


def parse_emr_smalltextout(emf: bytearray, rec_off: int, rec_size: int):
    base = rec_off

    rec_type = le32(emf, base)
    size     = le32(emf, base+4)

    if rec_type != EMR_SMALLTEXTOUT or size != rec_size:
        return None

    pos = base + 8

    x = le32(emf, pos); pos += 4
    y = le32(emf, pos); pos += 4

    cChars     = le32(emf, pos); pos += 4
    fuOptions  = le32(emf, pos); pos += 4
    graphics   = le32(emf, pos); pos += 4

    pos += 8   # exScale, eyScale

    ETO_NO_RECT     = 0x100
    ETO_SMALL_CHARS = 0x8000

    if not (fuOptions & ETO_NO_RECT):
        pos += 16

    text_start = pos

    if fuOptions & ETO_SMALL_CHARS:
        byte_len = cChars
        encoding = "cp949"
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

    chars      = le32(emf, emrtext_off + 8)
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
    except Exception:
        return 0

    if not find_sensitive_spans(normalization_text(text)):
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
        if rec_type == EMR_EXTTEXTOUTA:
            total += redact_emr_block(emf, rec_off, False)

        elif rec_type == EMR_EXTTEXTOUTW:
            total += redact_emr_block(emf, rec_off, True)

        elif rec_type in (EMR_POLYTEXTOUTA, EMR_POLYTEXTOUTW):
            is_unicode = (rec_type == EMR_POLYTEXTOUTW)
            segs = parse_emr_polytextout(emf, rec_off, rec_size, is_unicode)

            for start, length, enc in segs:
                raw = bytes(emf[start:start+length])

                try:
                    text = raw.decode(enc, errors="ignore")
                except Exception:
                    continue

                if find_sensitive_spans(normalization_text(text)):
                    red = ("*" * len(text)).encode(enc)
                    red = red[:length].ljust(length, b'*')
                    emf[start:start+length] = red
                    total += 1
                    print(f"[EMR-POLY] redacted {repr(text)} at 0x{start:08X}")

        elif rec_type == EMR_SMALLTEXTOUT:
            seg = parse_emr_smalltextout(emf, rec_off, rec_size)
            if seg:
                start, length, enc = seg
                raw = bytes(emf[start:start+length])

                try:
                    text = raw.decode(enc, errors="ignore")
                except Exception:
                    continue

                if find_sensitive_spans(normalization_text(text)):
                    red = ("*" * len(text)).encode(enc)
                    red = red[:length].ljust(length, b'*')
                    emf[start:start+length] = red
                    total += 1
                    print(f"[EMR-SMALL] redacted {repr(text)} at 0x{start:08X}")

    if total:
        print(f"[EMR OK] total {total} text(s) redacted in EMF")
    else:
        print("[EMR ERR] no redactions in EMF")

    return bytes(emf)


# ───────────────────────────────────────────────
# 차트 부분 전체 처리
# ───────────────────────────────────────────────
def redact_workbooks(file_bytes: bytes, single_byte_codec="cp949") -> bytes:
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            modified = file_bytes

            for entry in ole.listdir():
                if len(entry) < 2:
                    continue

                top = entry[0]
                name = entry[-1]

                # 1) Workbook(BIFF) 레닥션
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

                        with open(temp_path, "rb") as f:
                            modified = f.read()
                        os.remove(temp_path)

                # 2) EPRINT(EMF) 레닥션
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

                        with open(temp_path, "rb") as f:
                            modified = f.read()
                        os.remove(temp_path)

            return modified

    except Exception as e:
        print(f"[ERR] redact_workbooks exception: {e}")
        return file_bytes
