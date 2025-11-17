import io, os, re, struct, tempfile, olefile
from typing import Optional, List, Tuple
from server.core.normalize import normalization_text
from server.core.matching import find_sensitive_spans


def le16(b, off):
    return struct.unpack_from("<H", b, off)[0]

def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]


#biff 레코드 반복자
def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    
    while off + 4 <= n:
        #record 헤더 읽기
        opcode, length = struct.unpack_from("<HH", data, off)

        # 페이로드 시작 위치로 이동
        off += 4
        payload = data[off:off + length]

        yield off -4, opcode, length, payload # record 반환

        off += length


# Continue 레코드 병합
def coalesce_continue(biff_bytes: bytes, off: int) -> Tuple[bytes, List[Tuple[int, int]], int]:
    merged = b'' # 병합된 페이로드 저장
    segs: List[Tuple[int, int]] = [] # (시작, 길이) 세그먼트 리스트
    n = len(biff_bytes) # 전체 길이
    cur_off = off # 현재 오프셋

    while cur_off + 4 <= n:
        op, length = struct.unpack_from("<HH", biff_bytes, cur_off) # 헤더읽기

        #첫 레코드가 Continue -> 비정상
        if op == 0x003C and not segs:
            break

        # 실제 페이로드 범위
        payload_off = cur_off + 4
        payload_end = payload_off + length
        payload = biff_bytes[payload_off:payload_end]

        # 병합 데이터에 append
        merged += payload
        segs.append((payload_off, payload_end))
        
        cur_off = payload_end

        if cur_off + 4 > n:
            break

        next_op = struct.unpack_from("<H", biff_bytes, cur_off)[0]

        if next_op != 0x003C:  # Continue 레코드가 아니면 종료
            break
    
    return merged, segs, cur_off


# XLUCS 가 청크 단위로 넘나들기 위한 함수
def collect_continue_chuncks(biff: bytes, off: int):
    chunks = []
    segs = []

    cur_off = off
    n = len(biff)

    # first TEXT_LIKE payload 
    op, ln = struct.unpack_from("<HH", biff, cur_off)
    if op == 0x003C:
        return [], []
    
    payload_off = cur_off + 4
    payload_end = payload_off + ln
    chunks.append(biff[payload_off:payload_end])
    segs.append((payload_off, payload_end))

    cur_off = payload_end
    
    # continue 탐색
    while cur_off + 4 <= n:
        op, ln = struct.unpack_from("<HH", biff, cur_off)
        if op != 0x003C:
            break

        payload_off = cur_off + 4
        payload_end = payload_off + ln

        chunks.append(biff[payload_off:payload_end])
        segs.append((payload_off, payload_end))

        cur_off = payload_end
    
    return chunks, segs


# 청크 전체를 하나의 연속된 버퍼처럼 봐 pos 부터 need 바이트 모아서 반환
def read_bytes_fChunks(chunks: List[bytes], pos: int, need: int) -> Optional[bytes]:
    out = bytearray()
    ch_idx = 0    # 현재 청크 인덱스
    local = pos   # 해당 청크 내부 offset

    while ch_idx < len(chunks):
        if local < len(chunks[ch_idx]):
            break
        local -= len(chunks[ch_idx])
        ch_idx += 1

    if ch_idx >= len(chunks):
        return None
    
    # need 바이트 채울때까지 여러 청크에서 이어 붙이기
    while ch_idx < len(chunks) and len(out) < need:
        remain_chunk = len(chunks[ch_idx]) - local
        take = min(need - len(out), remain_chunk)
        out.extend(chunks[ch_idx][local:local+take])
        ch_idx += 1
        local = 0 #다음 청크부터는 0부터 시작

    if len(out) < need:
        return None
    
    return bytes(out)



class XLUCS:
    __slots__ = ("cch", "flags", "fHigh", "fExt", "fRich", "cRun", "cbExtRst", "text_lo", "text_hi", "buf", "chunks")

    def try_parse_chunks(self, chunks: List[bytes], pos: int) -> bool:
        n_header = read_bytes_fChunks(chunks, pos, 3)
        if n_header is None:
            return False 
        
        cch = le16(n_header, 0)
        flags = n_header[2]

        fHigh = flags & 0x01        # 인코딩 플래그
        fExt = (flags >> 2) & 0x01  # ExtRst
        fRich = (flags >> 3) & 0x01 # Rich Text Run

        pos_cur = pos + 3

        #Rich Text Run 개수
        cRun = 0
        if fRich: 
            raw = read_bytes_fChunks(chunks, pos_cur, 2)
            if raw is None:
                return False
            cRun = le16(raw, 0)
            pos_cur += 2

        #ExtRst 길이
        cbExtRst = 0 
        if fExt:
            raw = read_bytes_fChunks(chunks, pos_cur, 4)
            if raw is None:
                return False
            cbExtRst = le32(raw, 0)
            pos_cur += 4


        # 본문
        bpc = 2 if fHigh else 1
        text_bytes = cch * bpc

        raw_text = read_bytes_fChunks(chunks, pos_cur, text_bytes)
        if raw_text is None:
            return False

        # 필드 셋팅
        self.cch      = cch
        self.flags    = flags
        self.fHigh    = fHigh
        self.fExt     = fExt
        self.fRich    = fRich
        self.cRun     = cRun
        self.cbExtRst = cbExtRst

        # offset 기준으로 텍스트 위치와 길이 기록
        self.text_lo = pos_cur    # 시작 오프셋
        self.text_hi = pos_cur + text_bytes # 길이

        # 디코딩을 위해 raw는 buf에 저장
        self.buf = bytearray(raw_text)
        self.chunks = chunks

        return True

    def decode_text(self, single_bytes_enc: str = "cp949") -> str:
        raw = bytes(self.buf)

        if not self.fHigh and len(raw) >= 4 and raw[1] == 0x00 and raw[3] == 0x00:
            enc = "utf-16le"
        else:
            enc = "utf-16le" if self.fHigh else single_bytes_enc
        
        return raw.decode(enc, errors="ignore")



def extract_chart_text(file_bytes: bytes, single_byte_enc="cp949") -> List[str]:
    texts = []

    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:

            for entry in ole.listdir():
                if len(entry) < 2:
                    continue

                top = entry[0]
                name = entry[-1]

                # Workbook(BIFF)
                if top == "ObjectPool" and name in ("Workbook", "\x01Workbook"):
                    wb_data = ole.openstream(entry).read()
                    wb = bytearray(wb_data)

                    # BIFF 순회
                    for rec_off, opcode, length, payload in iter_biff_records(wb):
                        if opcode not in CHART_STRING_LIKE:
                            continue

                        # CONTINUE 포함 전체 청크 수집
                        chunks, segs = collect_continue_chuncks(wb, rec_off)
                        if not chunks:
                            continue

                        total_len = sum(len(c) for c in chunks)
                        pos = 0

                        while pos < total_len:
                            x = XLUCS()

                            # CHUNKS 기반 파서
                            if not x.try_parse_chunks(chunks, pos):
                                pos += 1
                                continue

                            text = x.decode_text(single_byte_enc).strip()
                            if text:
                                texts.append(text)

                            # advance 계산 로직
                            header_len = 3
                            if x.fRich:
                                header_len += 2 + x.cRun * 4
                            if x.fExt:
                                header_len += 4 + x.cbExtRst

                            text_bytes = x.cch * (2 if x.fHigh else 1)
                            advance = header_len + text_bytes

                            pos += advance

                if top == "ObjectPool" and name == "\x03EPRINT":
                    pass

    except Exception as e:
        print(f"[ERR] extract_chart_text: {e}")

    return texts


def write_chunk_mask(chunks, lo, masked):
    remain = len(masked)
    ch_idx = 0
    local = lo

    # local offset 계산
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
    seg = buf[:]  # 전체 buf에서 찾기

    patterns = [
        (re.compile(rb"[ -~]{5,}"), single_byte_enc),
        (re.compile(rb"(?:[\x20-\x7E]\x00){5,}"), "utf-16le"),
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
            except:
                pass
    
    return red



def write_back_fallback(chunks, fb_buf):
    p = 0
    for i, c in enumerate(chunks):
        ln = len(c)
        chunks[i] = bytearray(fb_buf[p:p+ln])
        p += ln


def write_chunks_back_to_wb(wb, chunks, segs):
    merged = b"".join(chunks)
    p = 0
    for lo, hi in segs:
        ln = hi - lo
        wb[lo:hi] = merged[p:p+ln]
        p += ln



CHART_STRING_LIKE = {0x100D, 0x1025, 0x0004}
def scan_and_redact_payload(wb: bytearray, payload_off: int, length: int, single_byte_codec="cp949") -> int:
    rec_off = payload_off - 4

    # TEXT + CONTINUE 레코드 조각 모으기
    chunks, segs = collect_continue_chuncks(wb, rec_off)
    if not chunks:
        return 0

    # 전체길이 = 모든 chunks 길이 합
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
            raw_len = x.text_hi - x.text_lo
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

    # XLUCS에서 아무 것도 없었으면 fallback 실행
    if red == 0:
        # 청크 전체를 단일 버퍼처럼 보고 fallback
        fb_buf = bytearray(b"".join(chunks))
        fb = fallback_redact(fb_buf, single_byte_codec)
        red += fb

        if fb > 0:
            # fallback 마스킹을 chunks에 다시 분배
            write_back_fallback(chunks, fb_buf)

    write_chunks_back_to_wb(wb, chunks, segs)

    return red


def redact_biff_stream(biff_bytes: bytes, single_byte_codec="cp949") -> bytes:
    wb = bytearray(biff_bytes)
    total = 0

    # BIFF 전체 레코드 순회
    for rec_off, opcode, length, payload in iter_biff_records(wb):
        # 차트 관련 문자열 레코드만 처리
        if opcode in CHART_STRING_LIKE and length > 0:
            print(f"[REC] opcode=0x{opcode:04X} len={length}")
            try:
                # 이 레코드(payload) + CONTINUE 병합 → 문자열 레닥션
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


# ───────────────────────────────────────────────
# EPRINT 레닥션 
# ───────────────────────────────────────────────
EMR_EXTTEXTOUTA  = 0x53
EMR_EXTTEXTOUTW  = 0x54
EMR_POLYTEXTOUTA = 0x60
EMR_POLYTEXTOUTW = 0x61
EMR_SMALLTEXTOUT = 0x6C


# EMF 레코드 반복자
def iter_emf_records(data: bytearray):
    off = 0
    n = len(data)

    while off + 8 <= n:
        # EMR header: type(4) + size(4)
        rec_type = le32(data, off)
        rec_size = le32(data, off + 4)

        # size가 이상하거나 파일 끝을 초과하면 중단
        if rec_size <= 0 or off + rec_size > n:
            break

        payload_off = off + 8
        payload = data[payload_off: off + rec_size]

        yield off, rec_type, rec_size, payload

        off += rec_size



# PolyTextOut
def parse_emr_polytextout(emf: bytearray, rec_off: int, rec_size: int, is_unicode: bool):
    base = rec_off

    # rec_size 검증
    size = le32(emf, base+4)   # header size 로드
    if size != rec_size:
        return []

    pos = base + 8  # payload 시작

    # Bounds RECT
    pos += 16

    # iGraphicsMode(4), exScale(4), eyScale(4)
    pos += 12

    # cStrings: 문자열 블록 개수
    cStrings = le32(emf, pos)
    pos += 4

    segments = []
    ETO_NO_RECT = 0x100

    # 각 문자열 블록을 순회
    for _ in range(cStrings):
        # Reference POINTL
        pos += 8

        chars = le32(emf, pos); pos += 4       # 문자 개수
        offString = le32(emf, pos); pos += 4   # 문자열 시작 offset
        options = le32(emf, pos); pos += 4     # 옵션 플래그

        # 사각형 정보가 있는 경우 rect 영역 스킵
        if not (options & ETO_NO_RECT):
            pos += 16

        # offDx
        pos += 4

        # 문자열이 없으면 스킵
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

        # 레코드 내부 범위 검사
        if not (base <= str_start < str_end <= base + rec_size):
            continue

        segments.append((str_start, str_len, encoding))

    return segments




# EMR_SMALLTEXTOUT
def parse_emr_smalltextout(emf: bytearray, rec_off: int, rec_size: int):
    base = rec_off

    rec_type = le32(emf, base)
    size     = le32(emf, base+4)

    # 타입 또는 크기 불일치 시 None 반환
    if rec_type != EMR_SMALLTEXTOUT or size != rec_size:
        return None

    pos = base + 8

    # x, y 좌표(2x 4bytes)
    x = le32(emf, pos); pos += 4
    y = le32(emf, pos); pos += 4

    # cChars(4), fuOptions(4), iGraphicsMode(4)
    cChars     = le32(emf, pos); pos += 4
    fuOptions  = le32(emf, pos); pos += 4
    graphics   = le32(emf, pos); pos += 4

    # exScale(4) + eyScale(4)
    pos += 8

    ETO_NO_RECT       = 0x100
    ETO_SMALL_CHARS   = 0x8000

    # 사각형이 포함된 경우 skip
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



# EMR_EXTTEXTOUT
def redact_emr_block(emf: bytearray, rec_off: int, is_unicode: bool) -> int:
    rec_type = le32(emf, rec_off)
    rec_size = le32(emf, rec_off + 4)

    #  EMRText는 rec_off + 0x24 이후에 시작
    emrtext_off = rec_off + 0x24
    if emrtext_off + 8 > rec_off + rec_size:
        return 0

    # EMRTEXT: chars(4), offString(4)
    chars      = le32(emf, emrtext_off + 8)
    off_string = le32(emf, emrtext_off + 12)

    if chars == 0 or off_string == 0:
        return 0

    # 실제 문자열 위치 계산
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

    if not find_sensitive_spans(normalization_text(text)):
        return 0

    redacted = ("*" * len(text)).encode(enc)
    redacted = redacted[:len(raw)].ljust(len(raw), b'*')

    emf[str_start:str_end] = redacted
    print(f"[EMR] redacted text: {repr(text)} at 0x{str_start:08X}")

    return 1



# EPRINT 스트림 전체 레닥션
def redact_emf_stream(emf_bytes: bytes) -> bytes:
    emf = bytearray(emf_bytes)
    total = 0

    for rec_off, rec_type, rec_size, payload in iter_emf_records(emf):

        # EXTTEXTOUT
        if rec_type == EMR_EXTTEXTOUTA:
            total += redact_emr_block(emf, rec_off, False)

        elif rec_type == EMR_EXTTEXTOUTW:
            total += redact_emr_block(emf, rec_off, True)

        # POLY TEXT OUT
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

        # 3) SMALLTEXTOUT
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

            # OLE 내부 엔트리 전체 순회
            for entry in ole.listdir():
                if len(entry) < 2:
                    continue

                top = entry[0]
                name = entry[-1]

                # 1) Workbook 레닥션
                if top == "ObjectPool" and name in ("Workbook", "\x01Workbook"):
                    path_str = "/".join(entry)
                    print(f"[INFO] found Workbook stream: {path_str}")

                    wb_data = ole.openstream(entry).read()

                    # BIFF 전체 레닥션
                    new_biff = redact_biff_stream(wb_data, single_byte_codec)

                    # 변화가 있으면 파일 전체에 반영
                    if new_biff != wb_data:
                        # 임시 DOC 파일을 만들고 olefile로 재작성
                        with tempfile.NamedTemporaryFile(delete=False, suffix=".doc") as tmp:
                            tmp.write(modified)
                            temp_path = tmp.name

                        with olefile.OleFileIO(temp_path, write_mode=True) as olew:
                            olew.write_stream(path_str, new_biff)
                            print(f"  [WRITE] replaced Workbook: {path_str}")

                        with open(temp_path, "rb") as f:
                            modified = f.read()
                        os.remove(temp_path)

                # 2) EPRINT 레닥션
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