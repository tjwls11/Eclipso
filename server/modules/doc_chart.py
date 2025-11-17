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


class XLUCS:
    __slots__ = ("cch", "flags", "fHigh", "fExt", "fRich", "cRun", "cbExtRst", "text_lo", "text_hi", "buf")

    def try_parse_at(self, payloads: list[bytes], start_idx: int, start_off: int) -> bool:
        data = payloads[start_idx]
        n = len(data)
        pos = start_off

        # 최소 3바이트는 있어야 문자열 헤더라고 판단 (cch(2) + flags(1))
        if pos + 3 > n:
            return False
        
        cch = le16(data, pos)
        pos += 2

        flags = data[pos]
        pos += 1

        fHigh = flags & 0x01        # 1이면 utf-16, 0이면 cp949
        fExt = (flags >> 2) & 0x01  # 확장 정보 포함 여부
        fRich = (flags >> 3) & 0x01 # 서식 정보 포함 여부

        # Rich text run 개수, ExtRst 길이 읽기
        cRun = 0
        cbExtRst = 0

        if fRich:
            if pos + 2 > n:
                return False
            cRun = le16(data, pos)
            pos += 2

        if fExt:
            if pos + 4 > n:
                return False 
            cbExtRst = le32(data, pos)
            pos += 4

        bpc = 2 if fHigh else 1
        need_bytes = cch * bpc
        
        # 텍스트 범위가 페이로드 내부에 존재해야 정상구조
        if pos + need_bytes > n:
            return False
        
        text_lo = pos
        text_hi = pos + need_bytes

        self.cch = cch
        self.flags = flags
        self.fHigh = fHigh
        self.fExt = fExt
        self.fRich = fRich 
        self.cRun = cRun 
        self.cbExtRst = cbExtRst
        self.text_lo = text_lo 
        self.text_hi = text_hi 
        self.buf = data

        return True

    def decode_text(self, single_byte_enc: str = "cp949") -> str:
        raw = self.buf[self.text_lo:self.text_hi]

        if not self.fHigh and len(raw) >= 4 and raw[1] == 0x00 and raw[3] == 0x00:
            enc = "utf-16le"
        else:
            enc = "utf-16le" if self.fHigh else single_byte_enc

        return raw.decode(enc, errors="ignore")


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



def extract_chart_text(file_bytes:bytes, single_byte_enc="cp949") -> List[str]:
    texts: List[str] = []

    try:
        # OLE Compound File 열기 (읽기 전용)
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:

            # 모든 OLE 엔트리 순회
            for entry in ole.listdir():
                # 최소 2단계 이상의 경로(ObjectPool/Workbook 형태)가 아니면 스킵
                if len(entry) < 2:
                    continue

                top = entry[0] 
                name = entry[-1]

                if top == "ObjectPool" and name in ("Workbook", "\x01Workbook"):
                    # Workbook 스트림을 읽어서 BIFF 바이트 취득
                    wb_data = ole.openstream(entry).read()
                    wb = bytearray(wb_data)

                    # BIFF 레코드 순회
                    for rec_off, opcode, length, _payload in iter_biff_records(wb):
                        if opcode not in CHART_STRING_LIKE:
                            continue

                        # 해당 레코드 + CONTINUE 레코드까지 병합
                        merged, segs, _ = coalesce_continue(wb, rec_off)
                        if not segs:
                            continue
                        
                        buf = merged

                        pos = 0
                        n = len(buf)

                        while pos < n:
                            x = XLUCS()

                            if not x.try_parse_at([buf], 0, pos):
                                pos += 1
                                continue

                            txt = x.decode_text(single_byte_enc).strip()
                            if txt:
                                texts.append(txt)

                            # 다음 문자열 후보 위치로 이동하기 위해 현재 문자열 구조의 전체 길이를 계산
                            header_len = 3
                            if x.flags & 0x08: # fRich(0x08) 이면 cRun(2바이트) 존재
                                header_len += 2
                            if x.flags & 0x04: # fExt(0x04) 이면 cbExtRst(4바이트) 존재
                                header_len += 4

                            text_bytes = x.cch * (2 if x.fHigh else 1)
                            advance = header_len + text_bytes

                            if x.fRich:
                                advance += x.cRun * 4

                            if x.fExt:
                                advance += x.cbExtRst 
                            
                            pos += advance

                if top == "ObjectPool" and name == "\x03EPRINT":
                    pass

    except Exception as e:
            print(f"[ERR] extract_chart_text: {e}") # 예외 상황은 로그만 찍고 지금까지 수집분을 반환

    return texts



CHART_STRING_LIKE = {0x100D, 0x1025, 0x0004}
def scan_and_redact_payload(wb: bytearray, payload_off: int, length: int, single_byte_codec="cp949") -> int:
    rec_off = payload_off - 4
    merged, segs, next_rec_off = coalesce_continue(wb, rec_off)

    if not segs:
        return 0
    
    buf = bytearray(merged)
    n = len(buf)
    pos = 0
    red = 0

    # 병합된 buf에서만 XLUCS 파싱/마스킹 수행
    while pos < n:
        x = XLUCS()

        # 현재 pos 위치에서 XLUCS 시도
        if not x.try_parse_at([buf], 0, pos):
            # 파싱 실패 시 한 바이트 옮겨서 재시도
            pos += 1
            continue

        # 문자열 디코드
        text = x.decode_text(single_byte_codec).strip()
        print(f"[DEBUG-MERGED] candidate={repr(text)} (len={len(text)} fHigh={x.fHigh})")

        # 민감정보 검출
        if text and find_sensitive_spans(normalization_text(text)):
            print(f"[DEBUG!!!] MATCHED in merged: {repr(text)}")

            raw_len = x.text_hi - x.text_lo  # 실제 텍스트 영역의 raw 바이트 길이

            masked = ("*" * len(text)).encode("utf-16le" if x.fHigh else single_byte_codec)

            masked = masked[:raw_len].ljust(raw_len, b'*')

            buf[x.text_lo:x.text_hi] = masked
            red += 1

        header_len = 3      
        if x.flags & 0x08:  # fRich
            header_len += 2
        if x.flags & 0x04:  # fExt
            header_len += 4

        text_bytes = x.cch * (2 if x.fHigh else 1)
        advance = header_len + text_bytes

        # Rich text run 데이터 (run당 4바이트)
        if x.fRich:
            advance += x.cRun * 4

        # ExtRst 데이터
        if x.fExt:
            advance += x.cbExtRst

        pos += advance


    if red == 0:
        red += fallback_redact(buf, single_byte_codec)

    # 병합 버퍼(buf)에서 수정된 내용을 원본 BIFF(wb)에 다시 반영
    write_pos = 0
    for payload_lo, payload_hi in segs:
        segment_len = payload_hi - payload_lo
        wb[payload_lo:payload_hi] = buf[write_pos:write_pos + segment_len]
        write_pos += segment_len

    return red



# BIFF 전체 처리 (Workbook 스트림 수준)
def redact_biff_stream(biff_bytes: bytes, single_byte_codec="cp949") -> bytes:
    wb = bytearray(biff_bytes)
    total = 0

    # BIFF 전체 레코드 순회
    for rec_off, opcode, length, payload in iter_biff_records(wb):
        if opcode in CHART_STRING_LIKE and length > 0:
            print(f" ------ [REC] opcode=0x{opcode:04X} len={length} ------")
            try:
                # 이 레코드 + CONTINUE 병합 후 레닥션
                cnt = scan_and_redact_payload(wb, rec_off+4, length, single_byte_codec)
                total += cnt
                print(f"[CHART OK] opcode=0x{opcode:04X} → {cnt} texts redacted")
            except Exception as e:
                print(f"[WARN] opcode=0x{opcode:04X} exception: {e}")

    if total:
        print(f"[CHART] total {total} strings redacted")
    else:
        print("[CHART ERR] 레닥션 없음")

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