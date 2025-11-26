import io, os, struct, tempfile, olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans


SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD
LABEL = 0x0204


def le16(b, off=0): return struct.unpack_from("<H", b, off)[0]
def le32(b, off=0): return struct.unpack_from("<I", b, off)[0]


def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        header_off = off
        off += 4
        payload = data[off:off + length]
        off += length
        yield opcode, length, payload, header_off

# SST payload + payload 오프셋 반환
def get_sst_payload(wb: bytes):
    for opcode, length, payload, hdr in iter_biff_records(wb):
        if opcode == SST:
            payload_off = hdr + 4
            return payload, payload_off
    return None, None



class XLUCSString:
    def __init__(self):
        self.cch = 0
        self.fHigh = 0
        self.fRichSt = 0
        self.fExtSt = 0

        self.cRun = 0
        self.cbExt = 0

        self.text = ""

        # 텍스트가 SST payload에서 차지하는 정확한 오프셋 범위
        self.text_start = 0
        self.text_end = 0



class SSTParser:
    def __init__(self, payload: bytes, base_payload_offset: int):
        self.payload = payload
        self.pos = 0
        self.n = len(payload)

        self.base_off = base_payload_offset   # Workbook 내 절대 오프셋

        self.cstTotal = 0
        self.cstUnique = 0

    def read_n(self, n):
        if self.pos + n > self.n:
            raise EOFError("SST payload EOF")
        b = self.payload[self.pos:self.pos + n]
        self.pos += n
        return b

    def read_sst_header(self):
        self.cstTotal = le32(self.read_n(4))
        self.cstUnique = le32(self.read_n(4))

    def read_XLUCS(self) -> XLUCSString:
        x = XLUCSString()

        x.cch = le16(self.read_n(2))
        flags = self.read_n(1)[0]

        x.fHigh = flags & 0x01
        x.fExtSt = 1 if (flags & 0x04) else 0
        x.fRichSt = 1 if (flags & 0x08) else 0

        if x.fRichSt:
            x.cRun = le16(self.read_n(2))
        if x.fExtSt:
            x.cbExt = le32(self.read_n(4))

        char_size = 2 if x.fHigh else 1

        # 텍스트 영역 오프셋 기록
        x.text_start = self.base_off + self.pos
        raw = self.read_n(x.cch * char_size)
        x.text_end = self.base_off + self.pos

        x.text = raw.decode("utf-16le" if x.fHigh else "latin1", errors="ignore")

        # Rich text run skip
        if x.fRichSt:
            self.read_n(4 * x.cRun)

        # ExtRst skip
        if x.fExtSt and x.cbExt > 0:
            self.read_n(x.cbExt)

        return x

    def parse(self) -> List[XLUCSString]:
        self.read_sst_header()
        out = []
        for _ in range(self.cstUnique):
            try:
                out.append(self.read_XLUCS())
            except EOFError:
                break
        return out



# 문자열 추출
def extract_text(file_bytes: bytes):
    try:
        with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
            if not ole.exists("Workbook"):
                return {"full_text": "", "pages": [{"page": 1, "text": ""}]}
            wb = ole.openstream("Workbook").read()

        sst_payload, off = get_sst_payload(wb)
        if sst_payload:
            xlucs_list = SSTParser(sst_payload, off).parse()
            strings = [x.text for x in xlucs_list]
        else:
            strings = []

        # LABELSST/LABEL -> 셀 텍스트 추출
        texts = []
        for opcode, length, payload, hdr in iter_biff_records(wb):
            if opcode == LABELSST:
                idx = le32(payload, 6)
                if 0 <= idx < len(strings):
                    texts.append(strings[idx])

            elif opcode == LABEL and len(payload) > 8:
                try:
                    txt = payload[8:].decode("cp949", errors="ignore").strip()
                    if txt:
                        texts.append(txt)
                except:
                    pass

        full_text = "\n".join(texts)
        return {"full_text": full_text, "pages":[{"page":1,"text":full_text}]}

    except Exception as e:
        print("[ERROR extract]:", e)
        return {"full_text": "", "pages":[{"page":1,"text":""}]}


def mask_except_asterisk(original_segment: str) -> str:
    out = []
    for ch in original_segment:
        if ch in "-":
            out.append(ch)
        else:
            out.append("*")
    return "".join(out)



def redact_xlucs(text: str) -> str:
    if not text:
        return text

    # 정규화 + 인덱스 매핑
    norm_text, index_map = normalization_index(text)

    # 정규화된 텍스트 기준 매칭
    spans = find_sensitive_spans(norm_text)
    if not spans:
        return text

    chars = list(text)

    # 겹침 방지 - 정상 적용 루틴은 역순 매핑
    spans = sorted(spans, key=lambda x: x[0], reverse=True)

    for s_norm, e_norm, value, rule in spans:
        # 정규화된 인덱스를 원본 인덱스로 역매핑
        s = index_map.get(s_norm)
        e = index_map.get(e_norm - 1)

        if s is None or e is None:
            continue

        e = e + 1   # inclusive → exclusive

        original_seg = text[s:e]
        masked = mask_except_asterisk(original_seg)

        # apply
        for i in range(len(original_seg)):
            chars[s+i] = masked[i]

    return "".join(chars)


def redact(file_bytes: bytes) -> bytes:
    print("[INFO] XLS Redaction 시작")

    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        if not ole.exists("Workbook"):
            print("[ERROR] Workbook 없음")
            return file_bytes

        wb = bytearray(ole.openstream("Workbook").read())

    # SST 문자열 + offset 추출
    sst_payload, payload_off = get_sst_payload(wb)
    if not sst_payload:
        return file_bytes

    xlucs_list = SSTParser(sst_payload, payload_off).parse()

    # 텍스트 치환
    for x in xlucs_list:
        red = redact_xlucs(x.text)

        if len(red) != len(x.text):
            raise ValueError("동일길이 레닥션 실패")

        raw = red.encode("utf-16le" if x.fHigh else "latin1", errors="ignore")

        expected = x.text_end - x.text_start
        if len(raw) != expected:
            raise ValueError("raw 길이 mismatch")

        wb[x.text_start:x.text_end] = raw

    print("[OK] SST 텍스트 patch 완료")
    return bytes(wb)
