import io
import olefile, zlib, struct
from server.core.redaction_rules import apply_redaction_rules
TAG_PARA_TEXT = 67


def extract_text(file_bytes: bytes) -> dict:
    with olefile.OleFileIO(io.BytesIO(file_bytes)) as ole:
        raw = ole.openstream("BodyText/Section0").read()

    try:
        dec = zlib.decompress(raw, -15)
    except zlib.error:
        dec = raw

    off, n = 0, len(dec)
    texts = []
    while off < n:
        if off + 4 > n:
            break
        header = struct.unpack_from("<I", dec, off)[0]
        tag = header & 0x3FF
        size = (header >> 20) & 0xFFF
        off += 4
        payload = dec[off:off + size]
        if tag == TAG_PARA_TEXT:
            txt = payload.decode("utf-16le", errors="ignore")
            texts.append(txt)
        off += size

    full = "\n".join(texts)
    return {"full_text": full, "pages": [{"page": 1, "text": full}]}

def redact(file_bytes: bytes) -> bytes:
    """HWP BodyText 섹션 내부 텍스트 동일길이 치환"""
    f = io.BytesIO(file_bytes)
    with olefile.OleFileIO(f) as ole:
        if not ole.exists("BodyText/Section0"):
            return file_bytes
        raw = ole.openstream("BodyText/Section0").read()

    try:
        dec = zlib.decompress(raw, -15)
        compressed = True
    except zlib.error:
        dec = raw
        compressed = False

    data = bytearray(dec)
    off, n = 0, len(data)
    while off + 4 < n:
        header = struct.unpack_from("<I", data, off)[0]
        tag = header & 0x3FF
        size = (header >> 20) & 0xFFF
        off += 4
        if tag == TAG_PARA_TEXT and size > 0:
            text = data[off:off + size].decode("utf-16le", errors="ignore")
            redacted = apply_redaction_rules(text)
            enc = redacted.encode("utf-16le")
            data[off:off + size] = enc[:size].ljust(size, b"\x00")
        off += size

    if compressed:
        data = zlib.compress(data, 9)[2:-4]
    return bytes(data)