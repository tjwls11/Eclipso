import io
import olefile, zlib, struct

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

from .redac_rules import apply_redaction_rules

def redact(file_bytes: bytes) -> bytes:
    """HWP 텍스트 기반 레닥션"""
    result = extract_text(file_bytes)
    text = result.get("full_text", "")
    if not text.strip():
        return b""
    redacted = apply_redaction_rules(text)
    return redacted.encode("utf-8")
