import zlib
from core.utils import pad_to_length
from core.encoding_replace import visible_replace_keep_len_with_logs

def process_body_stream(raw: bytes, old: str):
    try:
        dec = zlib.decompress(raw, -15)
        compressed = True
    except zlib.error:
        dec = raw; compressed = False

    new_dec, hits = visible_replace_keep_len_with_logs(dec, old)
    if compressed:
        cobj = zlib.compressobj(level=9, wbits=-15)
        re_raw = cobj.compress(new_dec) + cobj.flush()
    else:
        re_raw = new_dec
    return pad_to_length(re_raw, len(raw)), hits
