import struct
from core.utils import bits

TAG_PARA_TEXT = 67
REC_TAG_BITS = (0, 10)
REC_LEVEL_BITS = (10, 10)
REC_SIZE_BITS = (20, 12)

def parse_records(raw: bytes):
    recs, off, n = [], 0, len(raw)
    while off < n:
        if off + 4 > n: break
        h = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        tag = bits(h, *REC_TAG_BITS)
        lvl = bits(h, *REC_LEVEL_BITS)
        sz = bits(h, *REC_SIZE_BITS)
        if sz == 0xFFF:
            if off + 4 > n: break
            sz = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        if off + sz > n:
            data = raw[off:n]; off = n
        else:
            data = raw[off:off+sz]; off += sz
        recs.append((tag, lvl, data))
    return recs
