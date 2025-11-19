import olefile
import struct
from pathlib import pathlib

def iter_biff_records(data: bytes):
    off = 0
    n = len(data)
    while off + 4 <= n:
        opcode, size = struct.unpack_from("<HH", data, off)
        off_header = off 
        off += 4
        payload = data[off:off + size]
        yield off_header, opcode, size, payload
        off += size

