import struct

SST = 0x00FC

def parse_records(wb: bytes):
    off = 0
    n = len(wb)
    records = []
    while off + 4 <= n:
        opcode, length = struct.unpack("<HH", wb[off:off + 4])
        payload = wb[off + 4:off + 4 + length]
        records.append((opcode, payload))
        off += 4 + length
    return records
