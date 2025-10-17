import struct

def utf16_same_len_replace_with_logs(data: bytes, old: str):
    old_u16 = old.encode("utf-16le")
    ba = bytearray(data)
    cnt, i, n = 0, 0, len(old_u16)
    if n == 0: return data, 0
    while True:
        j = ba.find(old_u16, i)
        if j == -1: break
        repl = ("*" * (n // 2)).encode("utf-16le")
        ba[j:j+n] = repl
        cnt += 1; i = j + n
    return bytes(ba), cnt

def visible_replace_keep_len_with_logs(data: bytes, old: str):
    changed, direct_hits = utf16_same_len_replace_with_logs(data, old)
    if direct_hits:
        return changed, direct_hits
    if len(data) < 2 or (len(data) % 2) != 0:
        return data, 0
    try:
        u16 = list(struct.unpack("<" + "H" * (len(data)//2), data))
    except struct.error:
        return data, 0
    target = list(struct.unpack("<" + "H"*len(old), old.encode("utf-16le")))
    m = len(target)
    if m == 0: return data, 0
    total = 0; i = 0
    while i < len(u16):
        j = 0; k = i
        while j < m and k < len(u16):
            if u16[k] < 0x20: k += 1; continue
            if u16[k] == target[j]: j += 1; k += 1
            else: break
        if j == m:
            p = i; filled = 0
            while p < k and filled < m:
                if u16[p] >= 0x20:
                    u16[p] = 0x002A
                    filled += 1
                p += 1
            total += 1; i = k
        else:
            i += 1
    return struct.pack("<" + "H"*len(u16), *u16), total
