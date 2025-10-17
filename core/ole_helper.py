import olefile

ENDOFCHAIN = 0xFFFFFFFE

def overwrite_bigfat(ole, container: bytearray, start_sector: int, new_raw: bytes):
    s = start_sector
    pos = 0
    sec = ole.sector_size
    fat = ole.fat

    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        if s >= len(fat):
            break
        off = (s + 1) * sec
        chunk = new_raw[pos:pos + sec]
        container[off:off + len(chunk)] = chunk
        pos += sec
        s = fat[s]
