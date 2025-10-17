ENDOFCHAIN = 0xFFFFFFFE

def get_root_entry(ole):
    for e in ole.direntries:
        if e and e.name == "Root Entry":
            return e
    return None


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


def big_sector_from_minioffset(ole, root_start_sector: int, mini_offset: int):
    sector = ole.sector_size
    block_idx = mini_offset // sector
    within = mini_offset % sector
    s = root_start_sector
    fat = ole.fat

    for _ in range(block_idx):
        if s in (-1, ENDOFCHAIN) or s >= len(fat):
            return None, None
        s = fat[s]
    return s, within


def overwrite_minifat_chain(ole, container: bytearray, mini_start: int, new_raw: bytes):
    minisize = ole.mini_sector_size
    minifat = ole.minifat
    root = get_root_entry(ole)
    if root is None:
        return

    root_big_start = root.isectStart
    s = mini_start
    pos = 0

    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        mini_off = s * minisize
        big_sector, within = big_sector_from_minioffset(ole, root_big_start, mini_off)
        if big_sector is None:
            break

        file_off = (big_sector + 1) * ole.sector_size + within
        chunk = new_raw[pos:pos + minisize]
        container[file_off:file_off + len(chunk)] = chunk

        pos += minisize
        if s >= len(minifat):
            break
        s = minifat[s]
