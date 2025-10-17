import sys, os, re, zlib, struct, argparse, hashlib, io
import olefile

ENDOFCHAIN = 0xFFFFFFFE
TAG_PARA_TEXT = 67
REC_TAG_BITS = (0, 10); REC_LEVEL_BITS = (10, 10); REC_SIZE_BITS = (20, 12)

def bits(v, o, n): return (v >> o) & ((1 << n) - 1)

def hexdump(b: bytes, width=16): return " ".join(f"{x:02X}" for x in b[:width])
def sha256(b: bytes) -> str: return hashlib.sha256(b).hexdigest()[:16]

def pad_to_length(blob: bytes, target: int) -> bytes:
    if len(blob) < target: return blob + b"\x00" * (target - len(blob))
    if len(blob) > target: return blob[:target]
    return blob

def list_all_streams(ole): return ["/".join(p) for p in ole.listdir(streams=True, storages=False)]

def find_direntry_by_tail(ole, name_tail: str):
    for e in ole.direntries:
        if e and e.name == name_tail:
            return e
    return None

def overwrite_bigfat_chain(ole, container: bytearray, start_sector: int, new_raw: bytes):
    s = start_sector; pos = 0; sector = ole.sector_size; fat = ole.fat
    written = []
    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        if s >= len(fat): break
        off = (s + 1) * sector
        chunk = new_raw[pos:pos + sector]
        container[off:off + len(chunk)] = chunk
        written.append((off, len(chunk)))
        pos += sector; s = fat[s]
    return written

def get_root_entry(ole):
    for e in ole.direntries:
        if e and e.name == "Root Entry":
            return e
    return None

def big_sector_from_minioffset(ole, root_start_sector: int, mini_offset: int):
    sector = ole.sector_size
    block_idx = mini_offset // sector
    within = mini_offset % sector
    s = root_start_sector; fat = ole.fat
    for _ in range(block_idx):
        if s in (-1, ENDOFCHAIN) or s >= len(fat):
            return None, None
        s = fat[s]
    return s, within

def overwrite_minifat_chain(ole, container: bytearray, mini_start: int, new_raw: bytes):
    minisize = ole.mini_sector_size
    minifat  = ole.minifat
    root = get_root_entry(ole)
    if root is None: return []
    root_big_start = root.isectStart
    s = mini_start; pos = 0; written = []
    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        mini_off = s * minisize
        big_sector, within = big_sector_from_minioffset(ole, root_big_start, mini_off)
        if big_sector is None: break
        file_off = (big_sector + 1) * ole.sector_size + within
        chunk = new_raw[pos:pos + minisize]
        container[file_off:file_off + len(chunk)] = chunk
        written.append((file_off, len(chunk)))
        pos += minisize
        if s >= len(minifat): break
        s = minifat[s]
    return written

# ---------- 레코드 파서 ----------
def parse_records(raw: bytes):
    recs, off, n = [], 0, len(raw)
    while off < n:
        if off + 4 > n: break
        h = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        tag = bits(h, *REC_TAG_BITS); lvl = bits(h, *REC_LEVEL_BITS); sz = bits(h, *REC_SIZE_BITS)
        if sz == 0xFFF:
            if off + 4 > n: break
            sz = struct.unpack("<I", raw[off:off+4])[0]; off += 4
        if off + sz > n:
            data = raw[off:n]; off = n
        else:
            data = raw[off:off+sz]; off += sz
        recs.append((tag, lvl, data))
    return recs

def build_records(recs):
    out = bytearray()
    for tag, lvl, data in recs:
        sz = len(data)
        if sz < 0xFFF:
            h = (tag & 0x3FF) | ((lvl & 0x3FF) << 10) | ((sz & 0xFFF) << 20)
            out += struct.pack("<I", h)
        else:
            h = (tag & 0x3FF) | ((lvl & 0x3FF) << 10) | (0xFFF << 20)
            out += struct.pack("<I", h) + struct.pack("<I", sz)
        out += data
    return bytes(out)

# ---------- 치환 로직 ----------
def utf16_same_len_replace_with_logs(data: bytes, old: str, max_log=3):
    old_u16 = old.encode("utf-16le")
    ba = bytearray(data)
    cnt, i, n = 0, 0, len(old_u16)
    logs = []
    if n == 0: return data, 0, logs
    while True:
        j = ba.find(old_u16, i)
        if j == -1: break
        repl = ("*" * (n // 2)).encode("utf-16le")
        before = ba[j:j+n]
        ba[j:j+n] = repl
        if len(logs) < max_log:
            logs.append(f" direct-hit byte_off={j}, before={hexdump(before)}, after={hexdump(repl)}")
        cnt += 1; i = j + n
    return bytes(ba), cnt, logs

def visible_replace_keep_len_with_logs(data: bytes, old: str, max_log=3):
    changed, direct_hits, direct_logs = utf16_same_len_replace_with_logs(data, old, max_log)
    if direct_hits:
        return changed, direct_hits, ["[mode] direct"] + direct_logs
    if len(data) < 2 or (len(data) % 2) != 0:
        return data, 0, ["[skip] not even-length UTF-16"]
    try:
        u16 = list(struct.unpack("<" + "H" * (len(data)//2), data))
    except struct.error:
        return data, 0, ["[skip] struct error on unpack"]
    target = list(struct.unpack("<" + "H"*len(old), old.encode("utf-16le")))
    m = len(target)
    if m == 0: return data, 0, ["[skip] empty old"]

    total = 0
    i = 0
    logs = ["[mode] visible"]
    while i < len(u16):
        j = 0; k = i
        while j < m and k < len(u16):
            if u16[k] < 0x20: k += 1; continue
            if u16[k] == target[j]: j += 1; k += 1
            else: break
        if j == m:
            if len(logs) <= max_log:
                win = u16[max(0, i-4):min(len(u16), k+4)]
                logs.append(f" visible-hit units[{i}:{k}) context={['%04X'%x for x in win]}")
            # 치환
            filled, p = 0, i
            while p < k and filled < m:
                if u16[p] >= 0x20:
                    u16[p] = 0x002A
                    filled += 1
                p += 1
            total += 1; i = k
        else:
            i += 1
    if total == 0:
        return data, 0, logs + [" no match"]
    return struct.pack("<" + "H"*len(u16), *u16), total, logs

# ---------- 스트림 처리 ----------
def process_stream_with_logs(name: str, raw: bytes, old: str, max_log=3):
    try:
        dec = zlib.decompress(raw, -15)
        compressed = True
    except zlib.error:
        dec = raw; compressed = False

    reco_logs = []
    if name.startswith("BodyText/Section"):
        recs = parse_records(dec)
        n67 = sum(1 for t,_,_ in recs if t == TAG_PARA_TEXT)
        reco_logs.append(f" records: total={len(recs)}, TAG67={n67}")

    new_dec, hits, rep_logs = visible_replace_keep_len_with_logs(dec, old, max_log)
    altered = (new_dec != dec)
    reco_logs += rep_logs + [f" hits={hits}, altered={altered}"]

    if compressed:
        cobj = zlib.compressobj(level=9, wbits=-15)
        re_raw = cobj.compress(new_dec) + cobj.flush()
    else:
        re_raw = new_dec
    re_raw_padded = pad_to_length(re_raw, len(raw))
    return re_raw_padded, compressed, hits, reco_logs, sha256(raw), sha256(re_raw_padded)

# ---------- 차트(OLE) 수정 ----------
def process_chart_stream(name: str, raw: bytes, chart_old: str, max_log=3):
    logs = []
    hits = 0
    try:
        o2 = olefile.OleFileIO(io.BytesIO(raw))
    except Exception as e:
        return raw, 0, [f"[error] inner OLE open failed: {e}"]

    for s in o2.listdir():
        sname = "/".join(s)
        if sname.lower() in ("workbook", "chartdata"):
            blob = o2.openstream(sname).read()
            new_blob, cnt, rep_logs = utf16_same_len_replace_with_logs(blob, chart_old, max_log)
            if cnt > 0:
                raw = raw.replace(blob, new_blob, 1)
                hits += cnt
                logs += [f"[chart] {sname}: hits={cnt}"] + rep_logs
    if hits == 0:
        logs.append("[chart] no matches in OLE inner streams")
    return raw, hits, logs

# ---------- 메인 ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--old", required=False)
    ap.add_argument("--chart-old", required=False, help="OLE 내부(차트)에서 교체할 문자열")
    ap.add_argument("--dry-run", action="store_true", help="실제 쓰기 없이 로그만")
    ap.add_argument("--max-log", type=int, default=3, help="매칭 로그 최대 표시 개수")
    args = ap.parse_args()

    ole = olefile.OleFileIO(args.file)
    with open(args.file, "rb") as f:
        container = bytearray(f.read())

    streams = list_all_streams(ole)
    total_hits = 0
    print(f"[INFO] streams={len(streams)}")

    for name in streams:
        try:
            raw = ole.openstream(name).read()
        except Exception:
            continue

        tail = name.split("/")[-1]
        entry = find_direntry_by_tail(ole, tail)
        if entry is None:
            continue
        cutoff = getattr(ole, "minisector_cutoff", 4096)
        which = "MiniFAT" if entry.size < cutoff else "FAT"

        hits = 0
        logs = []
        new_raw = raw

        if args.old:
            new_raw, compressed, hits, logs, h0, h1 = process_stream_with_logs(name, raw, args.old, args.max_log)
        elif args.chart_old and name.startswith("BinData/") and name.endswith(".OLE"):
            new_raw, hits, logs = process_chart_stream(name, raw, args.chart_old, args.max_log)
        else:
            continue

        if hits == 0:
            continue

        print(f"[HIT ] {name}: type={which}, len={len(raw)}, hits={hits}")
        for L in logs: print("       -", L)
        total_hits += hits

        if args.dry_run:
            continue
        if which == "MiniFAT":
            written = overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
        else:
            written = overwrite_bigfat_chain(ole, container, entry.isectStart, new_raw)
        print(f"[WR  ] {name}: wrote {len(written)} blocks")

    out = os.path.splitext(args.file)[0] + "_edit.hwp"
    if not args.dry_run:
        with open(out, "wb") as f:
            f.write(container)
        print(f"\n[DONE] total_hits={total_hits} → saved: {out}")
    else:
        print(f"\n[DRY ] total_hits={total_hits} → no file written (dry-run)")

if __name__ == "__main__":
    main()
