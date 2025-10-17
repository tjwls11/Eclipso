import sys, os, io, re, zlib, struct, argparse, hashlib
import olefile

ENDOFCHAIN = 0xFFFFFFFE
TAG_PARA_TEXT = 67
REC_TAG_BITS = (0, 10); REC_LEVEL_BITS = (10, 10); REC_SIZE_BITS = (20, 12)

# 공통 유틸
def bits(v, o, n): return (v >> o) & ((1 << n) - 1)
def hexdump(b: bytes, width=16): return " ".join(f"{x:02X}" for x in b[:width])
def sha256(b: bytes) -> str: return hashlib.sha256(b).hexdigest()[:16]
def sha16(b: bytes) -> str: return hashlib.sha256(b).hexdigest()[:16]

def pad_to_length(blob: bytes, target: int) -> bytes:
    if len(blob) < target: return blob + b"\x00" * (target - len(blob))
    if len(blob) > target: return blob[:target]
    return blob

def list_streams(ole): 
    return ["/".join(p) for p in ole.listdir(streams=True, storages=False)]

def find_direntry_tail(ole, tail: str):
    for e in ole.direntries:
        if e and e.name == tail: return e
    return None

def get_root_entry(ole):
    for e in ole.direntries:
        if e and e.name == "Root Entry":
            return e
    return None

def overwrite_bigfat(ole, container: bytearray, start_sector: int, new_raw: bytes):
    s, pos, sec, fat = start_sector, 0, ole.sector_size, ole.fat
    written = []
    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        if s >= len(fat): break
        off = (s + 1) * sec
        chunk = new_raw[pos:pos + sec]
        container[off:off + len(chunk)] = chunk
        written.append((off, len(chunk)))
        pos += sec
        s = fat[s]
    return written

def big_sector_from_minioffset(ole, root_start_sector: int, mini_offset: int):
    sector = ole.sector_size
    block_idx = mini_offset // sector
    within = mini_offset % sector
    s = root_start_sector; fat = ole.fat
    for _ in range(block_idx):
        if s in (-1, ENDOFCHAIN) or s >= len(fat): return None, None
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

# HWP 레코드 파서
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


# 본문 치환 (UTF-16LE 동일 길이)
def utf16_same_len_replace_with_logs(data: bytes, old: str, max_log=0):
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
            logs.append(f"byte_off={j}, before={hexdump(before)}, after={hexdump(repl)}")
        cnt += 1; i = j + n
    return bytes(ba), cnt, logs

def visible_replace_keep_len_with_logs(data: bytes, old: str, max_log=0):
    changed, direct_hits, direct_logs = utf16_same_len_replace_with_logs(data, old, max_log)
    if direct_hits:
        return changed, direct_hits, direct_logs
    if len(data) < 2 or (len(data) % 2) != 0:
        return data, 0, []
    try:
        u16 = list(struct.unpack("<" + "H" * (len(data)//2), data))
    except struct.error:
        return data, 0, []
    target = list(struct.unpack("<" + "H"*len(old), old.encode("utf-16le")))
    m = len(target)
    if m == 0: return data, 0, []

    total = 0; i = 0; logs=[]
    while i < len(u16):
        j = 0; k = i
        while j < m and k < len(u16):
            if u16[k] < 0x20: k += 1; continue
            if u16[k] == target[j]: j += 1; k += 1
            else: break
        if j == m:
            filled, p = 0, i
            while p < k and filled < m:
                if u16[p] >= 0x20:
                    u16[p] = 0x002A
                    filled += 1
                p += 1
            total += 1; i = k
        else:
            i += 1
    if total == 0: return data, 0, logs
    return struct.pack("<" + "H"*len(u16), *u16), total, logs

def process_body_stream(raw: bytes, old: str):
    try:
        dec = zlib.decompress(raw, -15)
        compressed = True
    except zlib.error:
        dec = raw; compressed = False

    new_dec, hits, _ = visible_replace_keep_len_with_logs(dec, old, max_log=0)

    if compressed:
        cobj = zlib.compressobj(level=9, wbits=-15)
        re_raw = cobj.compress(new_dec) + cobj.flush()
    else:
        re_raw = new_dec
    return pad_to_length(re_raw, len(raw)), hits

# 차트(BinData/*.OLE) 치환 (인코딩 다양)
def mask_same_len(b: bytes, fill: bytes = b"*") -> bytes:
    if not b: return b
    need = len(b)
    out = (fill * ((need + len(fill) - 1) // len(fill)))[:need]
    return out

def replace_bytes_with_enc(data: bytes, old_text: str, enc: str):
    needle = old_text.encode(enc)
    mask_char = "*" if enc.lower() == "utf-16le" else "＊"  
    repl = (mask_char * len(old_text)).encode(enc)
    if len(repl) != len(needle): 
        repl = b"*" * len(needle)

    ba = bytearray(data)
    i = 0; n = len(needle); cnt = 0
    while True:
        j = ba.find(needle, i)
        if j == -1: break
        ba[j:j + n] = repl
        cnt += 1
        i = j + n
    return bytes(ba), cnt

def try_patterns(blob: bytes, text: str):
    total = 0
    cur = blob
    for enc in ["utf-16le", "utf-8", "cp949"]:
        try:
            cur2, cnt = replace_bytes_with_enc(cur, text, enc)
        except Exception:
            cnt = 0; cur2 = cur
        if cnt > 0:
            total += cnt
            cur = cur2
    return cur, total

# 매직 시그너처
CFB = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
PNG = b"\x89PNG\r\n\x1a\n"
GZ  = b"\x1F\x8B"
JPG = b"\xFF\xD8\xFF"
WMF = b"\xD7\xCD\xC6\x9A"

def magic_hits(raw: bytes):
    hits = []
    if raw.startswith(CFB): hits.append(("ole", 0))
    if raw.startswith(PNG): hits.append(("png", 0))
    if raw.startswith(GZ):  hits.append(("gzip", 0))
    if raw.startswith(JPG): hits.append(("jpeg", 0))
    if raw.startswith(WMF): hits.append(("wmf", 0))
    for sig, name in [(CFB, "ole"), (PNG, "png"), (GZ, "gzip")]:
        off = raw.find(sig, 1)
        if off != -1:
            hits.append((name, off))
    return hits

def is_zlib_head(b: bytes) -> bool:
    return len(b) >= 2 and b[0] == 0x78 and b[1] in (0x01, 0x9C, 0xDA)

def scan_deflate(raw: bytes, limit: int = 64, step: int = 64):
    n = len(raw); cand = []
    for i in range(n - 1):
        if is_zlib_head(raw[i:i + 2]): cand.append(("zlib", i))
        if raw[i:i + 2] == GZ:        cand.append(("gzip", i))
    for i in range(0, n, step):        cand.append(("rawdef", i))
    out, seen = [], set()
    for k, o in cand:
        if (k, o) in seen: continue
        seen.add((k, o))
        out.append((k, o))
        if len(out) >= limit: break
    return out

def decomp_at(raw: bytes, off: int, kind: str):
    data = raw[off:]
    try:
        if kind == "zlib":
            obj = zlib.decompressobj()
            dec = obj.decompress(data)
            consumed = len(data) - len(obj.unused_data)
        elif kind == "gzip":
            obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
            dec = obj.decompress(data)
            consumed = len(data) - len(obj.unused_data)
        else: 
            obj = zlib.decompressobj(-15)
            dec = obj.decompress(data)
            consumed = len(data) - len(obj.unused_data)
        if consumed <= 0 or len(dec) == 0: return None
        return dec, consumed
    except Exception:
        return None

def recompress(kind: str, dec: bytes):
    if kind == "zlib":
        return zlib.compress(dec)
    if kind == "rawdef":
        co = zlib.compressobj(level=6, wbits=-15)
        return co.compress(dec) + co.flush()
    return None  
def patch_seg(raw: bytes, off: int, consumed: int, new_comp: bytes):
    seg = raw[off:off + consumed]
    if len(new_comp) > len(seg): return None
    if len(new_comp) < len(seg):
        new_comp = new_comp + b"\x00" * (len(seg) - len(new_comp))
    return raw[:off] + new_comp + raw[off + len(seg):]

def process_bindata(raw: bytes, chart_old: str):
    hits = 0
    mags = magic_hits(raw)


    if any(k in ("png", "jpeg", "wmf") and o == 0 for k, o in mags):
        return raw, 0


    for k, o in mags:
        if k == "ole":
            try:
                inner = olefile.OleFileIO(io.BytesIO(raw[o:]))
                names = ["/".join(s) for s in inner.listdir(streams=True, storages=False)]
                cur = raw
                for s in names:
                    try:
                        blob = inner.openstream(s).read()
                    except Exception:
                        continue
                    rep, cnt = try_patterns(blob, chart_old)
                    if cnt > 0:
                        cur = cur.replace(blob, rep, 1)
                        hits += cnt
                if hits > 0:
                    return cur, hits
            except Exception:
                pass

    for kind, off in scan_deflate(raw):
        r = decomp_at(raw, off, kind)
        if not r: continue
        dec, consumed = r
        rep_dec, cnt = try_patterns(dec, chart_old)
        if cnt == 0:
            continue
        if kind == "gzip":
            continue
        comp = recompress(kind, rep_dec)
        if comp is None:
            continue
        new_raw = patch_seg(raw, off, consumed, comp)
        if new_raw is None:
            continue
        hits += cnt
        return new_raw, hits


    rep, cnt = try_patterns(raw, chart_old)
    if cnt > 0:
        return rep, cnt

    return raw, 0

# 섹션에서 $ole 근처 BinDataID 후보 찾기
def find_bindata_ids_from_sections(ole):
    bins = {}
    for nm in list_streams(ole):
        m = re.fullmatch(r"BinData/BIN(\d{4})\.OLE", nm)
        if m: bins[int(m.group(1))] = nm

    targets = set()
    for nm in list_streams(ole):
        if not nm.startswith("BodyText/Section"):
            continue
        try:
            blob = ole.openstream(nm).read()
        except Exception:
            continue
        i = 0
        while True:
            j = blob.find(b"$ole", i)
            if j == -1: break
            window = blob[j:j + 128]
            for k in range(0, max(0, len(window) - 4)):
                val = int.from_bytes(window[k:k + 4], "little", signed=False)
                if val in bins:
                    targets.add(val)
                    break
            i = j + 4
    return sorted(targets)


# 메인
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="HWP 파일 경로")
    ap.add_argument("text", help="치환(마스킹)할 문자열")
    args = ap.parse_args()

    ole = olefile.OleFileIO(args.file)
    with open(args.file, "rb") as f:
        container = bytearray(f.read())

    streams = list_streams(ole)
    total_hits = 0
    print(f"총 스트림 {len(streams)}개")

    # 1) 본문 처리
    for name in streams:
        if not name.startswith("BodyText/Section"):
            continue
        try:
            raw = ole.openstream(name).read()
        except Exception:
            continue
        tail = name.split("/")[-1]
        entry = find_direntry_tail(ole, tail)
        if entry is None:
            continue
        cutoff = getattr(ole, "minisector_cutoff", 4096)
        which = "MiniFAT" if entry.size < cutoff else "FAT"

        new_raw, hits = process_body_stream(raw, args.text)
        if hits == 0:
            continue

        if which == "MiniFAT":
            written = overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
        else:
            written = overwrite_bigfat(ole, container, entry.isectStart, new_raw)

        total_hits += hits
        print(f"본문 치환: {name} → {hits}회")

    # 2) 차트 대상 스트림 추출
    bin_ids = find_bindata_ids_from_sections(ole)
    bindata_list = [s for s in streams if s.startswith("BinData/BIN") and s.endswith(".OLE")]
    targets = [f"BinData/BIN{idx:04d}.OLE" for idx in bin_ids if f"BinData/BIN{idx:04d}.OLE" in bindata_list]
    if not targets:
        targets = bindata_list  # 후보가 없으면 전체 BIN 대상

    # 3) 차트 처리
    for name in targets:
        try:
            raw = ole.openstream(name).read()
        except Exception:
            continue
        tail = name.split("/")[-1]
        entry = find_direntry_tail(ole, tail)
        if entry is None:
            continue

        new_raw, hits = process_bindata(raw, args.text)
        if hits == 0:
            continue

        overwrite_bigfat(ole, container, entry.isectStart, new_raw)
        total_hits += hits
        print(f"차트 치환: {name} → {hits}회")

    out = os.path.splitext(args.file)[0] + "_edit.hwp"
    with open(out, "wb") as f:
        f.write(container)
    print(f"\n총 치환 {total_hits}회 → 저장됨: {out}")

if __name__ == "__main__":
    main()
