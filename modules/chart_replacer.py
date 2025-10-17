import io, zlib, olefile

CFB = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
PNG = b"\x89PNG\r\n\x1a\n"
GZ  = b"\x1F\x8B"
JPG = b"\xFF\xD8\xFF"
WMF = b"\xD7\xCD\xC6\x9A"

def mask_same_len(b: bytes, fill: bytes = b"*") -> bytes:
    if not b: return b
    need = len(b)
    return (fill * ((need + len(fill) - 1) // len(fill)))[:need]

def replace_bytes_with_enc(data: bytes, old_text: str, enc: str):
    needle = old_text.encode(enc)
    mask_char = "*" if enc.lower() == "utf-16le" else "＊"
    repl = (mask_char * len(old_text)).encode(enc)
    if len(repl) != len(needle): repl = b"*" * len(needle)
    ba = bytearray(data)
    i = 0; n = len(needle); cnt = 0
    while True:
        j = ba.find(needle, i)
        if j == -1: break
        ba[j:j+n] = repl; cnt += 1; i = j + n
    return bytes(ba), cnt

def try_patterns(blob: bytes, text: str):
    total = 0; cur = blob
    for enc in ["utf-16le", "utf-8", "cp949"]:
        try:
            cur2, cnt = replace_bytes_with_enc(cur, text, enc)
        except Exception:
            cnt = 0; cur2 = cur
        if cnt > 0:
            total += cnt; cur = cur2
    return cur, total

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

def is_zlib_head(b: bytes): 
    return len(b) >= 2 and b[0] == 0x78 and b[1] in (0x01, 0x9C, 0xDA)

def scan_deflate(raw: bytes, limit: int = 64, step: int = 64):
    n = len(raw); cand = []
    for i in range(n - 1):
        if is_zlib_head(raw[i:i + 2]): cand.append(("zlib", i))
        if raw[i:i + 2] == GZ:        cand.append(("gzip", i))
    for i in range(0, n, step): cand.append(("rawdef", i))
    out, seen = [], set()
    for k, o in cand:
        if (k, o) in seen: continue
        seen.add((k, o)); out.append((k, o))
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
    if kind == "zlib": return zlib.compress(dec)
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
        if cnt == 0: continue
        if kind == "gzip": continue
        comp = recompress(kind, rep_dec)
        if comp is None: continue
        new_raw = patch_seg(raw, off, consumed, comp)
        if new_raw is None: continue
        hits += cnt
        return new_raw, hits
    rep, cnt = try_patterns(raw, chart_old)
    if cnt > 0: return rep, cnt
    return raw, 0
