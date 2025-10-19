# -*- coding: utf-8 -*-
"""
OLE(CFBF) BinData 내부 스트림을 패턴 기반으로 직접 스캔/치환.
- 길이 동일('*') 마스킹: 삭제/크기변경 없음 → 패키지 무결성 유지
- UTF-16LE·ASCII 모두 처리 + '@' 주변 윈도우 마스킹(안전망)
- MiniFAT/BigFAT 제자리 덮어쓰기
- 프리뷰(OlePres*/EMF) : 삭제 대신 내용만 공격적 마스킹(차트 유지)
- 풍부한 디버그 로그 + 디스크 덤프 기능(OLE_DUMP_DIR)

환경변수:
  OLE_LOG=DEBUG|INFO ...
  OLE_DUMP_DIR=/path/to/dir   # 원본/마스킹 결과 바이트 덤프 저장
"""

from __future__ import annotations
import io, re, struct, logging, os, pathlib
from typing import List, Tuple, Optional
import olefile
from olefile.olefile import STGTY_STREAM

# ---------------- 옵션 ----------------
OLE_BLANK_PREVIEW = False               # 프리뷰 삭제 금지(차트 유지)
OLE_PREVIEW_MASK_AGGRESSIVE = True     # 프리뷰(EMF) 내부 문자열 적극 마스킹
DUMP_DIR = os.getenv("OLE_DUMP_DIR")   # 디스크 덤프 폴더(없으면 미사용)

# ---------------- logger ----------------
log = logging.getLogger("ole_redactor")
if not log.handlers:
    parent = logging.getLogger("uvicorn.error")
    if parent.handlers:
        for h in parent.handlers:
            log.addHandler(h)
    else:
        h = logging.StreamHandler()
        f = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
        h.setFormatter(f)
        log.addHandler(h)
log.setLevel(getattr(logging, os.getenv("OLE_LOG", "DEBUG").upper(), logging.DEBUG))

ENDOFCHAIN = 0xFFFFFFFE
MINI_CUTOFF_DEFAULT = 4096
CFBF_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

# ---------------- helpers ----------------
def _hexdump(b: bytes, width: int = 16) -> str:
    return " ".join(f"{x:02X}" for x in b[:width])

def _visible_ascii_preview(b: bytes, limit=160) -> str:
    try: s = b.decode("utf-8", "ignore")
    except Exception: s = b.decode("latin1", "ignore")
    s = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in s)
    s = " ".join(s.split())
    return s[:limit]

def _looks_like_emf_preview(head: bytes) -> bool:
    # EMF( ' EMF' 서명) / EMF+ 문자열 힌트
    return (b" EMF" in head) or (b"EMF+" in head) or (b"EMF" in head)

def _dump_bytes(kind: str, path_parts: list[str], payload: bytes):
    if not DUMP_DIR: return
    outdir = pathlib.Path(DUMP_DIR)
    outdir.mkdir(parents=True, exist_ok=True)
    name = "_".join(path_parts).replace("/", "_")
    p = outdir / f"{kind}__{name}.bin"
    try:
        p.write_bytes(payload)
        log.info("    · dumped: %s (%d bytes)", str(p), len(payload))
    except Exception as e:
        log.warning("    · dump failed: %s", e)

def _sample_around_at_utf16(b: bytes, win=64) -> tuple[int, list[str], float]:
    """UTF-16LE에서 '@' 코드포인트(0x40 00) 개수 / 주변 샘플 문자열 / 가시문자비율%"""
    if len(b) < 2 or (len(b) % 2) != 0: return 0, [], 0.0
    u = b
    ats = []
    vis = 0
    total = len(u)//2
    # 가시문자 카운트
    for i in range(0, len(u), 2):
        if u[i+1] == 0x00 and 0x20 <= u[i] <= 0x7E:
            vis += 1
    vis_ratio = (vis / max(1,total)) * 100.0

    i = 0; samples = []
    while i + 1 < len(u):
        if u[i] == 0x40 and u[i+1] == 0x00:  # '@'
            ats.append(i//2)
            s = max(0, i - win*2); e = min(len(u), i + win*2)
            try:
                samples.append(u[s:e].decode("utf-16le","ignore").replace("\n"," ").replace("\r"," ")[:120])
            except Exception:
                pass
            i = e
        else:
            i += 2
    return len(ats), samples[:3], vis_ratio

def _sample_around_at_ascii(b: bytes, win=64) -> tuple[int, list[str]]:
    ats = []
    samples = []
    i = 0; n = len(b)
    while i < n:
        if b[i] == ord('@'):
            ats.append(i)
            s = max(0, i - win); e = min(n, i + win)
            try:
                seg = b[s:e]
                try: txt = seg.decode("utf-8","ignore")
                except Exception: txt = seg.decode("latin1","ignore")
                samples.append(" ".join(txt.split())[:120])
            except Exception:
                pass
            i = e
        else:
            i += 1
    return len(ats), samples[:3]

# ---------------- ASCII 바이트 패턴 ----------------
EMAIL_ASCII_LOOSE = re.compile(
    rb"[A-Za-z0-9._%+\-]+@\s*(?:[A-Za-z0-9\-]+\s*\.)+\s*[A-Za-z]{2,}",
    re.MULTILINE,
)
RRN_ASCII   = re.compile(rb"\b\d{6}-?[1-4]\d{6}\b", re.MULTILINE)
CARD_ASCII  = re.compile(rb"\b(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}|\d{4}[- ]\d{6}[- ]\d{5}|\d{15,16})\b", re.MULTILINE)
MOB_ASCII   = re.compile(rb"\b01[016789]-?\d{3,4}-?\d{4}\b", re.MULTILINE)
ASCII_PATTERNS = [
    ("email_loose", EMAIL_ASCII_LOOSE),
    ("rrn", RRN_ASCII),
    ("card", CARD_ASCII),
    ("mobile", MOB_ASCII),
]

def _mask_segment_keep_separators(seg: bytearray) -> None:
    for i, ch in enumerate(seg):
        if ch in (ord('-'), ord(' '), ord('\t'), ord('\r'), ord('\n'), ord('@'), ord('.')):
            continue
        if 32 <= ch <= 126:
            seg[i] = ord('*')

def _ascii_same_len_mask(b: bytes, rx: re.Pattern) -> Tuple[bytes, int]:
    ba = bytearray(b); cnt = 0
    for m in list(rx.finditer(b)):
        s, e = m.span()
        seg = bytearray(ba[s:e])
        _mask_segment_keep_separators(seg)
        ba[s:e] = seg
        cnt += 1
    return bytes(ba), cnt

def _fallback_mask_emails_around_at(b: bytes) -> Tuple[bytes, int]:
    ba = bytearray(b); hits = 0; i = 0; n = len(ba)
    def is_local(ch): return (ch == ord('.') or ch == ord('_') or ch == ord('-') or
                              48 <= ch <= 57 or 65 <= ch <= 90 or 97 <= ch <= 122)
    def is_dom(ch):   return (ch in (ord('.'), ord('-'), ord(' '), ord('\t'), ord('\r'), ord('\n')) or
                              48 <= ch <= 57 or 65 <= ch <= 90 or 97 <= ch <= 122)
    while i < n:
        if ba[i] != ord('@'): i += 1; continue
        L = i - 1
        while L >= 0 and is_local(ba[L]): L -= 1
        L += 1
        R = i + 1
        while R < n and is_dom(ba[R]): R += 1
        if L < i and R > i + 2:
            seg = ba[L:R]
            _mask_segment_keep_separators(seg)
            ba[L:R] = seg
            hits += 1
            i = R
        else:
            i += 1
    return bytes(ba), hits

# ---------------- UTF-16LE 동일 길이 치환 ----------------
def utf16_same_len_replace_with_logs(data: bytes, old: str):
    old_u16 = old.encode("utf-16le")
    ba = bytearray(data); cnt = 0; i = 0; n = len(old_u16)
    if n == 0: return data, 0
    while True:
        j = ba.find(old_u16, i)
        if j == -1: break
        ba[j:j+n] = ("*" * (n // 2)).encode("utf-16le")
        cnt += 1; i = j + n
    return bytes(ba), cnt

def visible_replace_keep_len_with_logs(data: bytes, old: str):
    changed, direct_hits = utf16_same_len_replace_with_logs(data, old)
    if direct_hits: return changed, direct_hits
    if len(data) < 2 or (len(data) % 2) != 0: return data, 0
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

# ---------------- FAT/MiniFAT 쓰기 ----------------
def get_root_entry(ole):
    for e in ole.direntries:
        if e and e.name == "Root Entry":
            return e
    return None

def overwrite_bigfat(ole, container: bytearray, start_sector: int, new_raw: bytes):
    s = start_sector; pos = 0; sec = ole.sector_size; fat = ole.fat
    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        if s >= len(fat): break
        off = (s + 1) * sec
        chunk = new_raw[pos:pos + sec]
        container[off:off + len(chunk)] = chunk
        pos += sec
        s = fat[s]

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
    minifat = ole.minifat
    root = get_root_entry(ole)
    if root is None: return
    root_big_start = root.isectStart
    s = mini_start; pos = 0
    while s != ENDOFCHAIN and s != -1 and pos < len(new_raw):
        mini_off = s * minisize
        big_sector, within = big_sector_from_minioffset(ole, root_big_start, mini_off)
        if big_sector is None: break
        file_off = (big_sector + 1) * ole.sector_size + within
        chunk = new_raw[pos:pos + minisize]
        container[file_off:file_off + len(chunk)] = chunk
        pos += minisize
        if s >= len(minifat): break
        s = minifat[s]

# ---------------- 자동 마스킹(ASCII / UTF-16) ----------------
_UTF16_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")
_UTF16_RRN   = re.compile(r"\b\d{6}-?[1-4]\d{6}\b")
_UTF16_CARD  = re.compile(r"\b(?:\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}|\d{4}[- ]\d{6}[- ]\d{5}|\d{15,16})\b")
_UTF16_MOB   = re.compile(r"\b01[016789]-?\d{3,4}-?\d{4}\b")

def _auto_pattern_mask_utf16(data: bytes) -> tuple[bytes, int, dict]:
    if len(data) < 2 or (len(data) % 2) != 0: return data, 0, {}
    try: text = data.decode("utf-16le", "ignore")
    except Exception: return data, 0, {}
    per, total = {}, 0; out = data
    for name, rx in (("email_u16", _UTF16_EMAIL),
                     ("rrn_u16", _UTF16_RRN),
                     ("card_u16", _UTF16_CARD),
                     ("mobile_u16", _UTF16_MOB)):
        hits = 0
        for m in list(rx.finditer(text)):
            val = m.group(0)
            out2, c = visible_replace_keep_len_with_logs(out, val)
            if c:
                out = out2; hits += c
        if hits: per[name] = hits; total += hits
    return out, total, per

def _auto_pattern_mask_ascii(data: bytes) -> Tuple[bytes, int, dict]:
    total = 0; per = {}; out = data
    for name, rx in ASCII_PATTERNS:
        out2, hits = _ascii_same_len_mask(out, rx)
        if hits:
            per[name] = per.get(name, 0) + hits
            total += hits; out = out2
    if b'@' in out:
        out2, hits2 = _fallback_mask_emails_around_at(out)
        if hits2:
            per["email_fallback"] = per.get("email_fallback", 0) + hits2
            total += hits2; out = out2
    return out, total, per

# ---------- UTF-16 '@' 주변 윈도우 마스킹(프리뷰 안전망) ----------
def _utf16_window_mask_around_at(data: bytes, win: int = 64) -> tuple[bytes, int]:
    if len(data) < 2 or (len(data) % 2) != 0: return data, 0
    u = bytearray(data); hits = 0; i = 0; n = len(u)
    while i + 1 < n:
        if u[i] == 0x40 and u[i+1] == 0x00:  # '@'
            cu = i // 2
            s = max(0, (cu - win) * 2); e = min(n, (cu + win) * 2)
            p = s; changed = 0
            while p + 1 < e:
                lo, hi = u[p], u[p+1]
                if hi == 0x00 and 0x20 <= lo <= 0x7E and lo not in (ord(' '), ord('\t'), ord('\r'), ord('\n'), ord('-'), ord('.'), ord('@')):
                    u[p] = 0x2A; u[p+1] = 0x00; changed += 1
                p += 2
            if changed: hits += 1
            i = e
        else:
            i += 2
    return bytes(u), hits

def _mask_emf_aggressively(raw: bytes, secrets: list[str] | None) -> tuple[bytes, int, dict]:
    out = raw; total = 0; stat = {}

    # 0) UTF-16 자동 패턴
    out2, h0, per0 = _auto_pattern_mask_utf16(out)
    if h0: out = out2; total += h0; stat["u16_auto"] = per0

    # 1) secrets
    h1 = 0
    if secrets:
        for s in secrets:
            out2, c = visible_replace_keep_len_with_logs(out, s)
            if c: out = out2; h1 += c
    if h1: total += h1; stat["u16_secrets"] = h1

    # 2) ASCII + fallback
    out2, h2, per2 = _auto_pattern_mask_ascii(out)
    if h2: out = out2; total += h2; stat["ascii"] = per2

    # 3) UTF-16 '@' 윈도우(안전망)
    out2, h3 = _utf16_window_mask_around_at(out, win=96)
    if h3: out = out2; total += h3; stat["u16_at_window"] = h3

    return out, total, stat

# ---------------- 시그니처/시작섹터 탐지 ----------------
def _find_cfbf_offset(b: bytes, search_limit: int = 64) -> int:
    return b[:min(len(b), search_limit)].find(CFBF_MAGIC)

# -------- 브루트포스 역추적(FAT/MiniFAT) --------
ole_fat_global: list = []

def _read_big_chain_bytes(raw: bytes, sec_size: int, fat: list, start: int, need: int) -> bytes:
    out = bytearray(); s = start
    while s not in (-1, ENDOFCHAIN) and len(out) < need:
        if s >= len(fat): break
        off = (s + 1) * sec_size
        out.extend(raw[off:off + sec_size])
        s = fat[s]
    return bytes(out[:need])

def _read_mini_chain_bytes(raw: bytes, sec_size: int, minifat: list, root_start: int, mini_size: int, start: int, need: int) -> bytes:
    out = bytearray(); s = start
    while s not in (-1, ENDOFCHAIN) and len(out) < need:
        mini_off = s * mini_size
        block_idx = mini_off // sec_size
        within = mini_off % sec_size
        big = root_start; hop = 0
        while hop < block_idx and big not in (-1, ENDOFCHAIN) and big < len(ole_fat_global):
            big = ole_fat_global[big]; hop += 1
        if big in (-1, ENDOFCHAIN) or big >= len(ole_fat_global): break
        file_off = (big + 1) * sec_size + within
        out.extend(raw[file_off:file_off + mini_size])
        s = minifat[s] if s < len(minifat) else -1
    return bytes(out[:need])

def _bruteforce_locate_start(raw: bytes, ole: olefile.OleFileIO, stream_head: bytes,
                             size: int, cutoff: int, kind_hint: Optional[str] = None,
                             head_len: int = 256, max_scan_big: int = 4096, max_scan_mini: int = 8192) -> tuple[Optional[int], Optional[str]]:
    global ole_fat_global
    sec = ole.sector_size; mini = ole.mini_sector_size
    fat = ole.fat; ole_fat_global = fat
    minifat = ole.minifat
    root = get_root_entry(ole)
    root_start = getattr(root, "isectStart", -1) if root else -1

    K = min(head_len, size, len(stream_head))
    if K <= 0: return None, None
    head = stream_head[:K]

    if kind_hint == "mini" or (size < cutoff and kind_hint is None):
        if root_start >= 0 and minifat:
            maxi = min(max_scan_mini, len(minifat))
            for cand in range(maxi):
                sample = _read_mini_chain_bytes(raw, sec, minifat, root_start, mini, cand, K)
                if sample == head:
                    log.info("    · MiniFAT 브루트포스 일치: start=%d (K=%d)", cand, K)
                    return cand, "MiniFAT(brute)"

    maxi_big = min(max_scan_big, len(fat))
    for cand in range(maxi_big):
        sample = _read_big_chain_bytes(raw, sec, fat, cand, K)
        if sample == head:
            log.info("    · BigFAT 브루트포스 일치: start=%d (K=%d)", cand, K)
            return cand, "BigFAT(brute)"

    if kind_hint != "mini" and size < cutoff:
        if root_start >= 0 and minifat:
            maxi = min(max_scan_mini, len(minifat))
            for cand in range(maxi):
                sample = _read_mini_chain_bytes(raw, sec, minifat, root_start, mini, cand, K)
                if sample == head:
                    log.info("    · MiniFAT 브루트포스 일치(후행): start=%d (K=%d)", cand, K)
                    return cand, "MiniFAT(brute)"
    return None, None

# ---------------- 코어 처리 ----------------
def _process_cfbf_blob(raw: bytes, secrets: Optional[List[str]]) -> Tuple[bytes, bool]:
    container = bytearray(raw)
    changed_any = False

    with olefile.OleFileIO(io.BytesIO(raw)) as ole:
        cutoff = getattr(ole, "minisector_cutoff", MINI_CUTOFF_DEFAULT)
        paths = ole.listdir(streams=True, storages=False) or []
        log.info("OLE 열림: streams=%d, sector=%d, mini=%d, cutoff=%d",
                 getattr(ole, "nb_streams", len(paths)),
                 getattr(ole, "sector_size", -1),
                 getattr(ole, "mini_sector_size", -1),
                 cutoff)

        for p in paths:
            pstr = "/".join(p)
            try:
                st = ole.openstream(p); size = getattr(st, "size", None) or st.size
                head = st.read(min(size, 256))
                log.debug("  · %s size=%d head=%s preview='%s'",
                          pstr, size, _hexdump(head, 16), _visible_ascii_preview(head))
            except Exception as e:
                log.warning("  · %s 읽기 실패: %s", pstr, e)
                continue

            try:
                raw_stream = ole.openstream(p).read()
            except Exception as e:
                log.warning("  · %s 전체 읽기 실패: %s", pstr, e)
                continue

            # === 프리뷰 진단(사전 로그) ===
            preview_name_hit = p[-1].lower().startswith("olepres")
            preview_head_hit = _looks_like_emf_preview(head)
            if preview_name_hit or preview_head_hit:
                cnt_u16_at, samples_u16, vis_ratio = _sample_around_at_utf16(raw_stream)
                cnt_a_at, samples_a = _sample_around_at_ascii(raw_stream)
                log.info("  · %s PREVIEW diag: utf16_at=%d (vis=%.1f%%) ascii_at=%d",
                         pstr, cnt_u16_at, vis_ratio, cnt_a_at)
                if samples_u16:
                    for s in samples_u16:
                        log.debug("    · UTF16 '@' sample: %s", s)
                if samples_a:
                    for s in samples_a:
                        log.debug("    · ASCII '@' sample: %s", s)

            # ---- 치환 파이프라인 ----
            out = raw_stream
            sumline = []

            out, u16_auto_total, u16_auto_per = _auto_pattern_mask_utf16(out)
            if u16_auto_total: sumline.append(f"u16_auto={u16_auto_per}")

            utf16_hits_total = 0
            if secrets:
                for s in secrets:
                    if not s: continue
                    out, hits = visible_replace_keep_len_with_logs(out, s)
                    utf16_hits_total += hits
            if utf16_hits_total: sumline.append(f"u16_secrets={utf16_hits_total}")

            out, ascii_total, per = _auto_pattern_mask_ascii(out)
            if ascii_total: sumline.append(f"ascii={per}")

            if preview_name_hit or preview_head_hit:
                if OLE_PREVIEW_MASK_AGGRESSIVE:
                    out_prev, prev_hits, stat = _mask_emf_aggressively(out, secrets)
                    if prev_hits:
                        out = out_prev
                        sumline.append(f"preview_aggr={stat}")
                    else:
                        log.info("  · %s PREVIEW mask-aggressive nohit", pstr)
                elif OLE_BLANK_PREVIEW:
                    out = b"\x00" * size
                    sumline.append("preview_blank")
                else:
                    sumline.append("preview_keep")

            if sumline:
                log.info("  · %s PIPELINE: %s", pstr, " | ".join(sumline))
            else:
                log.debug("  · %s 변경 없음", pstr)

            if out == raw_stream:
                continue

            # 덤프(원본/결과)
            _dump_bytes("orig", p, raw_stream)
            _dump_bytes("masked", p, out)

            # 길이 안전망
            if len(out) < size: out = out + b"\x00" * (size - len(out))
            elif len(out) > size: out = out[:size]

            # 시작 섹터 탐색
            start = None; field = ""; path_kind = ""
            try:
                de = ole._find(p)
            except Exception:
                de = None
            if de:
                if len(out) < cutoff:
                    cand_fields = ["sstart","isectStart","start","sectStart"]
                else:
                    cand_fields = ["isectStart","sstart","start","sectStart"]
                for name in cand_fields:
                    if hasattr(de, name):
                        try:
                            val = int(getattr(de, name))
                            if val >= 0: start = val; field = name; break
                        except Exception: pass
            if start is None:
                for name in ("secid","isectStart","sstart","start","sect","start_sector"):
                    if hasattr(st, name):
                        try:
                            val = int(getattr(st, name))
                            if val >= 0: start = val; field = f"stream.{name}"; break
                        except Exception: pass

            if start is None:
                hint = "mini" if size < cutoff else "big"
                ss, pk = _bruteforce_locate_start(raw, ole, raw_stream[:256], size, cutoff,
                                                  kind_hint=hint, head_len=256, max_scan_big=4096, max_scan_mini=8192)
                if ss is not None: start = ss; path_kind = pk

            if start is None:
                log.warning("  · %s start sector 파악 실패(쓰기 스킵)", pstr)
                continue

            # 제자리 덮어쓰기
            if size < cutoff or path_kind.startswith("MiniFAT"):
                overwrite_minifat_chain(ole, container, start, out)
                used = f"MiniFAT({field or path_kind})"
            else:
                overwrite_bigfat(ole, container, start, out)
                used = f"BigFAT({field or path_kind})"

            changed_any = True
            log.info("  · %s WRITE ok via %s (size=%d start=%d)", pstr, used, size, start)

    return bytes(container), changed_any

# ---------------- 공개 API ----------------
def redact_ole_bin_preserve_size(bin_bytes: bytes, secrets: Optional[List[str]] = None) -> bytes:
    if len(bin_bytes) < 8:
        log.debug("BinData 너무 짧음")
        return bin_bytes
    off = bin_bytes[:min(len(bin_bytes),64)].find(CFBF_MAGIC)
    if off < 0:
        log.debug("BinData: CFBF 시그니처 없음 (head=%s)", _hexdump(bin_bytes, 16))
        return bin_bytes
    if off > 0:
        log.info("BinData: CFBF 시그니처가 오프셋 %d에서 시작 (prefix 추정: %s)", off, _hexdump(bin_bytes[:off], min(16, off)))
    cfbf = bin_bytes[off:]
    try:
        processed, changed = _process_cfbf_blob(cfbf, secrets)
    except Exception as e:
        log.error("OLE 파싱 실패: %s", e)
        return bin_bytes
    if not changed:
        log.warning("OLE 처리 완료: 변경된 스트림 없음")
        return bin_bytes
    out = bytearray(bin_bytes)
    out[off:off+len(cfbf)] = processed
    log.info("OLE 처리 완료: 일부 스트림 변경됨 (prefix 보존, off=%d)", off)
    return bytes(out)
