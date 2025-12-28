from __future__ import annotations

import base64
import hashlib
import logging
import os
import re
import struct
import unicodedata
import zlib
from io import BytesIO
from typing import Any, Dict, Iterable, List, Optional, Tuple, Iterator, TypeAlias

from server.core.matching import find_sensitive_spans
from server.core.normalize import normalization_index

olefile = None
try:  # pragma: no cover
    import olefile  # type: ignore
except Exception:  # pragma: no cover
    olefile = None

OleLike: TypeAlias = Any

_FREESECT = 0xFFFFFFFF
_ENDOFCHAIN = 0xFFFFFFFE
_FATSECT = 0xFFFFFFFD
_DIFSECT = 0xFFFFFFFC


def _u16le(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def _u32le(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def _u64le(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


class _CFBFReader:

    def __init__(self, data: bytes):
        self._data = data if isinstance(data, (bytes, bytearray, memoryview)) else bytes(data)
        self._buf = memoryview(self._data)
        if len(self._buf) < 512:
            raise ValueError("CFBF header too small")
        if self._buf[:8].tobytes() != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
            raise ValueError("Not a CFBF container")

        hdr = self._buf[:512].tobytes()
        if _u16le(hdr, 0x1C) != 0xFFFE:
            raise ValueError("Unsupported byte order")
        sec_shift = _u16le(hdr, 0x1E)
        mini_shift = _u16le(hdr, 0x20)
        self.sector_size = 1 << sec_shift
        self.mini_sector_size = 1 << mini_shift

        self._num_fat_sectors = _u32le(hdr, 0x2C)
        self._first_dir_sector = _u32le(hdr, 0x30)
        self._mini_cutoff = _u32le(hdr, 0x38)
        self._first_minifat_sector = _u32le(hdr, 0x3C)
        self._num_minifat_sectors = _u32le(hdr, 0x40)
        self._first_difat_sector = _u32le(hdr, 0x44)
        self._num_difat_sectors = _u32le(hdr, 0x48)

        self._difat = []
        for k in range(109):
            s = _u32le(hdr, 0x4C + 4 * k)
            if s != _FREESECT:
                self._difat.append(s)

        # DIFAT extension sectors
        next_difat = self._first_difat_sector
        for _ in range(self._num_difat_sectors):
            if next_difat in (_FREESECT, _ENDOFCHAIN) or next_difat is None:
                break
            sec = self._read_sector(next_difat)
            # last DWORD is next DIFAT sector
            n_entries = (self.sector_size // 4) - 1
            for k in range(n_entries):
                s = _u32le(sec, 4 * k)
                if s != _FREESECT:
                    self._difat.append(s)
            next_difat = _u32le(sec, 4 * n_entries)

        # Build FAT
        self.fat: List[int] = []
        for fat_sec in self._difat[: self._num_fat_sectors]:
            sec = self._read_sector(fat_sec)
            for k in range(self.sector_size // 4):
                self.fat.append(_u32le(sec, 4 * k))

        # Directory stream
        self._dir_stream = self._read_chain_big(self._first_dir_sector)
        self._dir_entries = self._parse_dir_entries(self._dir_stream)

        # Root entry + mini stream
        self._root = self._dir_entries.get("Root Entry")
        self._mini_stream = b""
        if self._root and self._root.get("start") not in (_FREESECT, _ENDOFCHAIN, None):
            root_start = int(self._root.get("start", _ENDOFCHAIN))
            root_size = int(self._root.get("size", 0))
            self._mini_stream = self._read_chain_big(root_start, root_size)

        # MiniFAT
        self.minifat: List[int] = []
        if self._num_minifat_sectors and self._first_minifat_sector not in (_FREESECT, _ENDOFCHAIN):
            mini_fat_bytes = self._read_chain_big(self._first_minifat_sector)
            # miniFAT entries are 4 bytes each
            n = len(mini_fat_bytes) // 4
            for k in range(n):
                self.minifat.append(_u32le(mini_fat_bytes, 4 * k))

        # Stream index (root-level by name)
        self._streams: Dict[str, Dict[str, Any]] = {}
        for name, ent in self._dir_entries.items():
            if ent.get("type") == 2:  # stream
                self._streams[name] = ent

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def _read_sector(self, sec_id: int) -> bytes:
        off = (sec_id + 1) * self.sector_size
        end = off + self.sector_size
        if off < 0 or end > len(self._buf):
            raise ValueError("Sector out of range")
        return self._buf[off:end].tobytes()

    def _iter_chain(self, start: int, table: List[int]) -> Iterator[int]:
        s = start
        seen = 0
        # hard safety
        limit = max(1, len(table) + 16)
        while s not in (_ENDOFCHAIN, _FREESECT) and 0 <= s < len(table) and seen < limit:
            yield s
            s = table[s]
            seen += 1

    def _read_chain_big(self, start_sector: int, size: Optional[int] = None) -> bytes:
        if start_sector in (_ENDOFCHAIN, _FREESECT) or start_sector is None:
            return b""
        out = bytearray()
        for s in self._iter_chain(int(start_sector), self.fat):
            out += self._read_sector(s)
            if size is not None and len(out) >= size:
                break
        if size is not None and size >= 0:
            return bytes(out[:size])
        return bytes(out)

    def _read_chain_mini(self, start_mini: int, size: int) -> bytes:
        if start_mini in (_ENDOFCHAIN, _FREESECT) or start_mini is None:
            return b""
        if not self._mini_stream:
            return b""
        out = bytearray()
        for s in self._iter_chain(int(start_mini), self.minifat):
            off = s * self.mini_sector_size
            end = off + self.mini_sector_size
            if end > len(self._mini_stream):
                break
            out += self._mini_stream[off:end]
            if len(out) >= size:
                break
        return bytes(out[:size])

    def _parse_dir_entries(self, dir_bytes: bytes) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        if not dir_bytes:
            return out
        for i in range(0, len(dir_bytes), 128):
            chunk = dir_bytes[i : i + 128]
            if len(chunk) < 128:
                break
            name_len = _u16le(chunk, 0x40)
            if name_len < 2:
                continue
            raw_name = chunk[: max(0, name_len - 2)]
            try:
                name = raw_name.decode("utf-16le", errors="ignore").rstrip("\x00")
            except Exception:
                continue
            if not name:
                continue
            obj_type = chunk[0x42]
            start = _u32le(chunk, 0x74)
            size = _u64le(chunk, 0x78)
            out[name] = {"type": int(obj_type), "start": int(start), "size": int(size)}
        return out

    # olefile-compatible subset
    def exists(self, name: str) -> bool:
        return str(name) in self._streams

    def listdir(self, streams: bool = True, storages: bool = False):
        if not streams:
            return []
        # olefile returns list of lists/tuples for paths. Here: root-level only.
        return [(k,) for k in self._streams.keys()]

    def openstream(self, entry):
        # entry can be "name" or ("name",) like olefile.
        if isinstance(entry, (list, tuple)):
            name = entry[-1]
        else:
            name = entry
        name = str(name)
        ent = self._streams.get(name)
        if not ent:
            raise FileNotFoundError(name)

        size = int(ent.get("size", 0))
        start = int(ent.get("start", _ENDOFCHAIN))
        if size < 0:
            size = 0

        if size < int(self._mini_cutoff) and self.minifat and self._mini_stream:
            blob = self._read_chain_mini(start, size)
        else:
            blob = self._read_chain_big(start, size)

        return BytesIO(blob)


def _open_ppt_container(file_bytes: bytes) -> OleLike:
    """Return ole-like object with .exists/.openstream/.listdir. Does NOT require olefile."""
    if olefile is not None:
        try:
            return olefile.OleFileIO(BytesIO(file_bytes))  # type: ignore[attr-defined]
        except Exception:
            pass
    return _CFBFReader(file_bytes)


log = logging.getLogger("ppt_module")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    log.addHandler(_h)
    log.propagate = False
log.setLevel(logging.INFO)

PPT_DEBUG = os.getenv("PPT_DEBUG", "0") in ("1", "true", "TRUE")
PPT_DUMP_IMAGES = True  # 항상 Pictures 이미지 스트림 덤프/추출 실행
PPT_DUMP_DIR = os.getenv("PPT_DUMP_DIR", "./_ppt_dump")






_ZW_CHARS = r"\u200B\u200C\u200D\uFEFF"

_RE_MASTER_LEVEL = re.compile(
    r"^(?:[•·\*\-\–\—◦●○◆◇▪▫▶▷■□]+\s*)?"
    r"(?:첫|두|둘|세|셋|네|넷|다섯|여섯|일곱|여덟|아홉|열|[0-9]+)\s*(?:번째)?\s*수준\s*$",
    re.IGNORECASE,
)
_RE_BULLET_ONLY = re.compile(r"^[\*\u2022•·\-\–\—○●◦■□]+$", re.IGNORECASE)


def _norm_line(t: str) -> str:
    t = unicodedata.normalize("NFKC", t or "")
    t = re.sub(f"[{_ZW_CHARS}]", "", t)
    t = t.replace("\r\n", "\n").replace("\r", "\n")
    t = re.sub(r"[ \t]+", " ", t)
    return t.strip()


def _is_noise_line(line: str) -> bool:
    if not line:
        return True

    if "마스터" in line and "스타일" in line:
        return True
    if "편집하려면 클릭" in line:
        return True

    if _RE_MASTER_LEVEL.match(line):
        return True
    if _RE_BULLET_ONLY.match(line):
        return True

    return False


def _cleanup(text: str) -> str:
    out: List[str] = []
    for raw_line in (text or "").splitlines():
        line = _norm_line(raw_line)
        if not line:
            continue
        if _is_noise_line(line):
            continue
        out.append(line)
    return "\n".join(out)


_HDR = struct.Struct("<HHI")
_TEXTCHARSATOM = 0x0FA0  # UTF-16LE 텍스트
_TEXTBYTESATOM = 0x0FA8  # 단일바이트 텍스트


def _walk_records(buf: bytes, base_off: int = 0) -> Iterable[Tuple[int, int, int, int]]:
    i, n = 0, len(buf)
    while i + _HDR.size <= n:
        try:
            verInst, rtype, rlen = _HDR.unpack_from(buf, i)
        except struct.error:
            break

        rec_ver = verInst & 0x000F
        i_hdr_end = i + _HDR.size
        i_data_end = i_hdr_end + rlen
        if i_data_end > n or rlen < 0:
            break

        data_off_abs = base_off + i_hdr_end

        if rec_ver == 0xF:
            child = buf[i_hdr_end:i_data_end]
            yield from _walk_records(child, base_off + i_hdr_end)
        else:
            yield (rec_ver, rtype, rlen, data_off_abs)

        i = i_data_end


def _read_stream(ole: Any, name: str) -> bytes:
    with ole.openstream(name) as fp:  # type: ignore[attr-defined]
        return fp.read()


def _extract_text_from_records(doc_bytes: bytes) -> str:
    chunks: List[str] = []
    for _rec_ver, rtype, rlen, data_off in _walk_records(doc_bytes):
        if rlen <= 0:
            continue

        b = doc_bytes[data_off : data_off + rlen]
        if not b:
            continue

        txt: Optional[str] = None
        if rtype == _TEXTCHARSATOM:
            txt = b.decode("utf-16le", errors="ignore")
        elif rtype == _TEXTBYTESATOM:
            try:
                txt = b.decode("cp949", errors="ignore")
            except Exception:
                txt = b.decode("latin1", errors="ignore")

        if not txt:
            continue

        txt = txt.replace("\r\n", "\n").replace("\r", "\n")
        chunks.append(txt)

    return _cleanup("\n".join(chunks))


PPT_EXTRACT_EMBEDDED = True


def _extract_text_from_ole_stream(raw: bytes) -> str:
    if not raw:
        return ""

    out: List[str] = []
    try:
        with _open_ppt_container(raw) as sub:
            for entry in sub.listdir(streams=True, storages=False):
                try:
                    with sub.openstream(entry) as fp:
                        blob = fp.read()
                except Exception:
                    continue

                for enc in ("utf-8", "utf-16le", "cp949", "latin1"):
                    try:
                        txt = blob.decode(enc)
                        txt = _cleanup(txt)
                        if txt:
                            out.append(txt)
                        break
                    except Exception:
                        continue
    except Exception:
        return ""

    return "\n".join(out)


def _extract_embedded_noise_prone(ole: Any) -> str:
    out: List[str] = []
    for entry in ole.listdir(streams=True, storages=False):
        path = "/".join(entry)
        if path == "PowerPoint Document":
            continue
        try:
            with ole.openstream(entry) as fp:
                blob = fp.read()
        except Exception:
            continue

        if len(blob) > 6 and blob[0] == 0x78 and blob[1] in (0x01, 0x9C, 0xDA):
            try:
                blob = zlib.decompress(blob)
            except Exception:
                pass

        txt = _extract_text_from_ole_stream(blob)
        if txt:
            out.append(txt)

    return _cleanup("\n".join(out))


def _extract_chart_ole_text_from_doc(doc_bytes: bytes) -> str:
    out: List[str] = []
    n = len(doc_bytes)
    i = 0

    while i + _HDR.size <= n:
        try:
            _verInst, _rtype, rlen = _HDR.unpack_from(doc_bytes, i)
        except struct.error:
            break

        i_hdr_end = i + _HDR.size
        i_data_end = i_hdr_end + rlen
        if i_data_end > n or rlen < 0:
            break

        if rlen > 32:
            blob = doc_bytes[i_hdr_end:i_data_end]
            if len(blob) > 6 and blob[0] == 0x78 and blob[1] in (0x01, 0x9C, 0xDA):
                try:
                    decomp = zlib.decompress(blob)
                except Exception:
                    decomp = None
                if decomp:
                    txt = _extract_text_from_ole_stream(decomp)
                    if txt:
                        out.append(txt)

        i = i_data_end

    return _cleanup("\n".join(out))


_PNG_SIG = b"\x89PNG\r\n\x1a\n"
_BMP_SIG = b"BM"


def _find_all(data: bytes, sig: bytes) -> List[int]:
    out: List[int] = []
    start = 0
    while True:
        i = data.find(sig, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out


def _png_end_by_chunks(data: bytes, start: int) -> Optional[int]:
    n = len(data)
    if start + 8 > n or data[start : start + 8] != _PNG_SIG:
        return None

    p = start + 8
    try:
        while p + 12 <= n:
            length = struct.unpack_from(">I", data, p)[0]
            ctype = data[p + 4 : p + 8]
            p_next = p + 12 + length
            if p_next > n:
                return None
            if ctype == b"IEND":
                return p_next
            p = p_next
    except Exception:
        return None
    return None


def _bmp_end_by_header(data: bytes, start: int) -> Optional[int]:
    n = len(data)
    if start + 14 > n or data[start : start + 2] != _BMP_SIG:
        return None
    try:
        size = struct.unpack_from("<I", data, start + 2)[0]
    except Exception:
        return None
    if size <= 0:
        return None
    end = start + size
    if end <= n:
        return end
    return None


def _scan_image_sigs(pics: bytes) -> List[Tuple[str, int]]:
    hits: List[Tuple[str, int]] = []
    for p in _find_all(pics, _PNG_SIG):
        hits.append(("PNG", p))
    for p in _find_all(pics, _BMP_SIG):
        hits.append(("BMP", p))
    hits.sort(key=lambda x: x[1])
    return hits


def extract_images_from_pictures(
    file_bytes: bytes,
    *,
    dump_dir: Optional[str] = None,
    include_b64: bool = False,
    b64_limit: int = 250_000,
    max_images: int = 64,
) -> Dict[str, Any]:
    with _open_ppt_container(file_bytes) as ole:
        pics = _read_stream(ole, "Pictures") if ole.exists("Pictures") else b""
        doc = _read_stream(ole, "PowerPoint Document") if ole.exists("PowerPoint Document") else b""

    hits = _scan_image_sigs(pics)
    hits = hits[:max_images]

    if dump_dir:
        os.makedirs(dump_dir, exist_ok=True)

    out: List[Dict[str, Any]] = []
    n = len(pics)

    for idx, (kind, start) in enumerate(hits, start=1):
        next_start = hits[idx][1] if idx < len(hits) else n

        if kind == "PNG":
            end = _png_end_by_chunks(pics, start)
        elif kind == "BMP":
            end = _bmp_end_by_header(pics, start)
        else:
            end = None

        if end is None:
            end = next_start if next_start > start else n

        if end <= start:
            continue

        blob = pics[start:end]
        sha1 = hashlib.sha1(blob).hexdigest()

        rec: Dict[str, Any] = {
            "index": idx,
            "ole_path": "Pictures",
            "kind": kind,
            "offset": f"0x{start:X}",
            "end": f"0x{end:X}",
            "length": len(blob),
            "sha1": sha1,
        }

        if include_b64 and len(blob) <= b64_limit:
            rec["data_b64"] = base64.b64encode(blob).decode("ascii")

        if dump_dir:
            ext = "png" if kind == "PNG" else "bmp"
            fn = f"ppt_Pictures_{idx:03d}_{kind}_{start:08x}.{ext}"
            path = os.path.join(dump_dir, fn)
            with open(path, "wb") as fp:
                fp.write(blob)
            rec["dump_file"] = fn

        out.append(rec)

    by_type: Dict[str, int] = {}
    for k, _pos in hits:
        by_type[k] = by_type.get(k, 0) + 1

    return {
        "ok": True,
        "streams": {"Pictures": len(pics), "PowerPoint Document": len(doc)},
        "hits": [(k, f"0x{p:X}") for k, p in hits],
        "by_type": by_type,
        "count": len(out),
        "images": out,
    }


def build_image_loc_summary(file_bytes: bytes) -> Dict[str, Any]:
    with _open_ppt_container(file_bytes) as ole:
        has_pics = ole.exists("Pictures")
        has_doc = ole.exists("PowerPoint Document")
        pics_len = len(_read_stream(ole, "Pictures")) if has_pics else 0

    summary: Dict[str, Any] = {
        "found": bool(has_pics and pics_len > 0),
        "dgg": bool(has_doc),
        "dgg_note": "(정확하지 않음) 스트림 존재 기반",
        "bstore": bool(has_pics),
        "bstore_note": "(정확하지 않음) 스트림 존재 기반",
        "images": 0,
        "patched": 0,
        "pictures_len": pics_len,
    }

    if not has_pics:
        return summary

    try:
        with _open_ppt_container(file_bytes) as ole2:
            pics = _read_stream(ole2, "Pictures")
        hits = _scan_image_sigs(pics)
    except Exception:
        hits = []

    by_type: Dict[str, int] = {}
    for k, _pos in hits:
        by_type[k] = by_type.get(k, 0) + 1

    summary["images"] = len(hits)
    summary["by_type"] = by_type
    summary["hits"] = [f"{k}@0x{pos:X}" for k, pos in hits[:32]]
    if len(hits) > 32:
        summary["hits_more"] = len(hits) - 32

    return summary




def extract_text(file_bytes: bytes) -> Dict[str, Any]:
    with _open_ppt_container(file_bytes) as ole:
        if not ole.exists("PowerPoint Document"):
            raise ValueError("PowerPoint Document 스트림이 없습니다(.ppt 형식이 아닐 수 있음).")
        doc = _read_stream(ole, "PowerPoint Document")

        text_main = _extract_text_from_records(doc)

        if PPT_EXTRACT_EMBEDDED:
            extra_parts: List[str] = []
            t1 = _extract_embedded_noise_prone(ole)
            if t1:
                extra_parts.append(t1)
            t2 = _extract_chart_ole_text_from_doc(doc)
            if t2:
                extra_parts.append(t2)
            if extra_parts:
                text_main = _cleanup((text_main or "") + "\n" + "\n".join(extra_parts))

    out: Dict[str, Any] = {"full_text": text_main or "", "pages": [{"index": 1, "text": text_main or ""}]}

    try:
        out["image_loc"] = build_image_loc_summary(file_bytes)
    except Exception as e:
        out["image_loc"] = {"found": False, "error": repr(e)}

    # Pictures 스트림 이미지 덤프/추출은 항상 실행 (디버그 플래그와 무관)
    try:
        out["images_dump"] = extract_images_from_pictures(
            file_bytes, dump_dir=PPT_DUMP_DIR, include_b64=False, max_images=64
        )
    except Exception as e:
        out["images_dump"] = {"ok": False, "error": repr(e)}


    return out


def _collect_literals_from_spans(spans) -> List[str]:
    out: List[str] = []
    if not spans or not isinstance(spans, list):
        return out
    for sp in spans:
        if not isinstance(sp, dict):
            continue
        t = sp.get("text")
        if t is None:
            continue
        v = str(t).strip()
        if len(v) >= 2:
            out.append(v)
    return sorted(set(out), key=lambda x: (-len(x), x))


def redact(file_bytes: bytes, spans: Optional[List[Dict[str, Any]]] = None) -> bytes:
    try:
        from .ole_redactor import redact_ole_bin_preserve_size  # type: ignore
    except Exception:  # pragma: no cover
        try:
            from server.modules.ole_redactor import redact_ole_bin_preserve_size  # type: ignore
        except Exception:
            redact_ole_bin_preserve_size = None  # type: ignore

    if redact_ole_bin_preserve_size is None:
        return file_bytes

    try:
        data = extract_text(file_bytes) or {}
        raw_text = data.get("full_text", "") or ""
    except Exception as e:
        log.info(f"[PPT] extract_text 예외: {e!r}")
        return file_bytes

    if not raw_text:
        log.info("[PPT] extract_text 결과가 비어 있음 → 레닥션 생략")
        return file_bytes

    # spans(정규식+NER)로 넘어온 텍스트 리터럴이 있으면 우선 사용
    span_literals = _collect_literals_from_spans(spans)
    if span_literals:
        try:
            return redact_ole_bin_preserve_size(file_bytes, span_literals, mask_preview=False)
        except Exception as e:
            log.info(f"[PPT] redact_ole_bin_preserve_size(spans) 예외: {e!r}")
            # fallback to rule-based below

    norm_text, index_map = normalization_index(raw_text)

    try:
        matches = find_sensitive_spans(norm_text)
    except Exception as e:
        log.info(f"[PPT] find_sensitive_spans 예외: {e!r}")
        return file_bytes

    if not matches:
        log.info("[PPT] 민감정보 매칭 0건 → 레닥션 생략")
        return file_bytes

    def _map_pos(idx: int) -> Optional[int]:
        if idx in index_map:
            return index_map[idx]
        j = idx
        while j >= 0 and j not in index_map:
            j -= 1
        if j >= 0 and j in index_map:
            return index_map[j]
        j = idx
        while j < len(norm_text) and j not in index_map:
            j += 1
        if j < len(norm_text) and j in index_map:
            return index_map[j]
        return None

    secrets: List[str] = []
    for s_idx, e_idx, _val, _name in matches:
        if not isinstance(s_idx, int) or not isinstance(e_idx, int) or e_idx <= s_idx:
            continue
        start = _map_pos(s_idx)
        end0 = _map_pos(e_idx - 1)
        if start is None or end0 is None:
            continue
        end = end0 + 1
        if end <= start:
            continue

        frag = raw_text[start:end].strip()
        if len(frag) >= 2:
            secrets.append(frag)

    if not secrets:
        log.info("[PPT] 매칭은 있으나 실제 시크릿 문자열이 비어 있음 → 레닥션 생략")
        return file_bytes

    uniq: List[str] = []
    seen = set()
    for v in sorted(set(secrets), key=lambda x: (-len(x), x)):
        if v not in seen:
            seen.add(v)
            uniq.append(v)
    secrets = uniq

    try:
        return redact_ole_bin_preserve_size(file_bytes, secrets, mask_preview=False)
    except Exception as e:
        log.info(f"[PPT] redact_ole_bin_preserve_size 예외: {e!r}")
        return file_bytes