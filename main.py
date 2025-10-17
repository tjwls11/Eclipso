import argparse, olefile, os
from core.utils import list_streams, find_direntry_tail
from core.ole_helper import overwrite_bigfat, overwrite_minifat_chain
from modules.body_replacer import process_body_stream
from modules.chart_replacer import process_bindata
from modules.bindata_finder import find_bindata_ids_from_sections

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("text")
    args = ap.parse_args()

    ole = olefile.OleFileIO(args.file)
    with open(args.file, "rb") as f:
        container = bytearray(f.read())

    streams = list_streams(ole)
    total_hits = 0
    print(f"총 스트림 {len(streams)}개")

    # 본문 처리
    for name in streams:
        if not name.startswith("BodyText/Section"):
            continue
        raw = ole.openstream(name).read()
        tail = name.split("/")[-1]
        entry = find_direntry_tail(ole, tail)
        cutoff = getattr(ole, "minisector_cutoff", 4096)
        which = "MiniFAT" if entry.size < cutoff else "FAT"

        new_raw, hits = process_body_stream(raw, args.text)
        if hits == 0: continue
        if which == "MiniFAT":
            overwrite_minifat_chain(ole, container, entry.isectStart, new_raw)
        else:
            overwrite_bigfat(ole, container, entry.isectStart, new_raw)
        total_hits += hits
        print(f"본문 치환: {name} → {hits}회")

    # 차트 처리
    bin_ids = find_bindata_ids_from_sections(ole)
    bindata_list = [s for s in streams if s.startswith("BinData/BIN") and s.endswith(".OLE")]
    targets = [f"BinData/BIN{idx:04d}.OLE" for idx in bin_ids if f"BinData/BIN{idx:04d}.OLE" in bindata_list]
    if not targets: targets = bindata_list

    for name in targets:
        raw = ole.openstream(name).read()
        tail = name.split("/")[-1]
        entry = find_direntry_tail(ole, tail)
        new_raw, hits = process_bindata(raw, args.text)
        if hits == 0: continue
        overwrite_bigfat(ole, container, entry.isectStart, new_raw)
        total_hits += hits
        print(f"차트 치환: {name} → {hits}회")

    out = os.path.splitext(args.file)[0] + "_edit.hwp"
    with open(out, "wb") as f:
        f.write(container)
    print(f"\n총 치환 {total_hits}회 → 저장됨: {out}")

if __name__ == "__main__":
    main()
