import re
from core.utils import list_streams

def find_bindata_ids_from_sections(ole):
    bins = {}
    for nm in list_streams(ole):
        m = re.fullmatch(r"BinData/BIN(\d{4})\.OLE", nm)
        if m:
            bins[int(m.group(1))] = nm
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
