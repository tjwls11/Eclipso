import os, olefile
from core.ole_helper import overwrite_bigfat
from modules.sst_replacer import redact_in_sst

ENDOFCHAIN = 0xFFFFFFFE

def patch_xls(infile: str, old: str):
    ole = olefile.OleFileIO(infile)
    wb = ole.openstream("Workbook").read()
    new_wb, count = redact_in_sst(wb, old)

    with open(infile, "rb") as f:
        data = bytearray(f.read())

    for entry in ole.direntries:
        if entry and entry.name == "Workbook":
            overwrite_bigfat(ole, data, entry.isectStart, new_wb)
            break

    base, ext = os.path.splitext(infile)
    outfile = f"{base}_edit{ext}"
    with open(outfile, "wb") as f:
        f.write(data)

    print(f"총 {count}건 치환 완료")
    print(f"새 파일 저장 완료: {outfile}")
