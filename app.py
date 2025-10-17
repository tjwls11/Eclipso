import struct, olefile, argparse, os

SST = 0x00FC
ENDOFCHAIN = 0xFFFFFFFE

# ─────────────────────────────
# SST 문자열 치환 (RichText/ExtRst 지원)
# ─────────────────────────────
def redact_in_sst(wb: bytes, old: str):
    new_wb = bytearray(wb)
    off, n = 0, len(wb)
    count = 0

    while off + 4 <= n:
        opcode, length = struct.unpack("<HH", wb[off:off+4])
        payload_off = off + 4
        payload = wb[payload_off:payload_off+length]

        if opcode == SST:
            if len(payload) < 8:
                break
            cstTotal, cstUnique = struct.unpack("<II", payload[:8])
            pos = 8

            for _ in range(cstUnique):
                if pos + 3 > length:
                    break
                cch = struct.unpack("<H", payload[pos:pos+2])[0]; pos+=2
                option = payload[pos]; pos+=1

                fHigh = option & 0x01
                fExt  = option & 0x04
                fRich = option & 0x08

                cRun, cbExtRst = 0, 0
                if fRich:
                    cRun = struct.unpack("<H", payload[pos:pos+2])[0]
                    pos += 2
                if fExt:
                    cbExtRst = struct.unpack("<I", payload[pos:pos+4])[0]
                    pos += 4

                # 문자열 본문
                if fHigh:
                    raw = payload[pos:pos+cch*2]; pos+=cch*2
                    text = raw.decode("utf-16le", errors="ignore")
                else:
                    raw = payload[pos:pos+cch]; pos+=cch
                    try:
                        text = raw.decode("cp949")  # 한국어 코드페이지 우선
                    except:
                        text = raw.decode("latin1", errors="ignore")

                # 치환
                if text == old:
                    redacted = "*" * len(text)
                    if fHigh:
                        patched = redacted.encode("utf-16le")
                    else:
                        patched = redacted.encode("cp949", errors="ignore")
                    patched = patched[:len(raw)].ljust(len(raw), b'*')
                    new_wb[payload_off + pos - len(raw):payload_off + pos] = patched
                    print(f"[INFO] '{text}' -> '{redacted}' 치환 완료")
                    count += 1

                # RichText/ExtRst 데이터 건너뛰기
                if cRun:
                    pos += cRun * 4
                if cbExtRst:
                    pos += cbExtRst

        off = payload_off + length
    return bytes(new_wb), count

# ─────────────────────────────
# Workbook 교체 (size 갱신 생략)
# ─────────────────────────────
def patch_xls(infile: str, old: str):
    ole = olefile.OleFileIO(infile)
    wb = ole.openstream("Workbook").read()
    new_wb, count = redact_in_sst(wb, old)

    with open(infile, "rb") as f:
        data = bytearray(f.read())

    for sid, entry in enumerate(ole.direntries):
        if entry and entry.name == "Workbook":
            start_sector = entry.isectStart
            sector_size = ole.sector_size

            s = start_sector
            pos = 0
            while s != ENDOFCHAIN and s != -1 and pos < len(new_wb):
                offset = (s+1) * sector_size
                chunk = new_wb[pos:pos+sector_size]
                data[offset:offset+len(chunk)] = chunk
                pos += sector_size
                s = ole.fat[s]

            break

    base, ext = os.path.splitext(infile)
    outfile = f"{base}_edit{ext}"
    with open(outfile, "wb") as f:
        f.write(data)

    print(f"[INFO] 총 {count}건 치환 완료")
    print(f"[+] 새 파일 저장 완료: {outfile}")

# ─────────────────────────────
# CLI
# ─────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("xls", help="원본 XLS 파일 경로")
    parser.add_argument("--old", required=True, help="찾을 문자열")
    args = parser.parse_args()
    patch_xls(args.xls, args.old)

if __name__ == "__main__":
    main()
