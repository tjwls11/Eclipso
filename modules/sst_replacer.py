import struct

SST = 0x00FC

def redact_in_sst(wb: bytes, old: str):
    new_wb = bytearray(wb)
    off, n = 0, len(wb)
    count = 0

    while off + 4 <= n:
        opcode, length = struct.unpack("<HH", wb[off:off + 4])
        payload_off = off + 4
        payload = wb[payload_off:payload_off + length]

        if opcode == SST:
            if len(payload) < 8:
                break
            cstTotal, cstUnique = struct.unpack("<II", payload[:8])
            pos = 8

            for _ in range(cstUnique):
                if pos + 3 > length:
                    break
                cch = struct.unpack("<H", payload[pos:pos + 2])[0]; pos += 2
                option = payload[pos]; pos += 1

                fHigh = option & 0x01
                fExt = option & 0x04
                fRich = option & 0x08

                cRun, cbExtRst = 0, 0
                if fRich:
                    cRun = struct.unpack("<H", payload[pos:pos + 2])[0]
                    pos += 2
                if fExt:
                    cbExtRst = struct.unpack("<I", payload[pos:pos + 4])[0]
                    pos += 4

                if fHigh:
                    raw = payload[pos:pos + cch * 2]; pos += cch * 2
                    text = raw.decode("utf-16le", errors="ignore")
                else:
                    raw = payload[pos:pos + cch]; pos += cch
                    try:
                        text = raw.decode("cp949")
                    except:
                        text = raw.decode("latin1", errors="ignore")

                if text == old:
                    redacted = "*" * len(text)
                    patched = redacted.encode("utf-16le" if fHigh else "cp949", errors="ignore")
                    patched = patched[:len(raw)].ljust(len(raw), b'*')
                    new_wb[payload_off + pos - len(raw):payload_off + pos] = patched
                    print(f"'{text}' → '{redacted}' 치환 완료")
                    count += 1

                if cRun:
                    pos += cRun * 4
                if cbExtRst:
                    pos += cbExtRst

        off = payload_off + length
    return bytes(new_wb), count
