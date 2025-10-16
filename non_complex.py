import olefile
import struct

def le16(b, off): 
    return struct.unpack_from("<H", b, off)[0]

def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]

with olefile.OleFileIO("test.doc") as ole:
    word_data = ole.openstream("WordDocument").read()

#fComplex확인
fib_base_flags = struct.unpack_from("<H", word_data, 0x000A)[0]
fComplex = (fib_base_flags & 0x0004) != 0


fcMin = le32(word_data, 0x0018)
fcMac = le32(word_data, 0x001C)
ccpText = le32(word_data, 0x004C)    # main document text length
ccpFtn  = le32(word_data, 0x0050)    # footnote length
ccpHdr  = le32(word_data, 0x0054)    # header/footer length

#계산
doc_start = fcMin
doc_end = fcMin + ccpText

ftn_start = doc_end
ftn_end = ftn_start + ccpFtn

hdr_start = ftn_end
hdr_end = hdr_start + ccpHdr


# 출력
print(f"fComplex: {fComplex}")
print(f"fcMin: 0x{fcMin:08X} ({fcMin})")
print(f"fcMac: 0x{fcMac:08X} ({fcMac})")

print(f"doc_area (ccpText): 0x{doc_start:08X} ~ 0x{doc_end - 1:08X} ({ccpText})")
print(f"footnote_area (ccpFtn): 0x{ftn_start:08X} ~ 0x{ftn_end - 1:08X} ({ccpFtn})")
print(f"header_area (ccpHdr): 0x{hdr_start:08X} ~ 0x{hdr_end - 1:08X} ({ccpHdr})")


# ------ 압축여부 확인 ------
# FIB에서 fcClx, lcbClx 읽기
fcClx = le32(word_data, 0x01A2)
lcbClx = le32(word_data, 0x01A6)

clx = word_data[fcClx:fcClx + lcbClx]
print(f"fcClx: {fcClx}")
print(f"lcbClx: {lcbClx}")
print(f"Clx: {clx}")


