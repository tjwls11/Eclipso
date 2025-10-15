import olefile
import struct

def le16(b, off): 
    return struct.unpack_from("<H", b, off)[0]

def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]

with olefile.OleFileIO("test.doc") as ole:
    word_data = ole.openstream("WordDocument").read()

    fib_base_flags = struct.unpack_from("<H", word_data, 0x000A)[0]

    #fComplex확인
    fComplex = (fib_base_flags & 0x0004) != 0


fcMin = le32(word_data, 0x0018)
fcMac = le32(word_data, 0x001C)
doc_area = fcMac - fcMin

print(f"fcMin: 0x{fcMin:08X} ({fcMin})")
print(f"fcMac: 0x{fcMac:08X} ({fcMac})")
print(f"doc_erea: {doc_area} (0x{fcMin:08X} ~ 0x{(fcMac - 1):08X})")