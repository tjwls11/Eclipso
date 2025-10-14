import struct, olefile

def le16(b, off): 
    return struct.unpack_from("<H", b, off)[0]

def le32(b, off):
    return struct.unpack_from("<I", b, off)[0]


with olefile.OleFileIO("근희함.doc") as ole:
    word = ole.openstream("WordDocument").read()

base_len = 32
csw = le16(word, 32)
fibRgW_len = csw * 2
cslw = le32(word, 32 + 2 + fibRgW_len) # fibRgW 길이 + csw길이까지 포함
fibRgLw_off = 32 + 2 + fibRgW_len + 2
fibRgLw_len = cslw * 4

fib = {
    "base_len": base_len,
    "csw": csw,
    "fibRgW_len": fibRgW_len,
    "cslw": cslw,
    "fibRgLw_off": fibRgLw_off,
    "fibRgLw_len": fibRgLw_len,
}

#ccpHdd 읽기
ccpHdd = le32(word, fibRgLw_off + 0x0C)

for name, value in fib.items():
    print(f"{name} = {value}")

print(f"ccpHdd: {ccpHdd}")