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
cslw = le16(word, 32 + 2 + fibRgW_len) # fibRgW 길이 + csw길이까지 포함
fibRgLw_off = 32 + 2 + fibRgW_len + 2
fibRgLw_len = cslw * 4

#ccpHdd 읽기
ccpHdd = le32(word, fibRgLw_off + 0x0C)

cbRgFcLcb_off = fibRgLw_off + fibRgLw_len
cbRgFcLcb = le16(word, cbRgFcLcb_off)
fibRgFcLcbBlob_off = cbRgFcLcb_off + 2
fibRgFcLcbBlob_len = cbRgFcLcb * 8

#fcPlcHdd, lcbPlcHdd 읽기
index = 11
off = fibRgFcLcbBlob_off + index * 8
fcPlcHdd = le32(word, off)
lcbPlcHdd = le32(word, off + 4)


#출력 딕셔너리
fib = {
    "base_len": base_len,
    "csw": csw,
    "fibRgW_len": fibRgW_len,
    "cslw": cslw,
    "fibRgLw_off": fibRgLw_off,
    "fibRgLw_len": fibRgLw_len,
    "ccpHdd": ccpHdd,
    "cbRgFcLcb_off": cbRgFcLcb_off,
    "cbRgFcLcb": cbRgFcLcb,
    "fibRgFcLcbBlob_off": fibRgFcLcbBlob_off,
    "fibRgFcLcbBlob_len": fibRgFcLcbBlob_len,
    "fcPlcHdd": fcPlcHdd,
    "lcbPlcHdd": lcbPlcHdd,
}

for name, value in fib.items():
    print(f"{name} = {value}")
