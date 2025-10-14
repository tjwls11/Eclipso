import struct, olefile

with olefile.OleFileIO("근희함.doc") as ole:
    word = ole.openstream("WordDocument").read()

ccpHdd = struct.unpack_from("<I", word, 0x0068)[0]
print(f"ccpHdd = {ccpHdd}")
if ccpHdd > 0:
    print("헤더/푸터 문서 존재")
else:
    print("헤더/푸터 문서 없음")

for name in ole.listdir():
    print(name)