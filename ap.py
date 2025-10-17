data = bytes.fromhex(
    "26 00 52 00 14 BC E5 B2 00 AE 20 00 4C 01 A4 C2 B8 D2 20 00 38 BB 1C C1".replace(" ", "")
)

text = data.decode("utf-16le", errors="replace")
print(text)