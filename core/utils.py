import hashlib

def bits(v, o, n): 
    return (v >> o) & ((1 << n) - 1)

def hexdump(b: bytes, width=16):
    return " ".join(f"{x:02X}" for x in b[:width])

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]

def sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]

def pad_to_length(blob: bytes, target: int) -> bytes:
    if len(blob) < target: 
        return blob + b"\x00" * (target - len(blob))
    if len(blob) > target: 
        return blob[:target]
    return blob

def list_streams(ole):
    return ["/".join(p) for p in ole.listdir(streams=True, storages=False)]

def find_direntry_tail(ole, tail: str):
    for e in ole.direntries:
        if e and e.name == tail:
            return e
    return None
