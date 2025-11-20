import io
import os
import re
import struct
import tempfile
import olefile
from typing import List, Dict, Any, Tuple, Optional

from server.core.redaction_rules import apply_redaction_rules
from server.core.normalize import normalization_text, normalization_index
from server.core.matching import find_sensitive_spans

SST = 0x00FC
CONTINUE = 0x003C
LABELSST = 0x00FD

def le16(b, off): return struct.unpack_from("<H", b, off)[0]
def le32(b, off): return struct.unpack_from("<I", b, off)[0]

def iter_biff_records(data: bytes):
    off, n = 0, len(data)
    while off + 4 <= n:
        opcode, length = struct.unpack_from("<HH", data, off)
        payload_off = off + 4
        payload = data[payload_off : payload_off + length]
        yield off, opcode, length, payload
        off = payload_off + length



