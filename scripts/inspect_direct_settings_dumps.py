import os
from pathlib import Path

for fn in ["mem_direct_settings_32D28F30.bin", "mem_direct_settings_32DA9B86.bin", "mem_direct_settings_32DC701C.bin"]:
    p = Path("D:/Marathon-live") / fn
    if p.exists():
        data = p.read_bytes()
        print(f"\n==================== {fn} ({len(data)} bytes) ====================")
        # Search for printable ASCII strings of length >= 4
        s = ""
        offset = 0
        strings = []
        for i, b in enumerate(data):
            if 32 <= b <= 126:
                s += chr(b)
            else:
                if len(s) >= 4:
                    strings.append((i - len(s), s))
                s = ""
        if len(s) >= 4:
            strings.append((len(data) - len(s), s))
        for off, strval in strings:
            print(f"  +0x{off:04X}: {strval}")
