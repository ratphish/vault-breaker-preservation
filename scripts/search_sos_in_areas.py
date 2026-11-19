import glob
import re

for fn in sorted(glob.glob("D:/Marathon-live/mem_area_*.bin")):
    data = open(fn, 'rb').read()
    # Search for printable ASCII strings of length >= 5
    strings = []
    s = ""
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            s += chr(b)
        else:
            if len(s) >= 5:
                strings.append((i - len(s), s))
            s = ""
    print(f"\n==================== {fn} ({len(strings)} strings) ====================")
    for off, strval in strings:
        if any(k in strval.lower() for k in ["sos", "action", "task", "manifest", "content", "bootflow", "online", "service", "login", "signon"]):
            print(f"  +0x{off:04X}: {strval}")
