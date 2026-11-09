import re

with open(r"D:\Marathon-live\Marathon.exe", "rb") as f:
    data = f.read()

# search ASCII and UTF16
for pattern in [b"Problem reading game content", b"P\x00r\x00o\x00b\x00l\x00e\x00m", b"m\x00a\x00r\x00m\x00o\x00t"]:
    matches = [m.start() for m in re.finditer(pattern, data, re.IGNORECASE)]
    print(f"Pattern {pattern}: found {len(matches)} matches")
    for m in matches:
        print(f"  0x{m:X}: {data[m:m+64]!r}")
