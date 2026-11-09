with open(r"D:\Marathon-live\Marathon.exe", "rb") as f:
    data = f.read()

import re
matches = [m.start() for m in re.finditer(b"marmot", data, re.IGNORECASE)]
print(f"Found {len(matches)} occurrences of 'marmot':")
for m in matches:
    snippet = data[max(0, m - 64):min(len(data), m + 128)]
    print(f"Offset 0x{m:X}: {snippet!r}\n")
