with open(r"D:\Marathon-live\Marathon.exe", "rb") as f:
    data = f.read()

import re
matches = [m.start() for m in re.finditer(b"steam_api64", data, re.IGNORECASE)]
print(f"Found {len(matches)} occurrences of 'steam_api64':")
for m in matches:
    snippet = data[max(0, m - 32):min(len(data), m + 48)]
    print(f"Offset 0x{m:X}: {snippet!r}")
