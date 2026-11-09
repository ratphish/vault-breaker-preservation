with open(r"D:\Marathon-live\MarathonLauncher.exe", "rb") as f:
    data = f.read()

import re
matches = [m.start() for m in re.finditer(b"steam_api64", data, re.IGNORECASE)]
print(f"Launcher: Found {len(matches)} occurrences of 'steam_api64':")
for m in matches:
    snippet = data[max(0, m - 32):min(len(data), m + 48)]
    print(f"Offset 0x{m:X}: {snippet!r}")

# Also check UTF-16LE
matches16 = [m.start() for m in re.finditer(b"s\x00t\x00e\x00a\x00m\x00_\x00a\x00p\x00i\x006\x004", data, re.IGNORECASE)]
print(f"Launcher UTF16: Found {len(matches16)} occurrences:")
for m in matches16:
    snippet = data[max(0, m - 32):min(len(data), m + 48)]
    print(f"Offset 0x{m:X}: {snippet!r}")
