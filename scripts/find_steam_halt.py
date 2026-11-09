with open(r"D:\Marathon-live\Marathon.exe", "rb") as f:
    data = f.read()

import re
pattern = b"The Steam API failed to initialize"
matches = [m.start() for m in re.finditer(pattern, data, re.IGNORECASE)]
print(f"Found {len(matches)} matches for '{pattern.decode()}':")
for m in matches:
    print(f"Offset 0x{m:X}")
    print("Context:", data[max(0, m - 32):min(len(data), m + 64)])
