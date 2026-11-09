with open(r"D:\Marathon-live\MarathonLauncher.exe", "rb") as f:
    data = f.read()

import re
# Find strings like Marathon.exe or arguments
matches = [m.start() for m in re.finditer(b"Marathon\\.exe", data, re.IGNORECASE)]
print(f"Marathon.exe occurrences in Launcher: {len(matches)}")
for m in matches:
    print(data[max(0, m - 32):min(len(data), m + 64)])

# Find command line switches or strings in Launcher
pattern = re.compile(b"-[a-zA-Z0-9_]+")
switches = set(m.group(0).decode() for m in pattern.finditer(data))
print("Switches in Launcher:", switches)
