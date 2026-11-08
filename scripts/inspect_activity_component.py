import struct
from pathlib import Path

p = Path("D:/Marathon-preservation/analysis/vault-reference-records/80B37FED.bin")
data = p.read_bytes()
print(f"80B37FED length: {len(data)}")

# Search for tags
for tag, name in [(0x80b37c7e, "activity_metadata_80B37C7E"), (0x8080b8f1, "wrapper_8080B8F1"), (0x8080a23f, "listener_8080A23F"), (0x8080a240, "listener_8080A240")]:
    pattern = struct.pack("<I", tag)
    pos = 0
    count = 0
    while True:
        pos = data.find(pattern, pos)
        if pos == -1: break
        count += 1
        slot = struct.unpack_from("<i", data, pos + 4)[0] if pos + 8 <= len(data) else None
        if count <= 15:
            print(f"Found {name} at offset {hex(pos)}: next_dword={hex(slot) if slot is not None else None}")
        pos += 1
    print(f"Total {name}: {count}")

# Check string paths in 80B37FED
for off in range(0, len(data)-4):
    if data[off:off+8] == b"activity" or data[off:off+7] == b"content":
        end = data.find(b"\0", off)
        s = data[off:end].decode("ascii", errors="ignore")
        print(f"String at {hex(off)}: {s}")
