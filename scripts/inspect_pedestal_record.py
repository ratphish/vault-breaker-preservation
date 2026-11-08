import struct
from pathlib import Path

p = Path("D:/Marathon-preservation/analysis/vault-reference-records/80B38567.bin")
data = p.read_bytes()
print(f"80B38567 length: {len(data)}")

# Search for tags
for tag, name in [(0x80b38561, "instance_metadata_80B38561"), (0x80b38555, "definition_metadata_80B38555"), (0x8080a23f, "listener_8080A23F"), (0x8080a240, "listener_8080A240"), (0x8080b8f1, "wrapper_8080B8F1")]:
    pattern = struct.pack("<I", tag)
    pos = 0
    while True:
        pos = data.find(pattern, pos)
        if pos == -1: break
        slot = struct.unpack_from("<i", data, pos + 4)[0] if pos + 8 <= len(data) else None
        print(f"Found {name} at offset {hex(pos)}: next_dword={hex(slot) if slot is not None else None}")
        pos += 1

# Check string paths in 80B38567
for off in range(0, len(data)-4):
    if data[off:off+7] == b"content":
        end = data.find(b"\0", off)
        s = data[off:end].decode("ascii", errors="ignore")
        print(f"Path string at {hex(off)}: {s}")
