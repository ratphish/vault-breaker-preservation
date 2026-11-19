import struct

data = open(r'D:\Marathon-live\mem_bootflow_table.bin', 'rb').read()
base = 0x00007FF70F850000

# String names table is at offset 0x1098 (RVA 0x32DA2728)
names = []
for i in range(23):
    ptr = struct.unpack_from('<Q', data, 0x1098 + i * 8)[0]
    rva = ptr - base
    off_in_dump = rva - 0x32DA1690
    end_str = data.find(b'\x00', off_in_dump)
    s = data[off_in_dump:end_str].decode('latin1')
    names.append(s)

tables = [
    ("Table 0 (0x32DA1D68)", 0x06D8),
    ("Table 1 (0x32DA1E70)", 0x07E0),
    ("Table 2 (0x32DA2CA0)", 0x1610),
    ("Table 3 (0x32DA2E10)", 0x1780),
]

print(f"{'Stage':<6} | {'Stage Name':<38} | " + " | ".join([f"{t[0]:<22}" for t in tables]))
print("-" * 140)

for st in range(23):
    line = f"{st:<6} | {names[st]:<38}"
    for name, offset in tables:
        ptr = struct.unpack_from('<Q', data, offset + st * 8)[0]
        rva = ptr - base
        line += f" | 0x{rva:08X} ({ptr:016X})"
    print(line)
