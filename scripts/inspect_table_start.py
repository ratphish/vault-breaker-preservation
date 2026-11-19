import struct

data = open('D:/Marathon-live/mem_bootflow_table.bin', 'rb').read()
base = 0x00007FF70F850000

for i in range(0, 0x800, 16):
    p1 = struct.unpack('<Q', data[i:i+8])[0]
    p2 = struct.unpack('<Q', data[i+8:i+16])[0]
    r1 = (p1 - base) if (p1 >> 32) == 0x7FF7 else 0
    r2 = (p2 - base) if (p2 >> 32) == 0x7FF7 else 0
    s1 = f"0x{r1:08X}" if r1 else f"{p1:016X}"
    s2 = f"0x{r2:08X}" if r2 else f"{p2:016X}"
    print(f"+0x{i:04X} (RVA 0x{0x32DA1690 + i:08X}): {s1} | {s2}")
