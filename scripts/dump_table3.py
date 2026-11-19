import struct

data = open("D:/Marathon-live/mem_bootflow_table.bin", "rb").read()
base = 0x00007FF70F850000

off = 0x1780 # Table 3
print("=== Table 3 (0x1780 / RVA 0x32DA2E10) ===")
for i in range(22):
    p = struct.unpack('<Q', data[off + i*8 : off + (i+1)*8])[0]
    r = p - base if (p >> 32) == 0x7FF7 else 0
    print(f"Stage {i:2d}: 0x{r:08X} (VA 0x{p:016X})")
