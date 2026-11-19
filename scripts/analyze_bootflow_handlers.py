import struct

data = open(r'D:\Marathon-live\mem_bootflow_table.bin', 'rb').read()
base = 0x00007FF70F850000

print("=== Bootflow Stage Table & Function Table Analysis ===")
# Let's inspect from 0x1600 to 0x1800
for off in range(0x1610, 0x1750, 8):
    val = struct.unpack('<Q', data[off:off+8])[0]
    rva = val - base
    table_rva = 0x32DA1690 + off
    idx = (off - 0x1610) // 8
    print(f"Index {idx:2d} | Table RVA 0x{table_rva:X} | Target VA 0x{val:016X} (RVA 0x{rva:X})")
