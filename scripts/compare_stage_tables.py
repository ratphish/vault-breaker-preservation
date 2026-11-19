import struct

data = open(r'D:\Marathon-live\mem_bootflow_table.bin', 'rb').read()
base = 0x00007FF70F850000

# Let's inspect the tables
# We know the tables have entries for 22 stages.
# Stage 8 is index 8.

# Let's check every 8-byte aligned offset in data
tables = [
    ("Table at 0x06D8 (RVA 0x32DA1D68)", 0x06D8),
    ("Table at 0x07E0 (RVA 0x32DA1E70)", 0x07E0),
    ("Table at 0x1610 (RVA 0x32DA2CA0)", 0x1610),
    ("Table at 0x1780 (RVA 0x32DA2E10)", 0x1780),
    ("Table at 0x1808 (RVA 0x32DA2E98)", 0x1808),
    ("Table at 0x1A28 (RVA 0x32DA30B8)", 0x1A28),
    ("Table at 0x1AD0 (RVA 0x32DA3160)", 0x1AD0),
    ("Table at 0x29C0 (RVA 0x32DA4050)", 0x29C0),
    ("Table at 0x2D58 (RVA 0x32DA43E8)", 0x2D58),
    ("Table at 0x2F40 (RVA 0x32DA45D0)", 0x2F40),
    ("Table at 0x33A8 (RVA 0x32DA4A38)", 0x33A8),
    ("Table at 0x3570 (RVA 0x32DA4C00)", 0x3570),
    ("Table at 0x35C0 (RVA 0x32DA4C50)", 0x35C0),
    ("Table at 0x3AD0 (RVA 0x32DA5160)", 0x3AD0),
]

for name, off in tables:
    ptr8 = struct.unpack('<Q', data[off + 8*8 : off + 9*8])[0]
    rva8 = ptr8 - base
    ptr7 = struct.unpack('<Q', data[off + 7*8 : off + 8*8])[0]
    rva7 = ptr7 - base
    ptr6 = struct.unpack('<Q', data[off + 6*8 : off + 7*8])[0]
    rva6 = ptr6 - base
    print(f"{name}:")
    print(f"   Stage 6: 0x{ptr6:016X} (RVA 0x{rva6:08X})")
    print(f"   Stage 7: 0x{ptr7:016X} (RVA 0x{rva7:08X})")
    print(f"   Stage 8: 0x{ptr8:016X} (RVA 0x{rva8:08X})")
