import struct

data = open("D:/Marathon-live/mem_bootflow_table.bin", "rb").read()
base = 0x00007FF70F850000

# There are 14 tables. Let's list their offset, pointer to Stage 8, and pointer to Stage 9
tables = [
    ("Table 0  (0x06D8)", 0x06D8),
    ("Table 1  (0x07E0)", 0x07E0),
    ("Table 2  (0x1610)", 0x1610),
    ("Table 3  (0x1780)", 0x1780),
    ("Table 4  (0x1808)", 0x1808),
    ("Table 5  (0x1A28)", 0x1A28),
    ("Table 6  (0x1AD0)", 0x1AD0),
    ("Table 7  (0x29C0)", 0x29C0),
    ("Table 8  (0x2D58)", 0x2D58),
    ("Table 9  (0x2F40)", 0x2F40),
    ("Table 10 (0x33A8)", 0x33A8),
    ("Table 11 (0x3570)", 0x3570),
    ("Table 12 (0x35C0)", 0x35C0),
    ("Table 13 (0x3AD0)", 0x3AD0),
]

print(f"{'Table':<18} | {'Stage 7 (Server Offline)':<25} | {'Stage 8 (SOS Actions)':<25} | {'Stage 9 (Manifest)'}")
print("-" * 95)
for name, off in tables:
    p7 = struct.unpack('<Q', data[off+7*8:off+8*8])[0]
    p8 = struct.unpack('<Q', data[off+8*8:off+9*8])[0]
    p9 = struct.unpack('<Q', data[off+9*8:off+10*8])[0]
    r7 = p7 - base if (p7 >> 32) == 0x7FF7 else 0
    r8 = p8 - base if (p8 >> 32) == 0x7FF7 else 0
    r9 = p9 - base if (p9 >> 32) == 0x7FF7 else 0
    print(f"{name:<18} | 0x{r7:08X} (VA {p7:012X}) | 0x{r8:08X} (VA {p8:012X}) | 0x{r9:08X}")
