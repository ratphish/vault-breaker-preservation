import struct

data = open("D:/Marathon-live/mem_bootflow_table.bin", "rb").read()
base = 0x00007FF70F850000

# Let's inspect the entire table area from 0x0000 to 0x1000
# Notice that at 0x1000 is Table 0 (names)
# Where is the master bootflow controller vtable?
for off in range(0, 0x1000, 8):
    val = struct.unpack('<Q', data[off:off+8])[0]
    if (val >> 32) == 0x7FF7:
        rva = val - base
        # check if it points to code or data
        pass
