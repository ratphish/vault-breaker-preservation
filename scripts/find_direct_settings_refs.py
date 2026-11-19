import struct

base = 0x00007FF70F850000
target_rva = 0x32D28FC8
target_va = base + target_rva

print(f"Target VA for '%s/direct_settings/%s/%s.json': 0x{target_va:016X} (RVA 0x{target_rva:08X})")

# Let's check mem_func_state8_2EF4C7E0.bin, mem_func_state7_2EF77E60.bin, mem_func_state6_3005D820.bin
import glob
for fn in glob.glob("D:/Marathon-live/mem_*.bin"):
    data = open(fn, 'rb').read()
    # Search for RIP-relative disp or 32-bit offset or 64-bit pointer
    # Search 64-bit pointer
    pack8 = struct.pack('<Q', target_va)
    if pack8 in data:
        print(f"Found absolute 64-bit VA in {fn} at offset 0x{data.find(pack8):X}")
