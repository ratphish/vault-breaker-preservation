import struct
import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000

def inspect_vtable(name, path, target_rva):
    data = open(path, 'rb').read()
    # The dump was: fwrite(vt - 0x100, 1, 0x1000, fp)
    # So offset 0x100 is target_rva
    print(f"\n==================== {name} (RVA 0x{target_rva:X}) ====================")
    vt_offset = 0x100
    for idx in range(16):
        off = vt_offset + idx * 8
        val = struct.unpack('<Q', data[off:off+8])[0]
        rva = val - base
        print(f"vfunc[{idx:2d}]: 0x{val:016X} (RVA 0x{rva:X})")

inspect_vtable("State 7/8 vtable", "D:/Marathon-live/mem_vtable_2EF1EDC0.bin", 0x2EF1EDC0)
inspect_vtable("State 9 vtable", "D:/Marathon-live/mem_vtable_302832A0.bin", 0x302832A0)
