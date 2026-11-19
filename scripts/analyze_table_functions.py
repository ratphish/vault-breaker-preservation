import sys
sys.path.insert(0, 'D:/Marathon-preservation/tools/python')
import capstone

# .text raw offset = 0x600, VA = 0x1000
TEXT_RAW = 0x600
TEXT_VA = 0x1000

def rva_to_raw(rva):
    return rva - TEXT_VA + TEXT_RAW

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

with open('D:/Marathon-live/Marathon.exe', 'rb') as f:
    for target_rva, name in [(0x10763DF7, "Table 1 Loader"), (0x16BD1055, "Table 3 Loader")]:
        start_rva = target_rva - 0x60
        f.seek(rva_to_raw(start_rva))
        code = f.read(0x100)
        print(f"\n==================== {name} around 0x{target_rva:X} ====================")
        for ins in md.disasm(code, start_rva):
            marker = " <--- TARGET" if ins.address == target_rva else ""
            print(f"0x{ins.address:08X}: {ins.mnemonic:8} {ins.op_str}{marker}")
