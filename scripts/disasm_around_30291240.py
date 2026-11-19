import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000
data = open("D:/Marathon-live/mem_area_30280000.bin", "rb").read()

target_rva = 0x30291240
target_off = target_rva - 0x30280000

print("=== Disassembly before 0x30291240 (offset 0x11200..0x11240) ===")
for ins in md.disasm(data[target_off - 64 : target_off], base + target_rva - 64):
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}")

print("\n=== Disassembly after 0x30291276 (offset 0x11276..0x112C0) ===")
for ins in md.disasm(data[target_off + 54 : target_off + 128], base + target_rva + 54):
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}")
