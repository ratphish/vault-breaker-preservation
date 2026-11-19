import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000
data = open("D:/Marathon-live/mem_area_30050000.bin", "rb").read()

target_rva = 0x3005D820
target_off = target_rva - 0x30050000

print(f"Disassembling Stage 6 (Table 1) at RVA 0x{target_rva:08X} (offset 0x{target_off:04X}):")
code = data[target_off:target_off + 256]
for ins in md.disasm(code, base + target_rva):
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}")
    if ins.mnemonic == 'ret' and ins.address > base + target_rva + 0x10:
        break
