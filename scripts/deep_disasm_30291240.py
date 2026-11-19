import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True
base = 0x00007FF70F850000
data = open("D:/Marathon-live/mem_area_30280000.bin", "rb").read()

target_rva = 0x30291240
target_off = target_rva - 0x30280000

print(f"=== Full Disassembly of 0x{target_rva:08X} (offset 0x{target_off:04X}) ===")
code = data[target_off:target_off + 128]
insns = list(md.disasm(code, base + target_rva))
for ins in insns:
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}")
    if ins.mnemonic == 'ret' and ins.address > base + target_rva + 0x10:
        break
