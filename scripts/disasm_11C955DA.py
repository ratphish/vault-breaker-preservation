import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000
data = open("D:/Marathon-live/code_bootflow_ref_11C955DA.bin", "rb").read()

rva = 0x11C955DA
code = data[256-32:256+64]
start_addr = base + rva - 32
for ins in md.disasm(code, start_addr):
    marker = "  <=== TARGET" if ins.address == base + rva else ""
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}{marker}")
