import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000

# Let's inspect mem_func_state8_2EF4C7E0.bin in detail
data = open("D:/Marathon-live/mem_func_state8_2EF4C7E0.bin", "rb").read()
print(f"Total size: {len(data)}")

# Disassemble from 0 to 1024 bytes
insns = list(md.disasm(data[:1024], base + 0x2EF4C7E0))
for ins in insns:
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}")
