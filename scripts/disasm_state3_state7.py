import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000
data = open("D:/Marathon-live/mem_func_state7_2EF77E60.bin", "rb").read()

print("==================== State 7 at 0x2EF77E60 ====================")
code7 = data[:0xA0]
for ins in md.disasm(code7, base + 0x2EF77E60):
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}")

print("\n==================== State 3 at 0x2EF77F00 ====================")
code3 = data[0xA0:0xA0 + 256]
for ins in md.disasm(code3, base + 0x2EF77F00):
    print(f"0x{ins.address:016X} (RVA 0x{ins.address-base:08X}): {ins.mnemonic:<8} {ins.op_str}")
