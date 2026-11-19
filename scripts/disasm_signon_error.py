import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

data = open(r'D:\Marathon-live\code_signon_error_C972FFC.bin', 'rb').read()
rva = 0xC972FFC
start_rva = rva - 256
print(f"Disassembling code around 0x{rva:X}...")
for ins in md.disasm(data, start_rva):
    marker = "  <=== TARGET" if ins.address == rva else ""
    print(f"0x{ins.address:08X}: {ins.mnemonic:<8} {ins.op_str}{marker}")
