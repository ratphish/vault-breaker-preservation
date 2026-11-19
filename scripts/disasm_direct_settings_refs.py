import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000

for rva in [0x521F258, 0x7BEAE37, 0x9FA91D6, 0xC01AD04]:
    fn = f"D:/Marathon-live/code_bootflow_ref_{rva:X}.bin"
    data = open(fn, 'rb').read()
    # The dump is 512 bytes: 256 bytes before the instruction, instruction at +256
    code = data[256-32:256+128]
    start_addr = base + rva - 32
    print(f"\n==================== Code around RVA 0x{rva:X} ====================")
    for ins in md.disasm(code, start_addr):
        prefix = "-> " if ins.address == base + rva else "   "
        print(f"{prefix}0x{ins.address:016X} (RVA 0x{ins.address - base:08X}): {ins.mnemonic:<8} {ins.op_str}")
