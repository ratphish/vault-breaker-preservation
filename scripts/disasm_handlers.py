import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
base = 0x00007FF70F850000

for name, fn, rva in [("Handler 2EF1EDC0 (State 7/8)", "D:/Marathon-live/mem_vtable_2EF1EDC0.bin", 0x2EF1EDC0),
                      ("Handler 302832A0 (State 9)", "D:/Marathon-live/mem_vtable_302832A0.bin", 0x302832A0)]:
    data = open(fn, 'rb').read()
    code = data[0x100:0x100+128]
    print(f"\n==================== {name} ====================")
    for ins in md.disasm(code, rva):
        print(f"0x{ins.address:08X}:  {ins.mnemonic:<8} {ins.op_str}")
