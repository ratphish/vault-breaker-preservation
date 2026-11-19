constructors = [
    (0x2F03EA26, 0x3d64273),
    (0x2F2ECBC6, 0x3ab60d3),
    (0x2F526D76, 0x387bf23),
    (0x2F54C876, 0x3856423),
    (0x2F762E56, 0x363fe43),
    (0x2F7EBD56, 0x35b6f43),
    (0x2F91C476, 0x3486823),
    (0x303B3496, 0x29ef803),
    (0x303DCC16, 0x29c6083),
    (0x305B6AE6, 0x27ec1b3),
    (0x30A92076, 0x2310c23),
    (0x30B25546, 0x227d753),
    (0x30CD7956, 0x20cb343),
    (0x30FF65C6, 0x1dac6d3),
    (0x3114E7A6, 0x1c544f3),
]

data = open("D:/Marathon-live/mem_bootflow_table.bin", "rb").read()
base = 0x00007FF70F850000

for code_rva, disp in constructors:
    # lea rax, [rip + disp]
    # instruction is 7 bytes
    target_rva = code_rva + 7 + disp
    target_off = target_rva - 0x32DA1690
    print(f"Constructor at RVA 0x{code_rva:08X} assigns vtable RVA 0x{target_rva:08X} (offset in dump 0x{target_off:04X})")
