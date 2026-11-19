import struct

base = 0x00007FF70F850000
target_rva = 0x32DA2E10
target_va = base + target_rva

areas = {
    "mem_area_2EF40000.bin": 0x2EF40000,
    "mem_area_2EF70000.bin": 0x2EF70000,
    "mem_area_30050000.bin": 0x30050000,
    "mem_area_30280000.bin": 0x30280000,
}

print(f"Searching for Table 3 (0x{target_rva:08X}) references...")
for fn, area_rva in areas.items():
    data = open(f"D:/Marathon-live/{fn}", "rb").read()
    # Search for RIP-relative lea reg, [rip + disp32]
    # target_rva = ins_rva + 7 + disp32 -> disp32 = target_rva - ins_rva - 7
    for i in range(len(data) - 7):
        # 48 8d / 4c 8d / 48 8b / 4c 8b
        if data[i] in [0x48, 0x4C] and data[i+1] in [0x8D, 0x8B]:
            disp = struct.unpack('<i', data[i+3:i+7])[0]
            ins_rva = area_rva + i
            if ins_rva + 7 + disp == target_rva:
                print(f"[{fn}] Found ref to Table 3 at RVA 0x{ins_rva:08X} (offset 0x{i:04X})")
