import glob
import struct

areas = {
    "mem_area_2EF40000.bin": 0x2EF40000,
    "mem_area_2EF70000.bin": 0x2EF70000,
    "mem_area_30050000.bin": 0x30050000,
    "mem_area_30280000.bin": 0x30280000,
}

targets = [0x2EF4C7E0, 0x2EF4C7F0, 0x2EF77E60]

for fn, area_rva in areas.items():
    data = open(f"D:/Marathon-live/{fn}", "rb").read()
    for trva in targets:
        for i in range(len(data) - 5):
            if data[i] in [0xE8, 0xE9]:
                disp = struct.unpack('<i', data[i+1:i+5])[0]
                ins_rva = area_rva + i
                if ins_rva + 5 + disp == trva:
                    op = "CALL" if data[i] == 0xE8 else "JMP"
                    print(f"[{fn}] Found {op} to 0x{trva:08X} at RVA 0x{ins_rva:08X}")
