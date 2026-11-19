import struct

data = open("D:/Marathon-live/mem_area_2EF40000.bin", "rb").read()
base = 0x00007FF70F850000
area_rva = 0x2EF40000
target_rva = 0x2EF4C7F0

print(f"Searching for CALLs to 0x{target_rva:08X} in mem_area_2EF40000...")
# An x86-64 CALL rel32 is: 0xE8 disp32
# target_rva = call_rva + 5 + disp32
# disp32 = target_rva - (call_rva + 5)

for i in range(len(data) - 5):
    if data[i] == 0xE8:
        disp = struct.unpack('<i', data[i+1:i+5])[0]
        call_rva = area_rva + i
        if call_rva + 5 + disp == target_rva:
            print(f"Found CALL at RVA 0x{call_rva:08X} (offset 0x{i:04X})")

    # Also check JMP rel32 (0xE9)
    if data[i] == 0xE9:
        disp = struct.unpack('<i', data[i+1:i+5])[0]
        jmp_rva = area_rva + i
        if jmp_rva + 5 + disp == target_rva:
            print(f"Found JMP at RVA 0x{jmp_rva:08X} (offset 0x{i:04X})")
