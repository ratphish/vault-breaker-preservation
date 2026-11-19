import struct

data = open("D:/Marathon-live/mem_area_30280000.bin", "rb").read()
base = 0x00007FF70F850000
area_rva = 0x30280000

# Function 0x30291240 is at offset 0x11240
off = 0x11240
# Let's inspect the two calls:
# +0x07: call 1
# +0x0C: call 2
# +0x15: call 3 (if eax < edx)
# +0x2B: call 4 (if eax >= edx)

for call_off in [0x07, 0x0C, 0x15, 0x2B]:
    opcode = data[off + call_off]
    disp = struct.unpack('<i', data[off + call_off + 1 : off + call_off + 5])[0]
    call_ins_rva = 0x30291240 + call_off
    target_rva = call_ins_rva + 5 + disp
    print(f"Call at +0x{call_off:02X} (RVA 0x{call_ins_rva:08X}): opcode=0x{opcode:02X}, disp=0x{disp:08X} -> Target RVA 0x{target_rva:08X} (VA 0x{base + target_rva:016X})")
