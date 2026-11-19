import struct

with open('D:/Marathon-live/Marathon.exe', 'rb') as f:
    pe_data = f.read()

pe_off = struct.unpack_from('<I', pe_data, 0x3C)[0]
num_sec = struct.unpack_from('<H', pe_data, pe_off + 4 + 2)[0]
opt_hdr_size = struct.unpack_from('<H', pe_data, pe_off + 4 + 16)[0]
sec_off = pe_off + 4 + 20 + opt_hdr_size

sections = []
for i in range(num_sec):
    s = pe_data[sec_off + i*40 : sec_off + (i+1)*40]
    sname = s[:8].rstrip(b'\x00').decode('latin1')
    vsize, va, rsize, rptr = struct.unpack('<IIII', s[8:24])
    sections.append((sname, va, vsize, rptr, rsize))

targets = {
    'Table 0': 0x32DA1D68,
    'Table 1': 0x32DA1E70,
    'Master Table': 0x32DA2690,
    'Table 2': 0x32DA2CA0,
    'Table 3': 0x32DA2E10,
    'Func_30291240': 0x30291240,
    'Func_2EF4C7E0': 0x2EF4C7E0,
    'Func_2EF4C7F0': 0x2EF4C7F0,
}

print("Searching for RIP-relative instructions referencing targets in .text and code sections...")
# Scan .text section
for sname, va, vsize, rptr, rsize in sections:
    if sname not in ['.text']:
        continue
    print(f"Scanning section {sname} (VA 0x{va:X}..0x{va+vsize:X}, raw 0x{rptr:X})...")
    s_data = pe_data[rptr:rptr+rsize]
    for i in range(len(s_data) - 7):
        b0 = s_data[i]
        b1 = s_data[i+1]
        # Check 48 8D (LEA reg, [rip+disp]), 4C 8D, 48 8B (MOV reg, [rip+disp]), 4C 8B
        if (b0 in [0x48, 0x4C] and b1 in [0x8D, 0x8B]) or (b0 in [0xE8, 0xE9]):
            if b0 in [0xE8, 0xE9]:
                disp = struct.unpack_from('<i', s_data, i + 1)[0]
                ins_len = 5
            else:
                disp = struct.unpack_from('<i', s_data, i + 3)[0]
                ins_len = 7
            ins_rva = va + i
            target_rva = ins_rva + ins_len + disp
            for tname, trva in targets.items():
                if target_rva == trva:
                    print(f"[{sname}] RVA 0x{ins_rva:08X} (raw 0x{rptr+i:X}): refers to {tname} (0x{trva:08X}) with disp=0x{disp:08X}")
