import struct

data = open(r'C:\Program Files (x86)\Steam\steamclient64.dll', 'rb').read()

pe_off = struct.unpack('<I', data[0x3C:0x40])[0]
num_sections = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
opt_hdr_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
sec_hdr_start = pe_off + 24 + opt_hdr_size

sections = []
for i in range(num_sections):
    sec = data[sec_hdr_start + i*40 : sec_hdr_start + (i+1)*40]
    name = sec[:8].strip(b'\x00').decode('latin1')
    vsize, vrva, rsize, rraw = struct.unpack('<IIII', sec[8:24])
    sections.append((name, vrva, vsize, rraw, rsize))

def rva_to_raw(rva):
    for name, vrva, vsize, rraw, rsize in sections:
        if vrva <= rva < vrva + vsize:
            return rraw + (rva - vrva)
    return None

def raw_to_rva(raw):
    for name, vrva, vsize, rraw, rsize in sections:
        if rraw <= raw < rraw + rsize:
            return vrva + (raw - rraw)
    return None

str_rva = 0x1313620

for name, vrva, vsize, rraw, rsize in sections:
    sec_data = data[rraw:rraw+rsize]
    # Check 64-bit pointers
    for i in range(0, len(sec_data)-8, 8):
        val = struct.unpack('<Q', sec_data[i:i+8])[0]
        # In steamclient64.dll default image base is usually 0x38000000 or similar
        # let's check
    # Check RIP relative: [rip + disp] = str_rva
    for i in range(0, len(sec_data)-7):
        b = sec_data[i]
        if b in (0x48, 0x4C):
            if sec_data[i+1] == 0x8D and (sec_data[i+2] & 0xC7) == 0x05: # lea reg, [rip+disp]
                disp = struct.unpack('<i', sec_data[i+3:i+7])[0]
                instr_rva = vrva + i
                target_rva = instr_rva + 7 + disp
                if target_rva == str_rva:
                    print(f"LEA ref at RVA 0x{instr_rva:X} in section {name}")
