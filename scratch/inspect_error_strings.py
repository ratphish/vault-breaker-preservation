import struct

# In disasm:
# At offset 0xC972626 (RVA 0xC973026):
# 48 8D 05 3F 5B 43 26 (7 bytes): lea rax, [rip + 0x26435B3F]
# Next instr is at RVA 0xC973026 + 7 = 0xC97302D
# rip = 0xC97302D
# target RVA = 0xC97302D + 0x26435B3F = 0x32DA8B6C!

with open(r'D:\Marathon-live\Marathon.exe', 'rb') as f:
    dos_header = f.read(64)
    pe_offset = struct.unpack('<I', dos_header[60:64])[0]
    f.seek(pe_offset + 4 + 2)
    num_sections = struct.unpack('<H', f.read(2))[0]
    opt_hdr_size = struct.unpack('<H', f.read(16)[12:14])[0]
    f.seek(pe_offset + 24 + opt_hdr_size)
    sections = []
    for i in range(num_sections):
        sec = f.read(40)
        name = sec[:8].rstrip(b'\x00').decode('latin1')
        vsize, vaddr, raw_size, raw_ptr = struct.unpack('<IIII', sec[8:24])
        sections.append((name, vaddr, vsize, raw_ptr, raw_size))
        
    def rva_to_off(rva):
        for name, vaddr, vsize, raw_ptr, raw_size in sections:
            if vaddr <= rva < vaddr + vsize:
                return raw_ptr + (rva - vaddr), name
        return None, None

    # Let's inspect the target of lea rax at 0xC973026
    next_rip = 0xC97302D
    disp = 0x26435B3F
    target_rva = next_rip + disp
    off, sec = rva_to_off(target_rva)
    print(f"Target RVA: 0x{target_rva:X} -> Offset: 0x{off:X} in {sec}")
    if off:
        f.seek(off)
        str_bytes = f.read(64)
        print("Data at target:", str_bytes)

    # Let's inspect other lea rax around here
    # -048: 48 8D 05 49 5B 43 26 -> rip = 0xC9725FF + 7 = 0xC973006, disp = 0x26435B49 -> RVA = 0x32DA8B4F
    for rel_rip, disp_val in [(0xC973006, 0x26435B49), (0xC97302D, 0x26435B3F), (0xC973059, 0x26435B21), (0xC973085, 0x26435B0D)]:
        trva = rel_rip + disp_val
        toff, tsec = rva_to_off(trva)
        if toff:
            f.seek(toff)
            print(f"RVA 0x{trva:X} ({tsec}): {f.read(32)}")
