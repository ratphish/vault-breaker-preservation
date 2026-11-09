import struct

with open(r'D:\Marathon-live\Marathon.exe', 'rb') as f:
    dos_header = f.read(64)
    pe_offset = struct.unpack('<I', dos_header[60:64])[0]
    f.seek(pe_offset + 24)
    opt_header = f.read(240)
    
    # Read sections
    f.seek(pe_offset + 24 + struct.unpack('<H', opt_header[16:18])[0] if False else pe_offset + 24 + 240)
    # wait, num_sections:
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
        
    def rva_to_offset(rva):
        for name, vaddr, vsize, raw_ptr, raw_size in sections:
            if vaddr <= rva < vaddr + vsize:
                return raw_ptr + (rva - vaddr)
        return None

    import_offset = rva_to_offset(0x3352FDE8)
    f.seek(import_offset)
    while True:
        desc = f.read(20)
        orig_first_thunk, timedate, fwd, name_rva, first_thunk = struct.unpack('<IIIII', desc)
        if name_rva == 0: break
        pos = f.tell()
        name_off = rva_to_offset(name_rva)
        f.seek(name_off)
        dll_name = b''
        while True:
            c = f.read(1)
            if c == b'\x00': break
            dll_name += c
        print(f"DLL: {dll_name.decode('latin1')}")
        f.seek(pos)
