import struct

with open(r'D:\Marathon-live\Marathon.exe', 'rb') as f:
    dos_header = f.read(64)
    pe_offset = struct.unpack('<I', dos_header[60:64])[0]
    f.seek(pe_offset)
    pe_sig = f.read(4)
    coff_header = f.read(20)
    machine, num_sections, timedate, sym_ptr, num_sym, opt_hdr_size, characteristics = struct.unpack('<HHIIIHH', coff_header)
    opt_header = f.read(opt_hdr_size)
    
    # Read Data Directories (PE32+)
    # Import Directory is entry 1 (offset 112 in optional header for PE32+)
    import_dir_rva, import_dir_size = struct.unpack('<II', opt_header[120:128])
    print(f"Import Dir RVA: 0x{import_dir_rva:X}, Size: 0x{import_dir_size:X}")
    
    # Read sections
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

    import_offset = rva_to_offset(import_dir_rva)
    print(f"Import Dir File Offset: 0x{import_offset:X}")
    
    # Read Import Descriptors (20 bytes each)
    f.seek(import_offset)
    while True:
        desc = f.read(20)
        orig_first_thunk, timedate_stamp, forwarder_chain, name_rva, first_thunk = struct.unpack('<IIIII', desc)
        if name_rva == 0:
            break
        name_off = rva_to_offset(name_rva)
        f.seek(name_off)
        dll_name = b''
        while True:
            c = f.read(1)
            if c == b'\x00': break
            dll_name += c
        dll_name_str = dll_name.decode('latin1')
        
        # Check if steam_api
        if 'steam' in dll_name_str.lower():
            print(f"DLL: {dll_name_str}, IAT FirstThunk RVA: 0x{first_thunk:X}, OrigFirstThunk: 0x{orig_first_thunk:X}")
            thunk_rva = orig_first_thunk if orig_first_thunk else first_thunk
            thunk_off = rva_to_offset(thunk_rva)
            iat_rva = first_thunk
            f.seek(thunk_off)
            idx = 0
            while True:
                entry = struct.unpack('<Q', f.read(8))[0]
                if entry == 0: break
                curr_iat_rva = iat_rva + (idx * 8)
                if entry & 0x8000000000000000:
                    print(f"  Ordinal: {entry & 0xFFFF} -> IAT RVA: 0x{curr_iat_rva:X}")
                else:
                    name_ptr = rva_to_offset(entry)
                    saved = f.tell()
                    f.seek(name_ptr + 2)
                    fn_name = b''
                    while True:
                        c = f.read(1)
                        if c == b'\x00': break
                        fn_name += c
                    f.seek(saved)
                    print(f"  {fn_name.decode('latin1')} -> IAT RVA: 0x{curr_iat_rva:X}")
                idx += 1
        f.seek(import_offset + (sections[0][3] if False else 0)) # return to next desc
        import_offset += 20
        f.seek(import_offset)
