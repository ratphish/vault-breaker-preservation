import struct

# Let's inspect the PE header of Marathon.exe
with open(r'D:\Marathon-live\Marathon.exe', 'rb') as f:
    dos_header = f.read(64)
    pe_offset = struct.unpack('<I', dos_header[60:64])[0]
    f.seek(pe_offset)
    pe_sig = f.read(4)
    coff_header = f.read(20)
    machine, num_sections, timedate, sym_ptr, num_sym, opt_hdr_size, characteristics = struct.unpack('<HHIIIHH', coff_header)
    opt_header = f.read(opt_hdr_size)
    magic = struct.unpack('<H', opt_header[:2])[0]
    
    if magic == 0x20b: # PE32+
        image_base = struct.unpack('<Q', opt_header[24:32])[0]
        section_alignment = struct.unpack('<I', opt_header[32:36])[0]
        file_alignment = struct.unpack('<I', opt_header[36:40])[0]
        size_of_image = struct.unpack('<I', opt_header[56:60])[0]
        print(f"PE32+ ImageBase: 0x{image_base:X}, SizeOfImage: 0x{size_of_image:X}, Sections: {num_sections}")
        
        # Read section headers
        sections = []
        for i in range(num_sections):
            sec = f.read(40)
            name = sec[:8].rstrip(b'\x00').decode('latin1')
            vsize, vaddr, raw_size, raw_ptr = struct.unpack('<IIII', sec[8:24])
            sections.append((name, vaddr, vsize, raw_ptr, raw_size))
            
        target_rva = 0x18C87A2C
        print(f"Target RVA: 0x{target_rva:X}")
        for name, vaddr, vsize, raw_ptr, raw_size in sections:
            if vaddr <= target_rva < vaddr + vsize:
                file_offset = raw_ptr + (target_rva - vaddr)
                print(f"Found in section {name} (RVA 0x{vaddr:X}-0x{vaddr+vsize:X}): File Offset 0x{file_offset:X}")
                f.seek(file_offset - 64)
                code = f.read(128)
                print("Bytes around target:")
                print(code.hex())
                break
