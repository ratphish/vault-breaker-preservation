import struct

with open('D:/Marathon-live/Marathon.exe', 'rb') as f:
    dos_hdr = f.read(64)
    e_lfanew = struct.unpack('<I', dos_hdr[0x3c:0x40])[0]
    f.seek(e_lfanew)
    pe_sig = f.read(4)
    coff_hdr = f.read(20)
    machine, num_sections, time_date, sym_ptr, num_sym, opt_hdr_size, charact = struct.unpack('<HHIIIHH', coff_hdr)
    opt_hdr = f.read(opt_hdr_size)
    magic = struct.unpack('<H', opt_hdr[:2])[0]
    entry_point = struct.unpack('<I', opt_hdr[16:20])[0]
    image_base = struct.unpack('<Q', opt_hdr[24:32])[0]
    print(f"PE Magic: {hex(magic)}, Sections: {num_sections}, ImageBase: {hex(image_base)}, EntryPoint: {hex(entry_point)}")

    print(f"{'Name':<10} {'VirtAddr':<12} {'VirtSize':<12} {'RawAddr':<12} {'RawSize':<12}")
    for i in range(num_sections):
        sec_hdr = f.read(40)
        name = sec_hdr[:8].rstrip(b'\x00').decode('latin1', errors='replace')
        vsize, vaddr, raw_size, raw_ptr = struct.unpack('<IIII', sec_hdr[8:24])
        print(f"{name:<10} 0x{vaddr:08X}   0x{vsize:08X}   0x{raw_ptr:08X}   0x{raw_size:08X}")
