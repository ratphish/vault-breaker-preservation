import struct

target = struct.pack('<I', 88915786) # 0x054CBF4A -> 4A BF 4C 05
print(f"Searching for {target.hex()} (0x{88915786:08X})...")

with open(r'D:\Marathon-live\Marathon.exe', 'rb') as f:
    chunk_size = 64 * 1024 * 1024
    offset = 0
    overlap = 16
    prev_tail = b''
    
    # Read sections from PE header
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
        
    def offset_to_rva(off):
        for name, vaddr, vsize, raw_ptr, raw_size in sections:
            if raw_ptr <= off < raw_ptr + raw_size:
                return vaddr + (off - raw_ptr), name
        return None, None

    f.seek(0)
    matches = []
    while True:
        chunk = f.read(chunk_size)
        if not chunk: break
        data = prev_tail + chunk
        base_off = offset - len(prev_tail)
        
        pos = 0
        while True:
            idx = data.find(target, pos)
            if idx == -1: break
            found_off = base_off + idx
            rva, sname = offset_to_rva(found_off)
            matches.append((found_off, rva, sname))
            pos = idx + 1
            
        prev_tail = chunk[-overlap:]
        offset += len(chunk)

print(f"Total matches found: {len(matches)}")
for off, rva, sname in matches:
    if rva:
        print(f"  File Offset: 0x{off:X} | RVA: 0x{rva:X} (VA: 0x{0x140000000 + rva:X}) in {sname}")
    else:
        print(f"  File Offset: 0x{off:X}")
