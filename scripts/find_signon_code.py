import struct

with open(r'D:\Dawnv0.1.5.2\payload\steam_api64.dll', 'rb') as f:
    data = f.read()

# PE header
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
is_64 = (magic == 0x20B)
image_base = struct.unpack_from("<Q" if is_64 else "<I", data, e_lfanew + 24 + 4)[0]
num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
sec_table_offset = e_lfanew + 24 + opt_hdr_size

sections = []
for i in range(num_sections):
    sec = data[sec_table_offset + i * 40 : sec_table_offset + (i + 1) * 40]
    name = sec[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", sec, 8)
    sections.append((name, vaddr, vsize, roff, rsize))

def offset_to_rva(off):
    for name, vaddr, vsize, roff, rsize in sections:
        if roff <= off < roff + rsize:
            return (off - roff) + vaddr
    return None

str_off = data.find(b'/SignOn\x00')
rva = offset_to_rva(str_off)
print(f"String '/SignOn' at file offset 0x{str_off:X}, RVA 0x{rva:X}, VA 0x{image_base + rva:X}")

# Search for references to RVA or VA
rva_bytes = struct.pack("<I", rva)
va_bytes = struct.pack("<Q", image_base + rva)

print("Searching for direct pointers...")
for match_str, b in [("RVA", rva_bytes), ("VA", va_bytes)]:
    pos = 0
    while True:
        idx = data.find(b, pos)
        if idx == -1:
            break
        print(f"  Found {match_str} ref at file offset 0x{idx:X} (RVA 0x{offset_to_rva(idx):X})")
        pos = idx + 1

# Search for LEA relative references: instruction [48 8d ?? ?? ?? ?? ??] where target is VA or RIP+rel == VA
print("Searching for RIP-relative LEA references...")
# In x64: 48 8D reg [4-byte rel32] -> RIP after instruction + rel32 = target_rva
for name, vaddr, vsize, roff, rsize in sections:
    if "text" in name.lower() or "code" in name.lower():
        sec_data = data[roff:roff+rsize]
        for i in range(len(sec_data) - 7):
            b0 = sec_data[i]
            b1 = sec_data[i+1]
            if (b0 == 0x48 or b0 == 0x4C) and b1 == 0x8D: # LEA r64, [rip+disp32]
                disp = struct.unpack_from("<i", sec_data, i + 3)[0]
                target = (vaddr + i + 7) + disp
                if target == rva:
                    code_off = roff + i
                    print(f"  Found LEA /SignOn at file offset 0x{code_off:X} (RVA 0x{vaddr + i:X})")
