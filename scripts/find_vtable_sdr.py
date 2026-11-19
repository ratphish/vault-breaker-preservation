import struct

# In steamclient64.dll, the factory function was at RVA 0x7277e0.
# Let's inspect the code of 0x7277e0 and follow where it returns the singleton interface.
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

# Factory function code at RVA 0x7277e0:
raw = rva_to_raw(0x7277e0)
print(data[raw:raw+60].hex())
