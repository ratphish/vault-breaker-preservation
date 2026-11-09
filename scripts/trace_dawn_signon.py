import capstone
import struct

with open(r'D:\Dawnv0.1.5.2\payload\steam_api64.dll', 'rb') as f:
    data = f.read()

e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
num_sections = struct.unpack_from('<H', data, e_lfanew + 6)[0]
opt_hdr_size = struct.unpack_from('<H', data, e_lfanew + 20)[0]
sec_table_offset = e_lfanew + 24 + opt_hdr_size
sections = []
for i in range(num_sections):
    sec = data[sec_table_offset + i * 40 : sec_table_offset + (i + 1) * 40]
    name = sec[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
    vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', sec, 8)
    sections.append((name, vaddr, vsize, roff, rsize))

def rva_to_offset(rva):
    for name, vaddr, vsize, roff, rsize in sections:
        if vaddr <= rva < vaddr + vsize:
            return (rva - vaddr) + roff
    return None

target_rva = 0x4BDD70
target_off = rva_to_offset(target_rva)

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
code_slice = data[target_off:target_off + 4000]

instructions = list(cs.disasm(code_slice, 0x180000000 + target_rva))

# Let's look for tags being loaded into r9 or other registers
print("Scanning instructions in SignOn response builder:")
for ins in instructions:
    # Check if mov reg, const
    if ins.mnemonic == 'mov' or ins.mnemonic == 'movabs' or ins.mnemonic == 'lea':
        # print interesting lines
        if any(r in ins.op_str for r in ['r9', 'r8', 'rdx', 'rcx', 'eax', 'ebx']):
            # If immediate in op_str
            for token in ins.op_str.split(','):
                token = token.strip()
                if token.startswith('0x'):
                    try:
                        val = int(token, 16)
                        # Is it a tag? (field_num << 3) | wire_type
                        fnum = val >> 3
                        wtype = val & 7
                        if fnum in range(1, 40) and wtype in (0, 1, 2, 5):
                            print(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}  --> TAG: Field {fnum}, WireType {wtype}")
                    except:
                        pass
