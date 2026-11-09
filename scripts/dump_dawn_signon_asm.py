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
# Function runs from 0x1804BDD70 up to around 0x1804BECE0 (~3950 bytes)
code_slice = data[target_off:target_off + 4500]

instructions = list(cs.disasm(code_slice, 0x180000000 + target_rva))

with open(r'D:\vault-breaker-preservation\scripts\dawn_signon_asm.txt', 'w') as out:
    for ins in instructions:
        # Check for RIP relative references
        ref = ""
        if 'rip +' in ins.op_str:
            # parse offset
            part = ins.op_str.split('rip +')[1].split(']')[0].strip()
            try:
                disp = int(part, 16)
                target_va = ins.address + ins.size + disp
                target_rva_addr = target_va - 0x180000000
                off = rva_to_offset(target_rva_addr)
                if off and off < len(data):
                    chunk = data[off:off+32]
                    # check if string
                    s = ""
                    for b in chunk:
                        if 32 <= b <= 126:
                            s += chr(b)
                        else:
                            break
                    if len(s) >= 3:
                        ref = f" ; -> '{s}'"
                    else:
                        ref = f" ; -> [0x{target_va:X}]: {chunk[:8].hex()}"
            except:
                pass
        out.write(f"0x{ins.address:X}: {ins.mnemonic:<8} {ins.op_str:<35}{ref}\n")

print(f"Wrote {len(instructions)} instructions to dawn_signon_asm.txt")
