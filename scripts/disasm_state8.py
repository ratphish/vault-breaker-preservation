import struct
import capstone

# Function to convert RVA to file offset based on PE sections
def rva_to_file_offset(rva):
    sections = [
        (".text",  0x00001000, 0x32C8245C, 0x00000600, 0x32C82600),
        (".rdata", 0x32C84000, 0x008AF8C8, 0x32C82C00, 0x008AFA00),
        (".data",  0x33534000, 0x05D72BE1, 0x33532600, 0x01DD6C00),
    ]
    for name, va, vsz, raw_ptr, raw_sz in sections:
        if va <= rva < va + vsz:
            return rva - va + raw_ptr
    return None

exe_path = 'D:/Marathon-live/Marathon.exe'
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

state8_rva = 0x2EF4C7E0
file_off = rva_to_file_offset(state8_rva)
print(f"State 8 Entry RVA: 0x{state8_rva:08X} -> File offset: 0x{file_off:08X}")

with open(exe_path, 'rb') as f:
    f.seek(file_off)
    code = f.read(512)

print(f"\nDisassembly of State 8 Entry (0x{state8_rva:08X}):")
for ins in md.disasm(code, state8_rva):
    print(f"0x{ins.address:08X}:  {ins.mnemonic:<8} {ins.op_str}")
    if ins.mnemonic == 'ret' and ins.address > state8_rva + 0x20:
        # Stop after reasonable return
        pass
