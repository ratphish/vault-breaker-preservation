import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

base_in_crash = 0x7FF6FDFA0000
stack_addrs = [
    0x00007FF72F819B66,
    0x00007FF72F81988A,
    0x00007FF72DFB9872,
    0x00007FF72F4BAF43,
    0x00007FF72E09159C,
    0x00007FF72F482770,
    0x00007FF72EFAEC1B,
    0x00007FF72D09BD0C,
    0x00007FF72FB81116
]

pe = pefile.PE(r"D:\Marathon-live\Marathon.exe", fast_load=True)
pe.parse_data_directories()

print(f"PE ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
cs = Cs(CS_ARCH_X86, CS_MODE_64)

with open(r"D:\Marathon-live\Marathon.exe", "rb") as f:
    exe_bytes = f.read()

for addr in stack_addrs:
    rva = addr - base_in_crash
    print(f"\n--- Stack 0x{addr:X} -> RVA 0x{rva:X} ---")
    file_offset = pe.get_offset_from_rva(rva)
    print(f"File offset: 0x{file_offset:X}")
    # disassemble 32 bytes before and 32 bytes after
    code = exe_bytes[max(0, file_offset - 32):file_offset + 32]
    for ins in cs.disasm(code, addr - 32):
        marker = "==>" if ins.address == addr else "   "
        print(f"{marker} 0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
