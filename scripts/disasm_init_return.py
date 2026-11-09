import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

pe = pefile.PE(r"D:\Marathon-preservation\build-26136895-20261031\bin\x64\steam_api64.dll")
pe.parse_data_directories()

offset = pe.get_offset_from_rva(0x6be0)
with open(r"D:\Marathon-preservation\build-26136895-20261031\bin\x64\steam_api64.dll", "rb") as f:
    f.seek(offset)
    code = f.read(128)

cs = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in cs.disasm(code, 0x180006be0):
    print(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
    if ins.mnemonic == "ret":
        break
