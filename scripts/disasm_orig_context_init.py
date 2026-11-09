with open(r"D:\Marathon-preservation\build-26136895-20261031\bin\x64\steam_api64.dll", "rb") as f:
    f.seek(0x8BF0)
    code = f.read(128)

import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
cs = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in cs.disasm(code, 0x180008BF0):
    print(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")
