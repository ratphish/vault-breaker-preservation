"""Inspect two previously mapped export windows; capstone 5.0.9 required."""
import argparse
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

parser = argparse.ArgumentParser()
parser.add_argument('executable', type=Path)
args = parser.parse_args()
windows = [('_setup_script_workflow_tag_suite', 0x2f7a1c90, 0x16f7a2690),
           ('run_script_workflow_tag_unit_tests__function', 0x2ef21d10, 0x16ef22710)]
for name, offset, va in windows:
    with args.executable.open('rb') as f:
        f.seek(offset)
        data = f.read(128)
    print(name, hex(offset), 'bytes', data[:32].hex())
    for ins in list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(data, va))[:15]:
        print(hex(ins.address), ins.mnemonic, ins.op_str)
