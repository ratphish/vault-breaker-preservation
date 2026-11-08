"""Locate candidate indexed calls after a register is scaled by a 16-byte stride."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import re

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

parser = argparse.ArgumentParser()
parser.add_argument('text', type=Path)
args = parser.parse_args()
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
hits = {}
with args.text.open('rb') as file:
    if hashlib.file_digest(file, 'sha256').hexdigest() != 'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':
        raise ValueError('wrong text image')
    with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as image:
        for match in re.finditer(rb'[\x40-\x4f]?\xc1[\xe0-\xe7]\x04', image):
            offset = match.start()
            va = 0x140001000 + offset
            instructions = list(decoder.disasm(image[offset:offset + 48], va, count=8))
            if not instructions or instructions[0].mnemonic not in ('shl', 'sal'):
                continue
            register = instructions[0].operands[0].reg
            name = decoder.reg_name(register)
            names = {name, {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
                            'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp'}.get(name, name.rstrip('d'))}
            loaded = None
            for instruction in instructions[1:]:
                if instruction.mnemonic in ('call', 'jmp'):
                    operand = instruction.operands[0]
                    direct = operand.type == X86_OP_MEM and operand.mem.scale == 1 and (
                            decoder.reg_name(operand.mem.index) in names
                            or decoder.reg_name(operand.mem.base) in names)
                    via_register = loaded and operand.type == X86_OP_REG and operand.reg == loaded
                    via_rip = (loaded and decoder.reg_name(loaded) == 'rax'
                               and operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP)
                    if direct or via_register or via_rip:
                        hits[instruction.address] = {
                            'shift': hex(va), 'call': hex(instruction.address),
                            'kind': 'direct_memory' if direct else 'loaded_register' if via_register else 'possible_rax_thunk',
                            'instructions': [f'{i.mnemonic} {i.op_str}' for i in instructions
                                             if i.address <= instruction.address]}
                    break
                if instruction.mnemonic.startswith(('j', 'ret', 'int')):
                    break
                _, writes = instruction.regs_access()
                if instruction.mnemonic == 'mov' and len(instruction.operands) == 2:
                    dst, src = instruction.operands
                    if (dst.type == X86_OP_REG and src.type == X86_OP_MEM and src.size == 8
                            and src.mem.scale == 1 and
                            {decoder.reg_name(src.mem.base), decoder.reg_name(src.mem.index)} & names):
                        loaded = dst.reg
                        continue
                if loaded in writes:
                    break
                if any(decoder.reg_name(reg) in names for reg in writes):
                    break
print(json.dumps({'hits': list(hits.values()),
                  'scope': 'Exact short stride-16 idiom. Decoded sites require control-flow and data validation.'},
                 indent=2))
