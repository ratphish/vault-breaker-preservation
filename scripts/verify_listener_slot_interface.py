"""Verify decoded listener pairs against reconstructed native message tables."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

parser = argparse.ArgumentParser()
parser.add_argument('text', type=Path)
parser.add_argument('rdata', type=Path)
parser.add_argument('assignments', type=Path)
parser.add_argument('listeners', type=Path)
args = parser.parse_args()
rdata = args.rdata.read_bytes()
if hashlib.sha256(rdata).hexdigest() != 'e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42':
    raise ValueError('unexpected read-only data')
assignments = json.loads(args.assignments.read_text(encoding='utf-8-sig'))['rows']
by_type = {int(row['registry_key'], 16): row for row in assignments}
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True


def read_table(text, key):
    row = by_type[key]
    site = int(row['site'], 16)
    count_address = int(row['stored_pointer_va'], 16) + 8
    text.seek(site - 0x140001000)
    count = None
    for instruction in decoder.disasm(text.read(64), site):
        if instruction.mnemonic != 'mov' or len(instruction.operands) != 2:
            continue
        dst, src = instruction.operands
        if (dst.type == X86_OP_MEM and dst.size == 4 and dst.mem.base == X86_REG_RIP
                and instruction.address + instruction.size + dst.mem.disp == count_address
                and src.type == X86_OP_IMM):
            count = src.imm
            break
    offset = int(row['row'], 16) - 0x172c84000
    if count is None or not 0 < count < 512 or not 0 <= offset <= len(rdata) - 16 * count:
        raise ValueError(f'invalid message table for {key:#x}')
    return [struct.unpack_from('<QIHH', rdata, offset + 16 * slot) for slot in range(count)]


with args.text.open('rb') as text:
    if hashlib.file_digest(text, 'sha256').hexdigest() != 'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':
        raise ValueError('unexpected text')
    interface = read_table(text, 0x8080bae0)
    if len(interface) != 4 or any(pointer for pointer, *_ in interface):
        raise ValueError('unexpected four-row interface')
    listeners = []
    for path in sorted(args.listeners.glob('*.bin')):
        content = path.read_bytes()
        if len(content) != 160 or struct.unpack_from('<III', content, 8) != (0x8080a244, 0x8080bae0, 4):
            raise ValueError(f'unexpected listener layout: {path.name}')
        array = 0x18 + struct.unpack_from('<q', content, 0x18)[0]
        if (not 4 <= array <= len(content) - 16
                or struct.unpack_from('<I', content, array - 4)[0] != 0x8080bfcd):
            raise ValueError(f'invalid relative listener array: {path.name}')
        count, item_type = struct.unpack_from('<QQ', content, array)
        if count != len(interface) or item_type != 0x8080bafa or array + 16 + 24 * count != len(content):
            raise ValueError(f'invalid listener array header: {path.name}')
        pairs = [struct.unpack_from('<II', content, array + 16 + 24 * slot) for slot in range(count)]
        matches = []
        for signature, (key, slot) in zip(interface, pairs):
            table = read_table(text, key)
            if slot >= len(table):
                raise ValueError(f'out-of-range listener slot: {path.name}')
            pointer, message, field, flags = table[slot]
            matches.append({'type': hex(key), 'slot': slot, 'native_count': len(table),
                            'pointer': hex(pointer), 'id': hex(message),
                            'signature_match': (message, field) == signature[1:3],
                            'flags_xor': flags ^ signature[3]})
        listeners.append({'tag': path.stem, 'relative_array': hex(array), 'item_type': hex(item_type),
                          'matches': matches})
print(json.dumps({'interface': '0x8080bae0', 'listeners': listeners,
                  'scope': 'Exact signature comparison, no runtime invocation observed'}, indent=2))
