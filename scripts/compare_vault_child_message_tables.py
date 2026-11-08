"""Compare joined child-type message tables against decoded Vault metadata."""
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
parser.add_argument('joined', type=Path)
parser.add_argument('children', type=Path)
parser.add_argument('slots', type=Path)
parser.add_argument('component', type=Path)
args = parser.parse_args()


def load(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def fnv1(name):
    value = 0x811c9dc5
    for byte in name.encode('ascii'):
        value = ((value * 0x1000193) & 0xffffffff) ^ byte
    return value


children = {int(row['tag'], 16): row for row in load(args.children)['rows']}
slots = load(args.slots)['slots']
names = {fnv1(row['name']): row['name'] for row in slots}
rdata = args.rdata.read_bytes()
component = args.component.read_bytes()
if hashlib.sha256(rdata).hexdigest() != 'e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42':
    raise ValueError('unexpected rdata')
if hashlib.sha256(component).hexdigest() != '70ccaa2ce14425d4603690cf043ad0c69921af49b607bf1d7dea94a0389741cc':
    raise ValueError('unexpected component')
decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
tables = []
with args.text.open('rb') as code:
    if hashlib.file_digest(code, 'sha256').hexdigest() != 'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':
        raise ValueError('unexpected text')
    for row in load(args.joined)['rows']:
        key = int(row['registry_key'], 16)
        if key not in children:
            continue
        site = int(row['site'], 16)
        count_field = int(row['stored_pointer_va'], 16) + 8
        code.seek(site - 0x140001000)
        count = None
        for instruction in decoder.disasm(code.read(64), site):
            if instruction.mnemonic != 'mov' or len(instruction.operands) != 2:
                continue
            dst, src = instruction.operands
            if (dst.type == X86_OP_MEM and dst.size == 4 and dst.mem.base == X86_REG_RIP
                    and instruction.address + instruction.size + dst.mem.disp == count_field
                    and src.type == X86_OP_IMM):
                count = src.imm
                break
        start = int(row['row'], 16) - 0x172c84000
        if count is None or not 0 < count <= 512 or not 0 <= start <= len(rdata) - count * 16:
            raise ValueError(f'invalid candidate table at {site:#x}')
        matches = []
        for index in range(count):
            pointer, message, _, _ = struct.unpack_from('<QIHH', rdata, start + index * 16)
            if message in names:
                matches.append({'index': index, 'name': names[message], 'pointer': hex(pointer)})
        needle = struct.pack('<I', key)
        offsets = [hex(offset) for offset in range(len(component) - 3)
                   if component.startswith(needle, offset)]
        tables.append({'key': hex(key), 'site': row['site'], 'table': row['row'], 'count': count,
                       'slot_name_hash_matches': matches, 'component_key_offsets': offsets})
print(json.dumps({'tables': tables, 'children': len(children), 'slot_names': len(slots),
                  'scope': 'Exact 32-bit matches and initializer count fields only. Table semantics and dispatch remain unverified.'},
                 indent=2))
