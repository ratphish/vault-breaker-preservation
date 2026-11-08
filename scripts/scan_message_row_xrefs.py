"""Find decoded RIP-relative references to the two candidate message IDs' rows."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

import numpy as np
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_REG_RIP

parser = argparse.ArgumentParser()
parser.add_argument('text', type=Path)
parser.add_argument('rdata', type=Path)
args = parser.parse_args()
base = 0x140000000
rdata_rva = 0x32c84000
data = args.rdata.read_bytes()
if hashlib.sha256(data).hexdigest() != 'e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42':
    raise ValueError('wrong rdata image')

rows = {}
for offset in range(0, 0x8afa00 - 15, 16):
    message = struct.unpack_from('<I', data, offset + 8)[0]
    if message in (0x67774671, 0x3088896a):
        rows[offset] = message
targets = np.zeros(len(data), dtype=bool)
for offset in rows:
    for field in (0, 8, 12, 14):
        targets[offset + field] = True

decoder = Cs(CS_ARCH_X86, CS_MODE_64)
decoder.detail = True
hits = []
chunk = 8 * 1024 * 1024
with args.text.open('rb') as file:
    if hashlib.file_digest(file, 'sha256').hexdigest() != 'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':
        raise ValueError('wrong text image')
    with mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ) as image:
        for start in range(1, len(image) - 3, chunk):
            length = min(chunk, len(image) - 3 - start)
            disp = np.ndarray((length,), dtype='<u4', buffer=image, offset=start, strides=(1,))
            modrm = np.frombuffer(image, dtype='u1', count=length, offset=start - 1)
            positions = np.flatnonzero((modrm & 0xc7) == 5)
            resolved = disp[positions] + positions.astype(np.uint32) + np.uint32(start + 0x1004 - rdata_rva & 0xffffffff)
            for tail in (0, 1, 2, 4):
                offsets = resolved + np.uint32(tail)
                nearby = np.flatnonzero(offsets < len(data))
                for index in nearby[targets[offsets[nearby]]]:
                    pos = start + int(positions[index])
                    end = pos + 4 + tail
                    target = int(offsets[index])
                    for begin in range(max(0, end - 15), pos - 1):
                        va = base + 0x1000 + begin
                        ins = next(decoder.disasm(image[begin:end], va, count=1), None)
                        if not ins or ins.size != end - begin or ins.disp_offset != pos - begin or ins.disp_size != 4:
                            continue
                        if not any(o.type == X86_OP_MEM and o.mem.base == X86_REG_RIP
                                   and va + ins.size + o.mem.disp == base + rdata_rva + target
                                   for o in ins.operands):
                            continue
                        hits.append({'site': hex(va), 'instruction': f'{ins.mnemonic} {ins.op_str}',
                                     'row': hex(base + rdata_rva + (target & ~15)),
                                     'field': target & 15, 'id': hex(rows[target & ~15])})
                        if ins.mnemonic != 'lea' or ins.operands[0].size != 8:
                            continue
                        store = next(decoder.disasm(image[end:end + 15], va + ins.size, count=1), None)
                        if not store or store.mnemonic != 'mov' or len(store.operands) != 2:
                            continue
                        dst, src = store.operands
                        if (dst.type == X86_OP_MEM and dst.mem.base == X86_REG_RIP
                                and src.type == X86_OP_REG and src.reg == ins.operands[0].reg):
                            hits[-1]['stored_pointer_va'] = hex(store.address + store.size + dst.mem.disp)
            del disp, modrm
print(json.dumps({'rows': len(rows), 'hits': hits,
                  'scope': 'Exact direct RIP-relative references to four fields. Instruction boundaries and reachability require separate validation.'}, indent=2))
