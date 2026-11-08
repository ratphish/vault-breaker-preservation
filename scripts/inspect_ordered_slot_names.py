"""Cross-check serialized slot-number descriptors against ordered name pointers."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('metadata', type=Path)
p.add_argument('tag', help='32-bit metadata tag in hex')
a = p.parse_args()
b = a.metadata.read_bytes()
tag = int(a.tag, 16)

def qword(offset):
    if not 0 <= offset <= len(b) - 8:
        raise ValueError(f'out of bounds: {offset:#x}')
    return struct.unpack_from('<q', b, offset)[0]

def name_at(pos):
    if not 0 <= pos < len(b):
        raise ValueError('name pointer out of bounds')
    end = b.find(b'\0', pos, min(len(b), pos + 250))
    if end < 0:
        raise ValueError('unterminated name')
    return b[pos:end].decode('ascii')

array = 0x30 + qword(0x30)
count = qword(array)
if not 0 < count <= 1000 or array + 8 + 8 * count > len(b):
    raise ValueError('unexpected ordered-name array')
ordered = []
for slot in range(count):
    pos = array + 8 + 8 * slot
    target = pos + qword(pos)
    ordered.append({'slot': slot, 'name': name_at(target), 'name_offset': hex(target), 'pointer_offset': hex(pos)})
descriptors = {}
for off in range(0, len(b)-24, 8):
    ref, slot, flag = struct.unpack_from('<III', b, off+8)
    if ref != tag or flag != 0x16:
        continue
    target = off + qword(off)
    try:
        name = name_at(target)
    except (ValueError, UnicodeDecodeError):
        continue
    if slot in descriptors:
        raise ValueError(f'duplicate descriptor slot {slot}')
    descriptors[slot] = (name, off, target)
if set(descriptors) != set(range(count)):
    raise ValueError('descriptor slots do not match ordered table')
for row in ordered:
    name, off, target = descriptors[row['slot']]
    if name != row['name'] or target != int(row['name_offset'], 16):
        raise ValueError(f'descriptor mismatch at slot {row["slot"]}')
    row['descriptor_offset'] = hex(off)
print(json.dumps({'tag': f'{tag:08X}', 'sha256': hashlib.sha256(b).hexdigest(),
                  'array_offset': hex(array), 'count': count, 'entries': ordered,
                  'warning': 'Serialized name/index consistency only; no executable target or dispatch behavior established.'}, indent=2))
