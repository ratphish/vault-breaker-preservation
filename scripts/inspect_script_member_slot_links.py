"""Cross-check hashed members, serialized component offsets, and named slots."""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('metadata', type=Path)
p.add_argument('component', type=Path)
p.add_argument('metadata_tag', type=lambda x: int(x, 16))
p.add_argument('component_tag', type=lambda x: int(x, 16))
p.add_argument('ordered_slots', type=Path)
a = p.parse_args()
m, b = a.metadata.read_bytes(), a.component.read_bytes()
slots = {s['slot']: s['name'] for s in json.loads(a.ordered_slots.read_text(encoding='utf-8-sig'))['entries']}
names = {}
for match in re.finditer(rb'[ -~]{4,}', m):
    name = match.group().decode('ascii')
    h = 0x811c9dc5
    for byte in match.group():
        h = ((h * 0x1000193) & 0xffffffff) ^ byte
    names.setdefault(h, set()).add(name)
array = 0x50 + struct.unpack_from('<q', m, 0x50)[0]
count = struct.unpack_from('<Q', m, array)[0]
if count > 1000 or array + 24 + 12 * count > len(m):
    raise ValueError('unexpected member array')
base_hash, base_type, base_offset, pad = struct.unpack_from('<IIII', m, array+8)
if base_hash != 0x811c9dc5 or base_offset != 0 or pad != 0:
    raise ValueError('unexpected base row')
rows = []
for i in range(count):
    off = array + 24 + i * 12
    h, typ, relative = struct.unpack_from('<III', m, off)
    candidates = sorted(names.get(h, []))
    if len(candidates) != 1:
        raise ValueError(f'ambiguous member hash {h:#x}: {candidates}')
    component_offset = relative + 0xb0
    if component_offset + 0xb0 > len(b):
        raise ValueError('component member outside bounds')
    component_id, component_type = struct.unpack_from('<II', b, component_offset)
    if component_id != a.component_tag:
        raise ValueError(f'component reference mismatch: {component_offset:#x}')
    row = {'name': candidates[0], 'name_hash_fnv1': f'{h:08x}', 'member_type': f'{typ:08x}',
           'metadata_record_offset': hex(off), 'relative_offset': hex(relative),
           'component_offset': hex(component_offset), 'component_type': f'{component_type:08x}'}
    if typ == 0x8080b8f1:
        if struct.unpack_from('<III', b, component_offset+0x40) != (a.component_tag, typ, component_offset):
            raise ValueError('wrapper backlink mismatch')
        ref, slot = struct.unpack_from('<II', b, component_offset+0x20)
        if ref != a.metadata_tag or slot not in slots:
            raise ValueError('wrapper slot mismatch')
        row['slot'] = slot
        row['slot_name'] = slots[slot]
    if typ == 0x8080a23f:
        ref, slot = struct.unpack_from('<II', b, component_offset+0x28)
        if ref == a.metadata_tag:
            if slot not in slots:
                raise ValueError('listener slot mismatch')
            row['listener_slot'] = slot
            row['listener_slot_name'] = slots[slot]
    rows.append(row)
print(json.dumps({'metadata_sha256': hashlib.sha256(m).hexdigest(), 'component_sha256': hashlib.sha256(b).hexdigest(),
                  'member_array': hex(array), 'member_count': count, 'base_type': f'{base_type:08x}',
                  'component_offset_bias': '0xb0', 'members': rows,
                  'warning': 'Serialized linkage only; these are not native addresses or recovered handler bodies.'}, indent=2))
