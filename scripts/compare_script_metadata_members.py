"""Compare hashed member tables in an instance and its separate definition metadata."""
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('instance_links', type=Path)
p.add_argument('definition', type=Path)
a = p.parse_args()
known = json.loads(a.instance_links.read_text(encoding='utf-8-sig'))
b = a.definition.read_bytes()
array = 0x50 + struct.unpack_from('<q', b, 0x50)[0]
count = struct.unpack_from('<Q', b, array)[0]
if count != known['member_count'] or array + 24 + 12 * count > len(b):
    raise ValueError('member count or bounds differ')
rows = []
types = collections.Counter()
for index, old in enumerate(known['members']):
    h, typ, off = struct.unpack_from('<III', b, array + 24 + 12 * index)
    if h != int(old['name_hash_fnv1'], 16):
        raise ValueError(f'member order or hash differs at {index}')
    if typ != int(old['component_type'], 16):
        raise ValueError(f'definition type does not match serialized component at {index}')
    types[(old['member_type'], f'{typ:08x}')] += 1
    rows.append({'name': old['name'], 'hash': old['name_hash_fnv1'],
                 'instance_member_type': old['member_type'], 'instance_relative_offset': old['relative_offset'],
                 'definition_member_type': f'{typ:08x}', 'definition_relative_offset': hex(off),
                 'slot': old.get('slot'), 'slot_name': old.get('slot_name')})
print(json.dumps({'definition_sha256': hashlib.sha256(b).hexdigest(), 'member_count': count,
                  'definition_array': hex(array), 'type_pairs': [{'instance': k[0], 'definition': k[1], 'count': v} for k,v in types.items()],
                  'component_types_match_definition': True,
                  'members': rows, 'warning': 'Matching names and relative offsets do not reveal runtime handler code or structure layout.'}, indent=2))
