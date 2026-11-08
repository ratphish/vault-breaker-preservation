"""Check shared slot-related name descriptors in separate definition metadata."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('definitions', nargs='+', type=Path)
a = p.parse_args()
expected = {'discover_slot_dependencies': (0x8080b8e2, 0, 0x16),
            'flatten_slot_from_source': (0x8080b8e2, 1, 0x16),
            'import_slot': (0x8080b8a0, 0, 0x16),
            'simple_deep_copy': (0x8080baf7, 4, 0x16)}
out = []
for path in a.definitions:
    b = path.read_bytes()
    rows = []
    for name, wanted in expected.items():
        string = name.encode('ascii') + b'\0'
        name_at = b.find(string)
        if name_at < 0 or b.find(string, name_at+1) >= 0:
            raise ValueError(f'{path.name}: missing or duplicate {name}')
        hits = []
        for off in range(0, len(b)-24, 8):
            if off + struct.unpack_from('<q', b, off)[0] == name_at:
                ref, slot, flag = struct.unpack_from('<III', b, off+8)
                if (ref, slot, flag) == wanted:
                    hits.append(off)
        if len(hits) != 1:
            raise ValueError(f'{path.name}: unexpected descriptor for {name}')
        rows.append({'name': name, 'string_offset': hex(name_at), 'descriptor_offset': hex(hits[0]),
                     'raw_ref': f'{wanted[0]:08x}', 'raw_slot': wanted[1], 'flag': hex(wanted[2])})
    out.append({'file': path.name, 'sha256': hashlib.sha256(b).hexdigest(), 'descriptors': rows})
print(json.dumps({'definitions': out, 'warning': 'Shared serialized descriptors; code location, runtime meaning and availability of referenced schemas are unknown.'}, indent=2))
