"""Report exact four-byte match positions and neighboring bytes in a decoded record."""
import argparse
import hashlib
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('record', type=Path)
p.add_argument('expected_sha256')
p.add_argument('value', type=lambda s: int(s, 16))
a = p.parse_args()
b = a.record.read_bytes()
digest = hashlib.sha256(b).hexdigest()
if digest != a.expected_sha256.lower():
    raise ValueError('unexpected record digest')
needle = a.value.to_bytes(4, 'little')
rows = []
at = b.find(needle)
while at >= 0:
    rows.append({'offset': hex(at), 'alignment_mod4': at % 4,
                 'context_start': hex(max(0, at-24)), 'context': b[max(0,at-24):at+28].hex(' ')})
    at = b.find(needle, at+1)
print(json.dumps({'sha256': digest, 'length': len(b), 'value': f'{a.value:08x}', 'matches': rows,
                  'warning': 'A four-byte match is not by itself evidence of a code or metadata reference.'}, indent=2))
