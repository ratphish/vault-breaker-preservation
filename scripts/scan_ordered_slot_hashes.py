"""Search exact FNV-1 hashes of the extracted slot names in private images."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('slots', type=Path)
p.add_argument('images', nargs='+', type=Path)
a = p.parse_args()
rows = []
for slot in json.loads(a.slots.read_text(encoding='utf-8-sig'))['entries']:
    value = 0x811c9dc5
    for byte in slot['name'].encode('ascii'):
        value = ((value * 0x1000193) & 0xffffffff) ^ byte
    rows.append({'slot': slot['slot'], 'name': slot['name'], 'fnv1': hex(value), 'matches': {}})
identities = {}
for path in a.images:
    with path.open('rb') as f:
        identities[path.name] = hashlib.file_digest(f, 'sha256').hexdigest()
        f.seek(0)
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as image:
            for row in rows:
                needle = struct.pack('<I', int(row['fnv1'], 16))
                positions = []
                pos = image.find(needle)
                while pos >= 0:
                    positions.append(hex(pos))
                    if len(positions) >= 100:
                        raise ValueError('too many matches to report completely')
                    pos = image.find(needle, pos + 1)
                row['matches'][path.name] = positions
print(json.dumps({'image_sha256': identities, 'targets': rows,
                  'warning': 'Exact FNV-1 bytes only; accidental hits, protected encodings and undefined runtime hashing are possible.'}, indent=2))
