"""Search exact metadata header words in original and synthetic images, read-only."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('metadata_dir', type=Path)
p.add_argument('images', nargs='+', type=Path)
a = p.parse_args()
rows = []
for path in sorted(a.metadata_dir.glob('*.bin')):
    data = path.read_bytes()
    if len(data) < 12:
        raise ValueError(f'short metadata: {path}')
    rows.append({'tag': path.stem, 'metadata_sha256': hashlib.sha256(data).hexdigest(),
                 'word_at_8': f'{struct.unpack_from("<I", data, 8)[0]:08x}', 'images': {}})
for path in a.images:
    with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as image:
        for row in rows:
            needle = struct.pack('<I', int(row['word_at_8'], 16))
            positions = []
            pos = image.find(needle)
            while pos != -1:
                positions.append(hex(pos))
                if len(positions) >= 100:
                    raise ValueError('more than 100 matches; output would be incomplete')
                pos = image.find(needle, pos + 1)
            row['images'][path.name] = positions
print(json.dumps({'records': rows, 'warning': 'Exact byte matches only; metadata word meaning, encrypted values and runtime associations are not established.'}, indent=2))
