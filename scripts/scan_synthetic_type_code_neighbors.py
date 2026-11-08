"""Locate watched type words near code pointers in private synthetic heap pages.

This only identifies spatial co-occurrences; no dispatch or reachability is
implied. Region boundaries may hide candidates that cross two mapped regions.
"""
import argparse
import collections
import json
import struct
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('checkpoint', type=Path)
parser.add_argument('watchlist', type=Path)
parser.add_argument('--radius', type=int, default=96)
args = parser.parse_args()
if not 8 <= args.radius <= 512:
    raise ValueError('radius must be 8..512')
manifest = json.loads((args.checkpoint / 'manifest.json').read_text(encoding='utf-8'))
watch = json.loads(args.watchlist.read_text(encoding='utf-8-sig'))
tags = {int(row['tag'], 16) for row in watch['rows'] if row.get('tag')}
tags.update((0x8080b8e2, 0x8080b8a0, 0x8080baf7))
needles = {tag: struct.pack('<I', tag) for tag in tags}
rows, totals = [], collections.Counter()
for region in manifest['regions']:
    if not 0x790000000000 <= region['start'] < 0x7b0000000000:
        continue
    if Path(region['file']).name != region['file']:
        raise ValueError('invalid snapshot region')
    data = (args.checkpoint / region['file']).read_bytes()
    for tag, needle in needles.items():
        pos = data.find(needle)
        while pos >= 0:
            address = region['start'] + pos
            if address % 4 == 0:
                totals[f'{tag:08X}'] += 1
                neighbors = []
                start = max(0, (pos - args.radius + 7) & ~7)
                end = min(len(data) - 7, pos + args.radius + 1)
                for off in range(start, end, 8):
                    value = struct.unpack_from('<Q', data, off)[0]
                    if 0x140001000 <= value < 0x172c84000:
                        neighbors.append({'relative_offset': off - pos, 'pointer': hex(value)})
                if neighbors:
                    rows.append({'tag': f'{tag:08X}', 'address': hex(address), 'code_neighbors': neighbors})
            pos = data.find(needle, pos + 1)
print(json.dumps({'tags': len(tags), 'regions_scanned': sum(0x790000000000 <= r['start'] < 0x7b0000000000 for r in manifest['regions']),
                  'type_word_hits': sum(totals.values()), 'hits_with_code_neighbors': len(rows),
                  'by_tag': dict(totals), 'rows': rows,
                  'warning': 'Spatial candidates only; image range alone does not establish executable targets or calls.'}, indent=2))
