"""Compare the bounded bitset context across synthetic checkpoint snapshots."""
import argparse
from collections import defaultdict
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('analysis', type=Path)
parser.add_argument('--include-bucket-selector', action='store_true')
parser.add_argument('--address', type=lambda value: int(value, 0), default=0x174e970d0)
parser.add_argument('--size', type=lambda value: int(value, 0))
args = parser.parse_args()
if args.include_bucket_selector and (args.address != 0x174e970d0 or args.size is not None):
    parser.error('--include-bucket-selector requires the default bitset range')
address = args.address
size = args.size if args.size is not None else (0x3c if args.include_bucket_selector else 0x38)
if address < 0 or size <= 0:
    parser.error('the address must be nonnegative and the size must be positive')
decoder = json.JSONDecoder()
groups = defaultdict(list)
skipped = []
for manifest in sorted(args.analysis.glob('checkpoint-*/manifest.json')):
    root = manifest.parent.resolve()
    with manifest.open(encoding='utf-8') as stream:
        header = stream.read(65536)
    index = header.find('"regions": [')
    if index < 0:
        skipped.append(root.name)
        continue
    index += len('"regions": [')
    match = None
    while index < len(header):
        try:
            region, end = decoder.raw_decode(header, index)
        except ValueError:
            break
        if region['start'] <= address and address + size <= region['start'] + region['size']:
            match = region
            break
        if header[end:end + 1] != ',':
            break
        index = end + 1
        while index < len(header) and header[index].isspace():
            index += 1
    if match is None:
        complete = json.loads(manifest.read_text(encoding='utf-8'))
        match = next((r for r in complete['regions']
                      if r['start'] <= address and address + size <= r['start'] + r['size']), None)
        if match is None:
            skipped.append(root.name)
            continue
    path = (root / match['file']).resolve()
    if not path.is_relative_to(root) or path.stat().st_size != match['size']:
        raise ValueError(f'invalid checkpoint region in {root}')
    with path.open('rb') as stream:
        stream.seek(address - match['start'])
        data = stream.read(size)
    if len(data) != size:
        raise ValueError(f'short context read in {root}')
    groups[data.hex()].append(root.name)
print(json.dumps({'address': hex(address), 'size': size,
                  'snapshots': sum(map(len, groups.values())),
                  'groups': [{'bytes': data, 'count': len(names), 'checkpoints': names}
                             for data, names in groups.items()],
                  'skipped': skipped,
                  'scope': 'Sampled region bytes and manifest sizes. Region digests are not recomputed.'},
                 indent=2))
