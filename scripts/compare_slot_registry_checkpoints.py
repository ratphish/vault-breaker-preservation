"""Compare watched 32-byte registry candidates in two private Unicorn snapshots."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('before', type=Path)
parser.add_argument('after', type=Path)
parser.add_argument('watchlist', type=Path)
parser.add_argument('--verify', action='store_true', help='hash each region that contains a candidate')
args = parser.parse_args()
rows = json.loads(args.watchlist.read_text(encoding='utf-8-sig'))['rows']
addresses = sorted({int(candidate['pointer'], 16) for row in rows for candidate in row['registry_candidates']})


def read_snapshot(root):
    manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
    handles, data = {}, {}
    try:
        for address in addresses:
            region = next((r for r in manifest['regions'] if r['start'] <= address and address + 32 <= r['start'] + r['size']), None)
            if region is None:
                raise ValueError(f'unmapped candidate {address:#x}')
            name = region['file']
            if Path(name).name != name:
                raise ValueError('invalid region filename')
            if name not in handles:
                path = root / name
                if args.verify:
                    with path.open('rb') as source:
                        if hashlib.file_digest(source, 'sha256').hexdigest() != region['sha256'] or path.stat().st_size != region['size']:
                            raise ValueError(f'region mismatch: {name}')
                handles[name] = path.open('rb')
            handles[name].seek(address - region['start'])
            data[address] = handles[name].read(32)
            if len(data[address]) != 32:
                raise ValueError(f'short read at {address:#x}')
    finally:
        for handle in handles.values():
            handle.close()
    return manifest, data


before_manifest, before = read_snapshot(args.before)
after_manifest, after = read_snapshot(args.after)
if before_manifest['identity'] != after_manifest['identity']:
    raise ValueError('different model identities')
changes = []
for address in addresses:
    if before[address] != after[address]:
        linked = [{k: row[k] for k in ('tag', 'parent_type', 'class_hash', 'record_offset', 'vmp_offset') if k in row}
                  for row in rows if any(int(c['pointer'], 16) == address for c in row['registry_candidates'])]
        changes.append({'address': hex(address), 'references': linked,
                        'before_qwords': [hex(v) for v in struct.unpack('<4Q', before[address])],
                        'after_qwords': [hex(v) for v in struct.unpack('<4Q', after[address])]})
print(json.dumps({'watched': len(addresses), 'changed': len(changes), 'changes': changes}, indent=2))
