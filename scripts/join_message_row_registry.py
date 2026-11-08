"""Join decoded message initializer operands to a saved type registry."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import struct

parser = argparse.ArgumentParser()
parser.add_argument('text', type=Path)
parser.add_argument('xrefs', type=Path)
parser.add_argument('checkpoint', type=Path)
parser.add_argument('registry', type=Path)
parser.add_argument('--all-assignments', action='store_true',
                    help='search the same RAX/ECX store pattern without filtering on message IDs')
args = parser.parse_args()
hits = json.loads(args.xrefs.read_text(encoding='utf-8-sig'))['hits']
registry = {int(row['object'], 16): row for row in map(json.loads, args.registry.read_text().splitlines())}
manifest = json.loads((args.checkpoint / 'manifest.json').read_text())
region = next(r for r in manifest['regions'] if r['start'] == 0x173534000)
result = []
with args.text.open('rb') as code, (args.checkpoint / region['file']).open('rb') as data:
    if hashlib.file_digest(code, 'sha256').hexdigest() != 'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':
        raise ValueError('wrong text image')
    if hashlib.file_digest(data, 'sha256').hexdigest() != region['sha256']:
        raise ValueError('wrong checkpoint region')
    if args.all_assignments:
        hits = []
        with mmap.mmap(code.fileno(), 0, access=mmap.ACCESS_READ) as text_image:
            anchor = b'\x8b\x08\x48\x8d\x05'
            position = text_image.find(anchor)
            while position >= 0:
                site = 0x140001000 + position + 2
                if text_image[position + 9:position + 12] == b'\x48\x89\x05':
                    row = site + 7 + struct.unpack_from('<i', text_image, position + 5)[0]
                    destination = site + 14 + struct.unpack_from('<i', text_image, position + 12)[0]
                    if 0x172c84000 <= row < 0x173534000 and region['start'] <= destination < region['start'] + region['size']:
                        hits.append({'site': hex(site), 'row': hex(row), 'stored_pointer_va': hex(destination)})
                position = text_image.find(anchor, position + 1)
    with mmap.mmap(data.fileno(), 0, access=mmap.ACCESS_READ) as image:
        for hit in hits:
            if 'stored_pointer_va' not in hit:
                continue
            site = int(hit['site'], 16)
            code.seek(site - 0x140001000 - 25)
            before = code.read(25)
            if before[-2:] != b'\x8b\x08':
                continue
            if before[16:19] == b'\x48\x8b\x05':
                load = 16
            elif (before[:3] == b'\x48\x8b\x05' and before[7:9] == b'\x89\x0d'
                  and before[13:15] == b'\xc7\x05'):
                load = 0
            else:
                continue
            source = site - 25 + load + 7 + struct.unpack_from('<i', before, load + 3)[0]
            offset = source - region['start']
            if not 0 <= offset <= len(image) - 8:
                continue
            pointer = struct.unpack_from('<Q', image, offset)[0]
            record = registry.get(pointer)
            if record:
                object_offset = pointer - region['start']
                if not 0 <= object_offset <= len(image) - 4 or struct.unpack_from('<I', image, object_offset)[0] != int(record['key'], 16):
                    raise ValueError('registry key differs from checkpoint')
            result.append({**hit, 'source_pointer_va': hex(source), 'source_value': hex(pointer),
                           'registry_key': record['key'] if record else None})
print(json.dumps({'decoded_source_loads': len(result), 'registry_matches': sum(bool(r['registry_key']) for r in result),
                  'rows': result}, indent=2))
