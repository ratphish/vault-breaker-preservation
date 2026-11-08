"""Walk the 32-byte linked objects rooted at the observed synthetic image global."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('checkpoint', type=Path)
parser.add_argument('--head', type=lambda value: int(value, 0), default=0x178eec9c8)
parser.add_argument('--target', type=lambda value: int(value, 0), action='append', default=[])
parser.add_argument('--key', type=lambda value: int(value, 0), action='append', default=[])
parser.add_argument('--index', type=Path, help='private JSONL index of transformed VMP records')
parser.add_argument('--vmp', type=Path, help='also compare each indexed runtime record with this transformed image')
parser.add_argument('--export-map', type=Path, help='write a new private key/object/record JSONL map')
parser.add_argument('--verify', action='store_true')
args = parser.parse_args()
root = args.checkpoint
manifest = json.loads((root / 'manifest.json').read_text(encoding='utf-8'))
opened = {}


def read(address, length):
    region = next((r for r in manifest['regions'] if r['start'] <= address and address + length <= r['start'] + r['size']), None)
    if region is None or Path(region['file']).name != region['file']:
        raise ValueError(f'unmapped or invalid location {address:#x}')
    name = region['file']
    if name not in opened:
        path = root / name
        if args.verify:
            with path.open('rb') as source:
                if hashlib.file_digest(source, 'sha256').hexdigest() != region['sha256'] or path.stat().st_size != region['size']:
                    raise ValueError(f'region digest mismatch: {name}')
        opened[name] = path.open('rb')
    opened[name].seek(address - region['start'])
    result = opened[name].read(length)
    if len(result) != length:
        raise ValueError('short region read')
    return result


try:
    expected = {}
    image = None
    if args.vmp:
        if not args.index:
            raise ValueError('--vmp requires --index')
        with args.vmp.open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != '7aa5f1d4e1182373ee9275af90f37e5dbba75c85a0c1d6580803f2c25c0a9742':
                raise ValueError('unexpected transformed VMP image')
        image = args.vmp.open('rb')
    if args.index:
        with args.index.open(encoding='utf-8-sig') as stream:
            for line in stream:
                row = json.loads(line)
                tag = int(row['tag'], 16)
                if tag in expected:
                    raise ValueError(f'duplicate index tag {tag:#x}')
                expected[tag] = row
    head = struct.unpack('<Q', read(args.head, 8))[0]
    current = head
    seen, found, found_keys, mapped, mismatches, byte_matches, nodes = {}, {}, {hex(k): [] for k in args.key}, set(), [], 0, []
    while current:
        if current in seen:
            raise ValueError(f'cycle at {current:#x}')
        if len(seen) >= 100000:
            raise ValueError('chain length limit')
        seen[current] = len(seen)
        key, record, following, backing = struct.unpack('<4Q', read(current, 32))
        if args.export_map:
            nodes.append({'key': hex(key & 0xffffffff), 'object': hex(current), 'record': hex(record),
                          'next': hex(following), 'backing': hex(backing)})
        if expected:
            tag = key & 0xffffffff
            row = expected.get(tag)
            if row is None or tag in mapped or record != 0x179600000 + int(row['record_offset'], 16):
                if len(mismatches) < 20:
                    mismatches.append({'address': hex(current), 'key': hex(tag), 'record': hex(record)})
            else:
                mapped.add(tag)
                if image:
                    offset, size = int(row['record_offset'], 16), row['record_size']
                    image.seek(offset)
                    if read(record, size) == image.read(size):
                        byte_matches += 1
                    elif len(mismatches) < 20:
                        mismatches.append({'address': hex(current), 'key': hex(tag), 'error': 'record bytes differ'})
        if current in args.target:
            found[hex(current)] = {'index': seen[current], 'key_qword': hex(key), 'record': hex(record),
                                   'next': hex(following), 'backing': hex(backing)}
        if (key & 0xffffffff) in args.key:
            found_keys[hex(key & 0xffffffff)].append({'index': seen[current], 'address': hex(current),
                                                       'key_qword': hex(key), 'record': hex(record),
                                                       'next': hex(following), 'backing': hex(backing)})
        current = following
    if args.export_map:
        out = args.export_map.resolve()
        if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():
            raise ValueError('map must be a new private file')
        with out.open('x', encoding='utf-8') as stream:
            for node in nodes:
                stream.write(json.dumps(node) + '\n')
    print(json.dumps({'head_global': hex(args.head), 'head': hex(head), 'count': len(seen),
                      'null_terminated': True, 'targets': {hex(t): found.get(hex(t)) for t in args.target},
                      'keys': found_keys, 'index_validation': {'expected': len(expected), 'matched_unique': len(mapped),
                      'record_bytes_match': byte_matches if image else None,
                      'mismatch_examples': mismatches} if args.index else None}, indent=2))
finally:
    if image:
        image.close()
    for handle in opened.values():
        handle.close()
