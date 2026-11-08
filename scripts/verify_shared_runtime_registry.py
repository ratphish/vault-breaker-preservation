"""Verify three observed registry entries against their protected-record bytes."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('checkpoint', type=Path)
parser.add_argument('vmp', type=Path)
args = parser.parse_args()
with args.vmp.open('rb') as source:
    if hashlib.file_digest(source, 'sha256').hexdigest() != '7aa5f1d4e1182373ee9275af90f37e5dbba75c85a0c1d6580803f2c25c0a9742':
        raise ValueError('unexpected transformed vmp image')
manifest = json.loads((args.checkpoint / 'manifest.json').read_text(encoding='utf-8'))
files = {}


def read(address, length):
    region = next((r for r in manifest['regions'] if r['start'] <= address and address + length <= r['start'] + r['size']), None)
    if region is None or Path(region['file']).name != region['file']:
        raise ValueError(f'unmapped address {address:#x}')
    if region['file'] not in files:
        path = args.checkpoint / region['file']
        with path.open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != region['sha256']:
                raise ValueError('checkpoint digest mismatch')
        files[region['file']] = path.open('rb')
    stream = files[region['file']]
    stream.seek(address - region['start'])
    result = stream.read(length)
    if len(result) != length:
        raise ValueError('short checkpoint read')
    return result


targets = [(0x8080b8e2, 0x1767fa240, 0x8daf0, 160),
           (0x8080b8a0, 0x1767faa80, 0x1ef680, 144),
           (0x8080baf7, 0x1767f6bc0, 0x249de0, 176)]
out = []
try:
    with args.vmp.open('rb') as source:
        for tag, obj, offset, size in targets:
            key, record, following, backing = struct.unpack('<4Q', read(obj, 32))
            backing_obj, backing_key = struct.unpack('<QQ', read(backing, 16))
            source.seek(offset)
            expected = source.read(size)
            actual = read(record, size)
            if key != tag or backing_obj != obj or backing_key != tag or record != 0x179600000 + offset or actual != expected:
                raise ValueError(f'registry mismatch for {tag:#x}')
            out.append({'tag': hex(tag), 'object': hex(obj), 'record': hex(record), 'record_offset': hex(offset),
                        'record_size': size, 'class_hash': hex(struct.unpack_from('<I', expected, 8)[0]),
                        'backing': hex(backing), 'next': hex(following), 'record_bytes_match': True,
                        'backlink_matches': True})
    print(json.dumps({'verified': out, 'scope': 'synthetic checkpoint only'}, indent=2))
finally:
    for stream in files.values():
        stream.close()
