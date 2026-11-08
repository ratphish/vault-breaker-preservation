"""Join shared-type child records to a validated synthetic runtime registry map."""
import argparse
import collections
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('children', type=Path)
parser.add_argument('index', type=Path)
parser.add_argument('runtime_map', type=Path)
args = parser.parse_args()
children = json.loads(args.children.read_text(encoding='utf-8-sig'))
if children['image_sha256'] != '7aa5f1d4e1182373ee9275af90f37e5dbba75c85a0c1d6580803f2c25c0a9742':
    raise ValueError('unexpected transformed VMP identity')
by_offset = {}
with args.index.open(encoding='utf-8-sig') as stream:
    for line in stream:
        row = json.loads(line)
        if row['record_offset'] in by_offset:
            raise ValueError('duplicate indexed record offset')
        by_offset[row['record_offset']] = row
runtime = {}
with args.runtime_map.open(encoding='utf-8-sig') as stream:
    for line in stream:
        row = json.loads(line)
        key = int(row['key'], 16)
        if key in runtime:
            raise ValueError('duplicate runtime key')
        runtime[key] = row
rows, missing = [], []
for child in children['records']:
    index_row = by_offset.get(child['offset'])
    if index_row is None:
        missing.append({'record_offset': child['offset'], 'reason': 'not in embedded index'})
        continue
    if index_row['class_hash'] != child['class_hash']:
        raise ValueError('class hash mismatch')
    tag = int(index_row['tag'], 16)
    node = runtime.get(tag)
    if node is None or int(node['record'], 16) != 0x179600000 + int(child['offset'], 16):
        raise ValueError('runtime key/record mismatch')
    rows.append({'tag': f'{tag:08X}', 'parent_type': child['parent_type'], 'class_hash': child['class_hash'],
                 'record_offset': child['offset'], 'member_count': child['member_count'],
                 'registry_candidates': [{'pointer': node['object'], 'kind': 'runtime object'},
                                         {'pointer': node['backing'], 'kind': 'backing record'}]})
counts = collections.Counter(row['parent_type'] for row in rows)
print(json.dumps({'scope': 'synthetic runtime only; membership is a structural parent-word candidate',
                  'total_children': len(children['records']), 'mapped': len(rows), 'missing': missing,
                  'parent_counts': dict(counts), 'rows': rows}, indent=2))
