"""Prepare a small private native-transform probe from a captured synthetic data event."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('trace',type=Path)
p.add_argument('index',type=int)
p.add_argument('output',type=Path)
a=p.parse_args()
out=a.output.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('new private output required')
x=json.loads(a.trace.read_text(encoding='utf-8-sig'))
event=x['parent_data_events'][a.index]
if 'input' not in event:raise ValueError('full input was not captured')
data=bytes.fromhex(event['input'])
if len(data)!=event['length'] or hashlib.sha256(data).hexdigest()!=event['before_sha256']:raise ValueError('captured input mismatch')
capture={'index':a.index,'length':event['length'],'key':event['key'],'counter':event['counter'],
         'input':event['input'],'expected_sha256':event['after_sha256'],
         'data_rva':hex(int(event['data'],16)-0x140000000)}
with out.open('x',encoding='utf-8') as f:json.dump(capture,f)
print(json.dumps({'index':a.index,'data':event['data'],'length':event['length'],
                  'input_sha256':event['before_sha256'],'expected_output_sha256':event['after_sha256']}))
