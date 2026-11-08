"""Prepare a private bounded native probe for the modeled VMP transform prefix."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('trace',type=Path)
p.add_argument('output',type=Path)
p.add_argument('--index',type=int,default=0)
a=p.parse_args()
out=a.output.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('new private output required')
x=json.loads(a.trace.read_text(encoding='utf-8-sig'))
event=x['parent_vmp_events'][a.index];before=bytes.fromhex(event['input_prefix'])
if len(before)!=4096 or event['length']<len(before):raise ValueError('unexpected prefix')
capture={'index':a.index,'length':len(before),'key':event['key'],'counter':event['counter'],
         'input':before.hex(),'expected_sha256':event['output_prefix_sha256'],
         'data_rva':hex(int(event['data'],16)-0x140000000)}
with out.open('x',encoding='utf-8') as f:json.dump(capture,f)
print(json.dumps({'data':event['data'],'prefix_length':len(before),'input_sha256':hashlib.sha256(before).hexdigest(),
                  'expected_output_sha256':event['output_prefix_sha256']}))
