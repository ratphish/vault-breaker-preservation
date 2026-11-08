"""Index the modeled VMP image's sorted embedded type records and selected IDs."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('vmp',type=Path)
p.add_argument('rdata',type=Path)
p.add_argument('out',type=Path)
p.add_argument('tags',nargs='*',type=lambda s:int(s,16))
a=p.parse_args();out=a.out.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('new private index required')
b=a.vmp.read_bytes();digest=hashlib.sha256(b).hexdigest()
if digest!='7aa5f1d4e1182373ee9275af90f37e5dbba75c85a0c1d6580803f2c25c0a9742':raise ValueError('unexpected modeled VMP image')
r=a.rdata.read_bytes()
if hashlib.sha256(r).hexdigest()!='e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42':raise ValueError('unexpected modeled rdata')
count=struct.unpack_from('<Q',b,0x60)[0]
if count!=29896 or 0x68+16*count>len(b):raise ValueError('unexpected type index')
rows=[];last=-1;tags=set()
for i in range(count):
    pos=0x68+16*i;rel,key=struct.unpack_from('<qQ',b,pos);target=pos+rel
    if key>>32 or not 0<=target<=len(b)-0x18:raise ValueError(f'invalid row {i}')
    package=key&0xffff;index=key>>16
    if package>4095 or index>=8192:raise ValueError(f'invalid embedded id {i}')
    size,h=struct.unpack_from('<QI',b,target);parent=struct.unpack_from('<I',b,target+0x10)[0]
    if not 0x18<=size<=len(b)-target or h<=last:raise ValueError(f'invalid record or hash order {i}')
    tag=0x80800000+package*8192+index
    if tag in tags:raise ValueError(f'duplicate tag {i}')
    tags.add(tag);last=h
    rows.append({'tag':f'{tag:08X}','class_hash':f'{h:08x}','record_offset':hex(target),
                 'record_size':size,'parent_word':f'{parent:08x}','index_offset':hex(pos),'registry_candidates':[]})
by_hash={int(row['class_hash'],16):row for row in rows}
for off in range(8,len(r)-7,8):
    ptr,h=struct.unpack_from('<QQ',r,off-8)
    if h in by_hash and 0x173534000<=ptr<0x1792a6be1:
        by_hash[h]['registry_candidates'].append({'rdata_offset':hex(off),'pointer_field_offset':hex(off-8),'pointer':hex(ptr)})
with out.open('x',encoding='utf-8') as f:
    for row in rows:f.write(json.dumps(row)+'\n')
selected=[]
by_tag={int(row['tag'],16):row for row in rows}
for tag in a.tags:selected.append(by_tag.get(tag,{'tag':f'{tag:08X}','not_in_index':True}))
print(json.dumps({'vmp_sha256':digest,'records':count,'unique_tags':len(tags),
                  'records_with_registry_candidates':sum(bool(z['registry_candidates']) for z in rows),
                  'selected':selected,'index_path':str(out),
                  'warning':'Each candidate pairs a hash with the preceding pointer; runtime confirmation is limited to the synthetic checkpoint, and executable bindings remain unproven.'},indent=2))
