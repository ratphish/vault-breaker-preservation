"""Check three modeled registry descriptors against an artificial protected-code probe."""
import argparse, hashlib, json, struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('rdata',type=Path);p.add_argument('probe',type=Path);p.add_argument('types',type=Path);a=p.parse_args()
r=a.rdata.read_bytes()
if hashlib.sha256(r).hexdigest()!='e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42':raise ValueError('unexpected rdata')
probe=json.loads(a.probe.read_text(encoding='utf-8-sig'));types=json.loads(a.types.read_text(encoding='utf-8-sig'))['selected']
if probe['stop']!={'kind':'target_reached','address':'0x16f8d4c40'} or probe['registers_at_stop']['rcx']!='0x176803788' or probe['registers_at_stop']['rdx']!='0x3':raise ValueError('unexpected callee state')
writes={(x['address'],x['value']) for x in probe['image_write_samples']}
descriptors=[(0x176803788,0x172d66a70,1718),(0x176803798,0x172d6f5a0,1718),(0x1768037a8,0x172d77c50,1716)]
result=[]
for glob,ptr,count in descriptors:
 if not {(hex(glob),hex(ptr)),(hex(glob+8),hex(count))}<=writes:raise ValueError('missing descriptor writes')
 pos=ptr-0x172c84000
 rows=[(h,v) for v,h in (struct.unpack_from('<QQ',r,pos+16*i) for i in range(count))]
 if any(rows[i][0]>=rows[i+1][0] for i in range(count-1)) or any(not 0x173534000<=v<0x1792a6be1 for _,v in rows):raise ValueError('invalid table')
 matches=[]
 for t in types:
  if 'class_hash' not in t:continue
  for i,(h,v) in enumerate(rows):
   if h==int(t['class_hash'],16):
    if hex(v) not in [c['pointer'] for c in t['registry_candidates']]:raise ValueError('type pointer mismatch')
    matches.append({'tag':t['tag'],'row':i,'pointer':hex(v)})
 result.append({'descriptor':hex(glob),'pointer':hex(ptr),'count':count,'selected_type_matches':matches})
if len(result[0]['selected_type_matches'])!=3:raise ValueError('selected types not all in first table')
print(json.dumps({'probe_start':probe['start'],'callee':probe['stop']['address'],'descriptors':result,'warning':'The descriptor points at pointer/hash rows. This synthetic probe is not evidence of native process execution or a Vault handler.'},indent=2))
