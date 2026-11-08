"""Verify complete modeled shared-type initializer writes and backing records."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('probe',type=Path);p.add_argument('types',type=Path);p.add_argument('data',type=Path);a=p.parse_args()
d=json.loads(a.probe.read_text(encoding='utf-8-sig'));types=json.loads(a.types.read_text(encoding='utf-8-sig'))['selected'];raw=a.data.read_bytes()
if len(raw)!=0x5d72be1 or hashlib.sha256(raw).hexdigest()!='a9043bd1c26a144598e7b1f55ea3a9a2da5eddbae8b4cea95fad57537b91da49':raise ValueError('unexpected modeled data')
if d['stop']!={'kind':'target_reached','address':'0x16f8d4c40'} or d['image_writes']!=len(d['image_write_samples']):raise ValueError('incomplete probe')
by_addr={}
for w in d['image_write_samples']:by_addr.setdefault(int(w['address'],16),[]).append(w)
groups=[]
for base,count,site in [(0x1767f5fe0,1718,'0x16fc07380'),(0x176804310,1718,'0x1713ed180'),(0x176812670,1716,'0x16f15d640')]:
 for i in range(count):
  address=base+32*i;heads=[x for x in by_addr.get(address,[]) if x['rip']==site and x['size']==4 and x['value']=='0xffffffff'];ptrs=[x for x in by_addr.get(address+24,[]) if x['size']==8]
  if len(heads)!=1 or len(ptrs)!=1:raise ValueError('missing initializer entry '+hex(address))
  ptr=int(ptrs[0]['value'],16)
  if not 0x173534000<=ptr<=0x1792a6be1-16:raise ValueError('backing pointer out of range')
 groups.append({'base':hex(base),'objects':count,'stride':32,'backing_pointer_offset':24,'sentinel_write_site':site})
selected=[]
for t in types:
 if not t.get('registry_candidates'):continue
 obj=int(t['registry_candidates'][0]['pointer'],16);w=[x for x in by_addr[obj+24] if x['size']==8]
 if len(w)!=1:raise ValueError('bad selected backing pointer')
 ptr=int(w[0]['value'],16);first,second=struct.unpack_from('<QQ',raw,ptr-0x173534000)
 selected.append({'tag':t['tag'],'object':hex(obj),'backing_record':hex(ptr),'modeled_initial_qwords':[hex(first),hex(second)]})
print(json.dumps({'probe_start':d['start'],'writes':d['image_writes'],'groups':groups,'selected':selected,'warning':'Synthetic initialized pointers and modeled data, not a real runtime trace or a proven method dispatch.'},indent=2))
