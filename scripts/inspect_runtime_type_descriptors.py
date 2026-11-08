"""Resolve selected type registry descriptors and their runtime synthetic nodes."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('vmp',type=Path);p.add_argument('index',type=Path);p.add_argument('runtime_map',type=Path);p.add_argument('tags',nargs='+');a=p.parse_args()
b=a.vmp.read_bytes();assert hashlib.sha256(b).hexdigest()=='7aa5f1d4e1182373ee9275af90f37e5dbba75c85a0c1d6580803f2c25c0a9742'
wanted={int(t,16) for t in a.tags};idx={int(x['tag'],16):x for x in map(json.loads,a.index.read_text(encoding='utf-8-sig').splitlines()) if int(x['tag'],16) in wanted};runtime={int(x['key'],16):x for x in map(json.loads,a.runtime_map.read_text(encoding='utf-8-sig').splitlines()) if int(x['key'],16) in wanted};assert idx.keys()==wanted==runtime.keys()
rows=[]
for k in sorted(wanted):
 r=idx[k];o=int(r['record_offset'],16);size=struct.unpack_from('<Q',b,o)[0];assert size==r['record_size'] and o+size<=len(b);assert int(runtime[k]['record'],16)==0x179600000+o
 ptrs=[]
 for off in (0x38,0x40):
  field=o+off;rel=struct.unpack_from('<q',b,field)[0];target=field+rel if rel else None
  if target is not None:assert 0<=target<len(b)
  ptrs.append({'field_offset':hex(off),'target_offset':hex(target) if target is not None else None})
 rows.append({'tag':f'{k:08X}','class_hash':r['class_hash'],'record':hex(o),'size':size,'synthetic_object':runtime[k]['object'],'synthetic_backing':runtime[k]['backing'],'relative_targets':ptrs})
print(json.dumps({'scope':'synthetic registry objects; target semantics and executable consumers unproven','rows':rows},indent=2))
