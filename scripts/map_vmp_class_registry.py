"""Cross-check candidate VMP class hashes against hash/pointer rows in modeled rdata."""
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('records',type=Path)
p.add_argument('rdata',type=Path)
p.add_argument('data',type=Path)
a=p.parse_args()
records=json.loads(a.records.read_text(encoding='utf-8-sig'))['records']
r=a.rdata.read_bytes();d=a.data.read_bytes();wanted={int(z['class_hash'],16) for z in records}
data_va=0x173534000;matches=collections.defaultdict(list)
for off in range(8,len(r)-7,8):
    pointer,h=struct.unpack_from('<QQ',r,off-8)
    if h in wanted and data_va<=pointer<=data_va+len(d)-16:
        v=pointer-data_va
        matches[h].append({'rdata_offset':hex(off),'pointer_field_offset':hex(off-8),'pointer':hex(pointer),
                           'modeled_data_prefix':d[v:v+16].hex()})
rows=[]
for rec in records:
    h=int(rec['class_hash'],16)
    rows.append({'vmp_offset':rec['offset'],'parent_type':rec['parent_type'],'class_hash':rec['class_hash'],
                 'member_count':rec['member_count'],'registry_candidates':matches[h]})
def table_row(off):
    if not 8<=off<=len(r)-8:return None
    ptr,h=struct.unpack_from('<QQ',r,off-8)
    return (h,ptr) if h<=0xffffffff and data_va<=ptr<data_va+len(d) else None
groups=collections.Counter()
for row in rows:
    for match in row['registry_candidates']:
        pos=int(match['rdata_offset'],16);start=pos;end=pos+16
        while table_row(start-16) and table_row(start-16)[0]<table_row(start)[0]:start-=16
        while table_row(end) and table_row(end-16)[0]<table_row(end)[0]:end+=16
        groups[(start,end)]+=1
tables=[{'rdata_offset':hex(start),'rva':hex(0x32c84000+start),'entries':(end-start)//16,'matched_records':count,'bounds':'heuristic sorted run; not a verified descriptor extent'} for (start,end),count in sorted(groups.items())]
print(json.dumps({'rdata_sha256':hashlib.sha256(r).hexdigest(),'data_sha256':hashlib.sha256(d).hexdigest(),
                  'records':len(rows),'records_with_candidates':sum(bool(z['registry_candidates']) for z in rows),
                  'tables':tables,'rows':rows,'warning':'Each candidate pairs a hash with its preceding pointer. Table extents are heuristic and may include adjacent rows. Runtime-keyed mapping is validated separately in synthetic checkpoints; executable bindings remain unproven.'},indent=2))
