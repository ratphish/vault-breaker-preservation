"""Search a private modeled data image for Vault metadata identifiers."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('data',type=Path)
p.add_argument('slots',type=Path)
p.add_argument('members',type=Path)
a=p.parse_args()
slots=json.loads(a.slots.read_text(encoding='utf-8-sig'))['entries']
members=json.loads(a.members.read_text(encoding='utf-8-sig'))['members']
patterns=[]
for label,val in [('activity_metadata',0x80b37c7e),('activity_component',0x80b37fed),
                  ('activity_definition',0x80b37fe9),('pedestal_metadata',0x80b38561),
                  ('pedestal_definition',0x80b38555),('activity_class_header_word',0xe064302e),
                  ('pedestal_class_header_word',0x68936e81)]:
    patterns.append((label,'u32',struct.pack('<I',val)))
for row in slots:
    patterns.append((row['name'],'ascii',row['name'].encode('ascii')))
    v=0x811c9dc5
    for c in row['name'].encode('ascii'):v=((v*0x1000193)&0xffffffff)^c
    patterns.append((row['name'],'fnv1',struct.pack('<I',v)))
for row in members:
    patterns.append((row['name'],'member_fnv1',struct.pack('<I',int(row['name_hash_fnv1'],16))))
matches=[]
with a.data.open('rb') as f:
    digest=hashlib.file_digest(f,'sha256').hexdigest();f.seek(0)
    with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
        for label,kind,needle in patterns:
            pos=image.find(needle);offsets=[]
            while pos>=0:
                offsets.append(hex(pos))
                if len(offsets)>=100:raise ValueError(f'excessive hits for {label}')
                pos=image.find(needle,pos+1)
            if offsets:matches.append({'identifier':label,'kind':kind,'offsets':offsets})
print(json.dumps({'image_sha256':digest,'image_size':a.data.stat().st_size,'patterns':len(patterns),
                  'matches':matches,'warning':'Exact bytes only; accidental matches and transformed/indirect bindings remain possible.'},indent=2))
