"""Find candidate embedded records whose parent word matches selected type IDs."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('image',type=Path)
p.add_argument('type_ids',nargs='+',type=lambda s:int(s,16))
a=p.parse_args()
b=a.image.read_bytes();rows=[]
for target in a.type_ids:
    needle=struct.pack('<I',target);pos=b.find(needle)
    while pos>=0:
        base=pos-0x10
        if base>=0 and base%8==0 and base+0x58<=len(b):
            size,name_hash=struct.unpack_from('<QI',b,base)
            if 0x60<=size<=0x10000 and base+size<=len(b):
                rel=struct.unpack_from('<q',b,base+0x50)[0];array=base+0x50+rel
                if base<=array<=base+size-24:
                    count=struct.unpack_from('<Q',b,array)[0]
                    if count<=1000 and array+24+12*count<=base+size:
                        sentinel,base_type,base_offset,pad=struct.unpack_from('<IIII',b,array+8)
                        if sentinel==0x811c9dc5 and base_offset==0 and pad==0:
                            members=[{'hash':f'{h:08x}','type':f'{t:08x}','offset':hex(o)} for h,t,o in (struct.unpack_from('<III',b,array+24+12*i) for i in range(count))]
                            rows.append({'parent_type':f'{target:08x}','offset':hex(base),'size':size,'class_hash':f'{name_hash:08x}',
                                         'member_array_offset':hex(array),'member_count':count,'base_type':f'{base_type:08x}','members':members})
        pos=b.find(needle,pos+1)
print(json.dumps({'image_sha256':hashlib.sha256(b).hexdigest(),'records':rows,
                  'warning':'Candidate serialized structures in synthetic data; parent and class semantics and executable bindings are not proven.'},indent=2))
