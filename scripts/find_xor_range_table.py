"""Find XOR-masked 32-bit range tables matching observed synthetic data events."""
import argparse
import hashlib
import json
import mmap
import struct
from pathlib import Path
import numpy as np

p=argparse.ArgumentParser()
p.add_argument('pe',type=Path)
p.add_argument('trace',type=Path)
a=p.parse_args()
with a.pe.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
x=json.loads(a.trace.read_text(encoding='utf-8-sig'))
events=x['parent_data_events']
if len(events)<16:raise ValueError('need at least 16 observed events')
bases=[0x140000000,0x173534000]
expected={base:[(int(e['data'],16)-base,int(e['data'],16)-base+e['length']-1) for e in events[:16]] for base in bases}
hits=[];chunk=8*1024*1024
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
    for start in range(0,len(image)-32,chunk):
        n=min(chunk,len(image)-32-start)
        q=[np.ndarray((n,),dtype='<u4',buffer=image,offset=start+off,strides=(1,)) for off in (0,4,8,12)]
        for base,exp in expected.items():
            candidates=np.flatnonzero(((q[0]^q[1])==np.uint32(exp[0][0]^exp[0][1])) & ((q[0]^q[2])==np.uint32(exp[0][0]^exp[1][0])) & ((q[0]^q[3])==np.uint32(exp[0][0]^exp[1][1])))
            for candidate in candidates:
                pos=start+int(candidate);mask=struct.unpack_from('<I',image,pos)[0]^exp[0][0]
                if pos+16*8>len(image):continue
                if all((struct.unpack_from('<I',image,pos+8*i)[0]^mask)==begin and (struct.unpack_from('<I',image,pos+8*i+4)[0]^mask)==end for i,(begin,end) in enumerate(exp)):
                    hits.append({'file_offset':hex(pos),'address_basis':hex(base),'xor_mask':hex(mask),'first_16_match':True})
        del q
print(json.dumps({'pe_bytes_scanned':a.pe.stat().st_size,'candidates':hits,
                  'warning':'Matching descriptors establish table-byte correspondence only; execution and later coverage remain synthetic.'},indent=2))
