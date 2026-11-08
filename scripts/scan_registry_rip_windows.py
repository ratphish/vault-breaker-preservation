"""Find RIP-relative instruction candidates near candidate registry table boundaries."""
import argparse
import bisect
import hashlib
import json
import mmap
from pathlib import Path
import numpy as np
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_MEM,X86_REG_RIP

p=argparse.ArgumentParser()
p.add_argument('text',type=Path)
p.add_argument('trace',type=Path)
p.add_argument('registry',type=Path)
a=p.parse_args()
with a.text.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':raise ValueError('wrong text image')
reg=json.loads(a.registry.read_text(encoding='utf-8-sig'))
targets=sorted({int(z['rva'],16) for z in reg['tables']})
x=json.loads(a.trace.read_text())
events=sorted((int(e['data'],16)-0x140000000,int(e['data'],16)-0x140000000+e['length'],i) for i,e in enumerate(x['fast_transform_events']) if e['region']=='text')
starts=[e[0] for e in events];hits=[];cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;chunk=8*1024*1024
with a.text.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
    for start in range(0,len(image)-3,chunk):
        n=min(chunk,len(image)-3-start);vals=np.ndarray((n,),dtype='<u4',buffer=image,offset=start,strides=(1,));idx=np.arange(n,dtype=np.uint32)
        resolved=vals+idx+np.uint32((0x1000+start+4)&0xffffffff)
        for target in targets:
            for local in np.flatnonzero((resolved>=target-32)&(resolved<target+32)):
                pos=start+int(local)
                if pos<5:continue
                for off in range(1,6):
                    ins_start=pos-off;va=0x140001000+ins_start
                    ins=next(cs.disasm(image[ins_start:pos+4],va,count=1),None)
                    if not ins or ins.address+ins.size!=0x140001000+pos+4:continue
                    mem=[o for o in ins.operands if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP]
                    if not mem or ins.address+ins.size+mem[0].mem.disp!=0x140000000+int(resolved[int(local)]):continue
                    rva=0x1000+ins_start;j=bisect.bisect_right(starts,rva)-1;event=events[j][2] if j>=0 and rva+ins.size<=events[j][1] else None
                    hits.append({'site':hex(va),'instruction':ins.mnemonic+' '+ins.op_str,
                                 'resolved':hex(0x140000000+int(resolved[int(local)])),
                                 'table_start':hex(0x140000000+target),'delta':int(resolved[int(local)])-target,'modeled_event':event})
        del vals,idx,resolved
print(json.dumps({'table_count':len(targets),'window_each_side':32,'hits':hits,
                  'warning':'Overlapping instruction candidates in a synthetic image; boundaries and reachability are unverified.'},indent=2))
