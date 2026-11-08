"""Search direct relative branch candidates to bounded address intervals in the modeled raw text."""
import argparse,bisect,hashlib,json,mmap
from pathlib import Path
import numpy as np
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=argparse.ArgumentParser();p.add_argument('text',type=Path);p.add_argument('trace',type=Path);p.add_argument('bounds',nargs='+',type=lambda s:int(s,0));p.add_argument('--expected-sha256',default='e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca');a=p.parse_args()
if len(a.bounds)%2 or any(a.bounds[i]>=a.bounds[i+1] or a.bounds[i+1]-a.bounds[i]>4096 for i in range(0,len(a.bounds),2)):raise ValueError('bad bounds')
with a.text.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!=a.expected_sha256.lower():raise ValueError('wrong section')
x=json.loads(a.trace.read_text());ev=sorted((int(e['data'],16)-0x140000000,int(e['data'],16)-0x140000000+e['length'],i) for i,e in enumerate(x['fast_transform_events']) if e['region']=='text');starts=[z[0] for z in ev];size=851977728;chunk=8*1024*1024;hits=[];cs=Cs(CS_ARCH_X86,CS_MODE_64)
with a.text.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as m:
 for start in range(0,size-3,chunk):
  n=min(chunk,size-3-start);vals=np.ndarray((n,),dtype='<u4',buffer=m,offset=start,strides=(1,));idx=np.arange(n,dtype=np.uint32);targets=vals+idx+np.uint32((0x1000+start+4)&0xffffffff)
  for k in range(0,len(a.bounds),2):
   for j in np.flatnonzero((targets>=a.bounds[k])&(targets<a.bounds[k+1])):
    pos=start+int(j);ins_start=None
    if pos>=1 and m[pos-1] in (0xe8,0xe9):ins_start=pos-1
    elif pos>=2 and m[pos-2]==0x0f and 0x80<=m[pos-1]<=0x8f:ins_start=pos-2
    if ins_start is None:continue
    va=0x140001000+ins_start;ins=list(cs.disasm(m[ins_start:pos+4],va))
    if len(ins)!=1 or ins[0].size!=pos+4-ins_start:continue
    rva=0x1000+ins_start;ii=bisect.bisect_right(starts,rva)-1;event=ev[ii][2] if ii>=0 and rva+ins[0].size<=ev[ii][1] else None
    hits.append({'site':hex(va),'target':hex(0x140000000+int(targets[int(j)])),'instruction':ins[0].mnemonic+' '+ins[0].op_str,'event':event})
  del vals,idx,targets
print(json.dumps({'bytes_scanned':size,'hits':hits,'warning':'Candidates may be overlapping, unreachable, or in unchanged protected bytes.'}))
