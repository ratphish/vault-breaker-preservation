"""Find disp32 references across a complete raw modeled text-section image."""
import argparse,bisect,hashlib,json,mmap
from pathlib import Path
import numpy as np
p=argparse.ArgumentParser();p.add_argument('text',type=Path);p.add_argument('trace',type=Path);p.add_argument('rvas',nargs='+',type=lambda s:int(s,0));a=p.parse_args()
if a.text.stat().st_size!=851977728:raise ValueError('unexpected section size')
with a.text.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':raise ValueError('unexpected synthetic section')
x=json.loads(a.trace.read_text());events=sorted((int(e['data'],16)-0x140000000,int(e['data'],16)-0x140000000+e['length'],i) for i,e in enumerate(x['fast_transform_events']) if e['region']=='text');starts=[v[0] for v in events];size=851977728;chunk=8*1024*1024;hits=[]
with a.text.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
 for start in range(0,size-3,chunk):
  n=min(chunk,size-3-start);vals=np.ndarray((n,),dtype='<u4',buffer=mm,offset=start,strides=(1,));idx=np.arange(n,dtype=np.uint32);sums=vals+idx
  for target in a.rvas:
   want=np.uint32((target-0x1000-start-4)&0xffffffff)
   for v in np.flatnonzero(sums==want):
    pos=start+int(v);rva=0x1000+pos;j=bisect.bisect_right(starts,rva)-1;event=events[j][2] if j>=0 and rva+4<=events[j][1] else None
    hits.append({'target_rva':hex(target),'disp_rva':hex(rva),'event':event,'range_source':'modeled' if event is not None else 'original_unmodeled'})
  del vals,idx,sums
print(json.dumps({'bytes_scanned':size,'hits':hits,'warning':'Raw disp32 candidates include unchanged, unmodeled bytes; no instruction-boundary or reachability proof.'}))
