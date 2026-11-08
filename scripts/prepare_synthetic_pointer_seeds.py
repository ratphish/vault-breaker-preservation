"""Prepare bounded speculative seeds from aligned code pointers in synthetic .rdata."""
import argparse,bisect,collections,hashlib,json,mmap,struct
from pathlib import Path
import numpy as np
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('text',type=Path);p.add_argument('rdata',type=Path);p.add_argument('out',type=Path);a=p.parse_args();root=a.out.resolve()
if root.exists() or root.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('new private output directory required')
for path,want in [(a.pe,'d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'),(a.text,'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca'),(a.rdata,'e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42')]:
 with path.open('rb') as f:
  if hashlib.file_digest(f,'sha256').hexdigest()!=want:raise ValueError('wrong input')
with a.pe.open('rb') as f:f.seek(0x35309200);data=f.read(3509556)
intervals=[]
for i in range(0,len(data)-11,12):
 v,end,u=struct.unpack_from('<III',data,i)
 if 0x1000<=v<end<=0x32c84000 and end-v<0x100000 and u<0x39d3e000 and u%4==0:intervals.append((v,end))
intervals.sort();merged=[]
for v,end in intervals:
 if merged and v<=merged[-1][1]:merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
 else:merged.append((v,end))
ms=[v for v,_ in merged];pdata_starts=sorted(set(v for v,_ in intervals));r=a.rdata.read_bytes();raw=np.frombuffer(r[:len(r)//8*8],dtype='<u8');values=raw[(raw>=0x140001000)&(raw<0x172c84000)];pointer_words_count=len(values);freq=collections.Counter(int(v)-0x140000000 for v in values);seeds=[]
for v in sorted(freq):
 j=bisect.bisect_right(ms,v)-1
 if not (j>=0 and v<merged[j][1]):seeds.append(v)
if len(seeds)!=34417:raise ValueError(f'unexpected candidate count {len(seeds)}')
groups={};limit=0x2000000
for i,v in enumerate(seeds):
 j=bisect.bisect_right(pdata_starts,v);next_pdata=pdata_starts[j] if j<len(pdata_starts) else 0x32c84000;next_seed=seeds[i+1] if i+1<len(seeds) else 0x32c84000;end=min(v+256,next_seed,next_pdata,0x32c84000)
 if end<=v:raise ValueError('invalid bound')
 groups.setdefault(v//limit*limit,[]).append((v,end,freq[v]))
root.mkdir();manifest=[]
with a.text.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for base,values in sorted(groups.items()):
  lo=max(base,0x1000);hi=min(base+limit+0x100,0x1000+851977728);payload=image[lo-0x1000:hi-0x1000];digest=hashlib.sha256(payload).hexdigest()
  for part in range(0,len(values),12000):
   subset=values[part:part+12000];name=f'{base:08x}_{part//12000:02d}';d=root/name;d.mkdir();(d/'range.bin').write_bytes(payload);(d/'ranges.txt').write_text(''.join(f'0x{0x140000000+v:x} 0x{0x140000000+end-1:x}\n' for v,end,_ in subset));(d/'provenance.jsonl').write_text(''.join(json.dumps({'address':hex(0x140000000+v),'rdata_pointer_occurrences':n,'bound_bytes':end-v})+'\n' for v,end,n in subset));manifest.append({'window':name,'base':hex(0x140000000+lo),'ranges':len(subset),'bytes':len(payload),'sha256':digest})
(root/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps({'candidate_seeds':len(seeds),'windows':len(manifest),'pointer_words':pointer_words_count,'warning':'Synthetic .rdata pointers are unverified candidates; arbitrary 256-byte upper bounds do not establish function ends.'}))
