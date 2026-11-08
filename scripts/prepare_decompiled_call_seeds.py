"""Prepare recurrent candidate call targets from prior private Ghidra indexes."""
import argparse,bisect,collections,hashlib,json,mmap,re,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('text',type=Path);p.add_argument('prior_seeds',type=Path);p.add_argument('out',type=Path);p.add_argument('indexes',nargs='+',type=Path);a=p.parse_args();root=a.out.resolve()
if root.exists() or root.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('new private output required')
for path,want in [(a.pe,'d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'),(a.text,'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca')]:
 with path.open('rb') as f:
  if hashlib.file_digest(f,'sha256').hexdigest()!=want:raise ValueError('wrong input')
pat=re.compile(r'func_0x([0-9a-fA-F]+)\(');counts=collections.Counter();callers={}
for path in a.indexes:
 with path.open(encoding='utf8') as f:
  for line in f:
   x=json.loads(line)
   for text in set(pat.findall(x['pseudocode'])):
    va=int(text,16)
    if 0x140025c50<=va<0x16ee25c50:
     counts[va]+=1
     if len(callers.setdefault(va,[]))<8:callers[va].append(x['address'])
prior=set()
for q in a.prior_seeds.glob('*/provenance.jsonl'):
 for line in q.read_text().splitlines():prior.add(int(json.loads(line)['address'],16))
with a.pe.open('rb') as f:f.seek(0x35309200);data=f.read(3509556)
intervals=[]
for i in range(0,len(data)-11,12):
 v,end,u=struct.unpack_from('<III',data,i)
 if 0x1000<=v<end<=0x32c84000 and end-v<0x100000 and u<0x39d3e000 and u%4==0:intervals.append((v+0x140000000,end+0x140000000))
intervals.sort();merged=[]
for v,end in intervals:
 if merged and v<=merged[-1][1]:merged[-1]=(merged[-1][0],max(end,merged[-1][1]))
 else:merged.append((v,end))
starts=[v for v,_ in merged];pdata_starts=sorted(set(v for v,_ in intervals));seeds=[]
for v,n in sorted(counts.items()):
 if n<2 or v in prior:continue
 j=bisect.bisect_right(starts,v)-1
 if not (j>=0 and v<merged[j][1]):seeds.append(v)
groups={};limit=0x2000000
for i,v in enumerate(seeds):
 j=bisect.bisect_right(pdata_starts,v);next_pdata=pdata_starts[j] if j<len(pdata_starts) else 0x172c84000;next_seed=seeds[i+1] if i+1<len(seeds) else 0x172c84000;end=min(v+256,next_seed,next_pdata,0x172c84000)
 if end<=v:raise ValueError('invalid bound')
 groups.setdefault((v-0x140000000)//limit*limit,[]).append((v,end,counts[v],callers[v]))
root.mkdir();manifest=[]
with a.text.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for base,values in sorted(groups.items()):
  lo=max(base,0x1000);hi=min(base+limit+0x100,0x1000+851977728);payload=image[lo-0x1000:hi-0x1000];digest=hashlib.sha256(payload).hexdigest();name=f'{base:08x}';d=root/name;d.mkdir();(d/'range.bin').write_bytes(payload);(d/'ranges.txt').write_text(''.join(f'{v:#x} {end-1:#x}\n' for v,end,_,_ in values));(d/'provenance.jsonl').write_text(''.join(json.dumps({'address':hex(v),'caller_count':n,'sample_callers':cs,'bound_bytes':end-v})+'\n' for v,end,n,cs in values));manifest.append({'window':name,'base':hex(0x140000000+lo),'ranges':len(values),'bytes':len(payload),'sha256':digest})
(root/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps({'candidate_seeds':len(seeds),'windows':len(manifest),'min_callers':2,'warning':'Derived from potentially inaccurate decompilation; static repetition does not establish entry boundaries or execution.'}))
