"""Summarize verified synthetic TLS-dispatch transitions and containing PE ranges."""
import argparse,collections,hashlib,json,struct
from pathlib import Path
import numpy as np
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('edges',type=Path);a=p.parse_args()
if a.edges.exists():raise ValueError('output exists')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
 f.seek(0x35309200);raw=f.read(3509556)
x=json.loads(a.trace.read_text());events=x.get('dispatch_events',[])
if not events or any(z.get('matched') is not True for z in events):raise ValueError('unverified or missing transitions')
records=[]
for o in range(0,len(raw)-11,12):
 start,end,u=struct.unpack_from('<III',raw,o)
 if 0x1000<=start<end<=0x32c84000 and end-start<0x100000 and u<0x39d3e000 and u%4==0:records.append((start,end))
beg=np.array([v[0] for v in records],dtype=np.uint32);end=np.array([v[1] for v in records],dtype=np.uint32);counts=collections.Counter((z['source'],z['continuation']) for z in events);rows=[]
for (source,target),n in sorted(counts.items()):
 rva=int(target,16)-0x140000000;idx=np.flatnonzero((beg<=rva)&(end>rva));best=min(idx,key=lambda i:int(end[i])-int(beg[i])) if len(idx) else None
 rows.append({'source':source,'continuation':target,'observations':n,'containing_declared_range':{'start':hex(0x140000000+int(beg[best])),'end_exclusive':hex(0x140000000+int(end[best])),'candidates':len(idx)} if best is not None else None})
with a.edges.open('x',encoding='utf-8') as f:
 for row in rows:f.write(json.dumps(row)+'\n')
print(json.dumps({'dispatch_events':len(events),'unique_edges':len(rows),'edges_with_declared_target_range':sum(z['containing_declared_range'] is not None for z in rows),'warning':'Transitions observed only in an artificial fixed-timestamp TLS-callback model; range membership does not prove real execution.'}))
