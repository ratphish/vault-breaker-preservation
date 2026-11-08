"""Prepare zero-filled bounded windows containing only verified modeled text events."""
import argparse,bisect,hashlib,json,mmap,struct
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('out',type=Path);p.add_argument('--min-event',type=int,default=0);a=p.parse_args();root=a.out.resolve()
if root.exists() or root.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('output must be new and private')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
 f.seek(0x35309200);pdata=f.read(3509556)
x=json.loads(a.trace.read_text());events=[];windows={};size=0x200000
root.mkdir()
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for i,e in enumerate(x['fast_transform_events']):
  if e.get('region')!='text' or i<a.min_event:continue
  rva=int(e['data'],16)-0x140000000;n=e['length'];end=rva+n
  if not 0x1000<=rva<end<=0x1000+851977728:raise ValueError('event outside text')
  before=image[rva-0xa00:rva-0xa00+n];ctx=x['transform_entries'][i]
  if hashlib.sha256(before).hexdigest()!=e['before_sha256']:raise ValueError(f'input mismatch {i}')
  after=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
  if hashlib.sha256(after).hexdigest()!=e['after_sha256']:raise ValueError(f'output mismatch {i}')
  events.append((rva,end,i));off=0
  while off<n:
   v=rva+off;base=v//size*size;amount=min(n-off,size-(v-base))
   if base not in windows:windows[base]={'data':bytearray(size),'bytes':0,'ranges':[]}
   w=windows[base];w['data'][v-base:v-base+amount]=after[off:off+amount];w['bytes']+=amount;off+=amount
ordered=sorted(events)
if any(ordered[i][0]<ordered[i-1][1] for i in range(1,len(ordered))):raise ValueError('overlapping events need explicit ordering')
starts=[e[0] for e in ordered]
for off in range(0,len(pdata)-11,12):
 v,end,u=struct.unpack_from('<III',pdata,off)
 if not 0x1000<=v<end<=0x32c84000 or end-v>65536:continue
 j=bisect.bisect_right(starts,v)-1;base=v//size*size
 if j>=0 and end<=ordered[j][1] and end<=base+size:windows[base]['ranges'].append((v,end))
manifest=[]
for base,w in sorted(windows.items()):
 ranges=sorted(set(w['ranges']))
 if not ranges:continue
 d=root/f'{base:08x}';d.mkdir();(d/'range.bin').write_bytes(w['data']);(d/'ranges.txt').write_text(''.join(f'0x{0x140000000+v:x} 0x{0x140000000+end-1:x}\n' for v,end in ranges));manifest.append({'window':f'{base:08x}','base':hex(0x140000000+base),'modeled_bytes':w['bytes'],'ranges':len(ranges),'sha256':hashlib.sha256(w['data']).hexdigest()})
(root/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps({'windows':len(manifest),'modeled_bytes':sum(w['modeled_bytes'] for w in manifest),'ranges':sum(w['ranges'] for w in manifest),'max_ranges':max((w['ranges'] for w in manifest),default=0),'warning':'zero-filled gaps are unmodeled; declared function ranges only'}))
