"""Prepare the 64 KiB–1 MiB PE-declared ranges excluded from the small-range batches."""
import argparse,hashlib,json,mmap,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('text',type=Path);p.add_argument('out',type=Path);a=p.parse_args();root=a.out.resolve()
if root.exists() or root.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('output must be new and private')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
 f.seek(0x35309200);pdata=f.read(3509556)
with a.text.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':raise ValueError('wrong modeled section')
groups={}
for off in range(0,len(pdata)-11,12):
 v,end,u=struct.unpack_from('<III',pdata,off)
 if 0x1000<=v<end<=0x32c84000 and 0x10000<end-v<0x100000:groups.setdefault(v//0x400000*0x400000,set()).add((v,end))
root.mkdir();manifest=[]
with a.text.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for base,rs in sorted(groups.items()):
  ranges=sorted(rs);lo=max(base,0x1000);hi=min(base+0x500000,0x1000+851977728)
  if any(end>hi for _,end in ranges):raise ValueError('range crosses window')
  d=root/f'{base:08x}';d.mkdir();payload=image[lo-0x1000:hi-0x1000];(d/'range.bin').write_bytes(payload);(d/'ranges.txt').write_text(''.join(f'0x{0x140000000+v:x} 0x{0x140000000+end-1:x}\n' for v,end in ranges));manifest.append({'window':f'{base:08x}','base':hex(0x140000000+lo),'bytes':len(payload),'ranges':len(ranges),'sha256':hashlib.sha256(payload).hexdigest()})
(root/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps({'windows':len(manifest),'ranges':sum(v['ranges'] for v in manifest),'warning':'Large exception records may span unrelated code, unmodeled bytes, or overlapping functions.'}))
