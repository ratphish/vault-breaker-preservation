"""Prepare large, non-overlapping modeled text events and declared ranges for bounded Ghidra analysis."""
import argparse,hashlib,json,mmap,struct
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('out',type=Path);a=p.parse_args();out=a.out.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('output must be a new private directory')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
 f.seek(0x35309200);raw=f.read(3509556)
ranges=[struct.unpack_from('<III',raw,i)[:2] for i in range(0,len(raw)-11,12)]
x=json.loads(a.trace.read_text());events=x['fast_transform_events'];contexts=x['transform_entries'];out.mkdir();manifest=[]
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for i,e in enumerate(events):
  if e.get('region')!='text' or e['length']<65536 or i in (63666,63675):continue
  va=int(e['data'],16);v=va-0x140000000;n=e['length'];z=v+n
  if not 0x1000<=v<z<=0x1000+851977728:raise ValueError('invalid range')
  selected=sorted(set((a,b) for a,b in ranges if v<=a<b<=z and b-a<=65536))
  if not selected:continue
  before=image[v-0xa00:v-0xa00+n];ctx=contexts[i]
  if hashlib.sha256(before).hexdigest()!=e['before_sha256']:raise ValueError('input mismatch')
  plain=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
  if hashlib.sha256(plain).hexdigest()!=e['after_sha256']:raise ValueError('output mismatch')
  root=out/str(i);root.mkdir();(root/'range.bin').write_bytes(plain);(root/'ranges.txt').write_text(''.join(f'0x{0x140000000+a:x} 0x{0x140000000+b-1:x}\n' for a,b in selected));manifest.append({'event':i,'base':hex(va),'bytes':n,'ranges':len(selected),'sha256':e['after_sha256']})
(out/'manifest.json').write_text(json.dumps(manifest,indent=2));print(json.dumps(manifest))
