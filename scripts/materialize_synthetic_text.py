"""Materialize the raw synthetic text section outside the repository, never a PE executable."""
import argparse,hashlib,json,mmap,os
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('out',type=Path);a=p.parse_args();out=a.out.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or out.suffix.lower()!='.bin':raise ValueError('new private .bin output required')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
x=json.loads(a.trace.read_text());events=x['fast_transform_events'];contexts=x['transform_entries'];raw=0x600;size=851977728;base=0x140001000;count=total=0
with a.pe.open('rb') as src,out.open('x+b') as dst:
 src.seek(raw);remaining=size
 while remaining:
  b=src.read(min(8*1024*1024,remaining))
  if not b:raise ValueError('short source section')
  dst.write(b);remaining-=len(b)
 dst.flush()
 with mmap.mmap(dst.fileno(),0,access=mmap.ACCESS_WRITE) as mapped:
  for i,e in enumerate(events):
   if e.get('region')!='text':continue
   off=int(e['data'],16)-base;n=e['length'];ctx=contexts[i]
   if not 0<=off<off+n<=size:raise ValueError('event out of text range')
   before=mapped[off:off+n]
   if hashlib.sha256(before).hexdigest()!=e['before_sha256']:raise ValueError(f'input mismatch {i}')
   after=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
   if hashlib.sha256(after).hexdigest()!=e['after_sha256']:raise ValueError(f'output mismatch {i}')
   mapped[off:off+n]=after;count+=1;total+=n
  mapped.flush()
 dst.seek(0);digest=hashlib.file_digest(dst,'sha256').hexdigest()
print(json.dumps({'bytes':size,'modeled_events':count,'modeled_bytes':total,'sha256':digest,'output':str(out),'warning':'Raw synthetic text section, not PE or validated runtime memory; most bytes remain original, unmodeled data and extrapolated events are included.'}))
