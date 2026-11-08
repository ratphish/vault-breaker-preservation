"""Verify and search the synthetic text events for exact little-endian metadata values."""
import argparse,hashlib,json,mmap,struct
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('values',nargs='+',type=lambda s:int(s,0));a=p.parse_args()
with a.pe.open('rb') as f:identity=hashlib.file_digest(f,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected PE identity')
x=json.loads(a.trace.read_text());events=x['fast_transform_events'];contexts=x['transform_entries'];hits=[];total=count=0
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for i,e in enumerate(events):
  if e.get('region')!='text':continue
  va=int(e['data'],16);rva=va-0x140000000;n=e['length']
  if not 0x1000<=rva<rva+n<=0x1000+851977728:raise ValueError('invalid range')
  before=image[rva-0xa00:rva-0xa00+n];ctx=contexts[i]
  if hashlib.sha256(before).hexdigest()!=e['before_sha256']:raise ValueError('input mismatch')
  plain=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
  if hashlib.sha256(plain).hexdigest()!=e['after_sha256']:raise ValueError('output mismatch')
  count+=1;total+=n
  for v in a.values:
   needle=struct.pack('<I',v);pos=0
   while (pos:=plain.find(needle,pos))!=-1:
    hits.append({'event':i,'value':hex(v),'va':hex(va+pos)});pos+=1
print(json.dumps({'text_events_verified':count,'bytes_replayed':total,'values':[hex(v) for v in a.values],'hits':hits,'warning':'Raw-byte candidates in a synthetic model; not instruction or semantic evidence.'}))
