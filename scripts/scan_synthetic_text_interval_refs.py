"""Find candidate disp32 references to modeled .rdata intervals; replay and verify text events."""
import argparse,hashlib,json,mmap
from pathlib import Path
import numpy as np
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('bounds',nargs='+',type=lambda s:int(s,0));a=p.parse_args()
if len(a.bounds)%2 or any(a.bounds[i]>=a.bounds[i+1] or a.bounds[i+1]-a.bounds[i]>65536 for i in range(0,len(a.bounds),2)):raise ValueError('provide small ordered RVA interval pairs')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
x=json.loads(a.trace.read_text());hits=[];count=total=0
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for i,e in enumerate(x['fast_transform_events']):
  if e.get('region')!='text':continue
  va=int(e['data'],16);rva=va-0x140000000;n=e['length'];ctx=x['transform_entries'][i]
  if not 0x1000<=rva<rva+n<=0x1000+851977728:raise ValueError('bad range')
  before=image[rva-0xa00:rva-0xa00+n]
  if hashlib.sha256(before).hexdigest()!=e['before_sha256']:raise ValueError('input mismatch')
  plain=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
  if hashlib.sha256(plain).hexdigest()!=e['after_sha256']:raise ValueError('output mismatch')
  count+=1;total+=n
  if n<4:continue
  vals=np.ndarray((n-3,),dtype='<u4',buffer=plain,strides=(1,));idx=np.arange(n-3,dtype=np.uint32);targets=vals+idx+np.uint32((rva+4)&0xffffffff)
  for j in range(0,len(a.bounds),2):
   for k in np.flatnonzero((targets>=a.bounds[j])&(targets<a.bounds[j+1])):hits.append({'event':i,'disp_va':hex(va+int(k)),'target_va':hex(0x140000000+int(targets[k])),'offset_in_event':int(k)})
print(json.dumps({'text_events_verified':count,'bytes_replayed':total,'hits':hits,'warning':'Raw disp32 candidates; instruction boundaries, reachability and meaning not established.'}))
