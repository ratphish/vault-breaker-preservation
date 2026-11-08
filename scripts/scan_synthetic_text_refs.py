"""Replay bounded synthetic text events and find direct disp32 references within each range."""
import argparse,hashlib,json,mmap
from pathlib import Path
import numpy as np
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('target_rvas',nargs='+',type=lambda s:int(s,0));a=p.parse_args()
with a.pe.open('rb') as f:identity=hashlib.file_digest(f,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected PE identity')
x=json.loads(a.trace.read_text());events=x['fast_transform_events'];contexts=x['transform_entries'];base=0x140000000;hits=[];count=total=0
if len(contexts)<len(events):raise ValueError('missing contexts')
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for i,event in enumerate(events):
  if event.get('region')!='text':continue
  ctx=contexts[i];va=int(event['data'],16);n=event['length'];rva=va-base;off=rva-0xa00
  if not (0x1000<=rva and rva+n<=0x1000+851977728):raise ValueError('invalid event range')
  before=image[off:off+n]
  if hashlib.sha256(before).hexdigest()!=event['before_sha256']:raise ValueError(f'input mismatch event {i}')
  key=bytes.fromhex(ctx['rcx_bytes'])[:16];iv=bytes.fromhex(ctx['rdx_bytes'])[:16];plain=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv,'big')).encrypt(before)
  if hashlib.sha256(plain).hexdigest()!=event['after_sha256']:raise ValueError(f'output mismatch event {i}')
  count+=1;total+=n
  if n<4:continue
  vals=np.ndarray((n-3,),dtype='<u4',buffer=plain,strides=(1,));idx=np.arange(n-3,dtype=np.uint32);sums=vals+idx
  for target in a.target_rvas:
   want=np.uint32((target-rva-4)&0xffffffff)
   for j in np.flatnonzero(sums==want):hits.append({'event':i,'target_rva':hex(target),'disp_va':hex(va+int(j)),'event_va':hex(va),'event_length':n,'offset_in_event':int(j)})
print(json.dumps({'text_events_verified':count,'bytes_replayed':total,'hits':hits,'candidate_count':len(hits),'warning':'Synthetic inputs and disp32 candidates only; instruction boundaries and runtime reachability unknown.'}))
