"""Find possible direct branches into an address interval in replayed synthetic text."""
import argparse, hashlib, json, mmap
from pathlib import Path
import numpy as np
from Crypto.Cipher import AES
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('start',type=lambda s:int(s,0));p.add_argument('end',type=lambda s:int(s,0));a=p.parse_args()
if not 0 <= a.start < a.end <= 0xffffffff or a.end-a.start>65536:raise ValueError('invalid RVA interval')
with a.pe.open('rb') as f:identity=hashlib.file_digest(f,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected PE identity')
x=json.loads(a.trace.read_text());events=x['fast_transform_events'];contexts=x['transform_entries'];base=0x140000000;hits=[];count=total=0;cs=Cs(CS_ARCH_X86,CS_MODE_64)
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for i,e in enumerate(events):
  if e.get('region')!='text':continue
  va=int(e['data'],16);n=e['length'];rva=va-base;off=rva-0xa00
  if not (0x1000<=rva and rva+n<=0x1000+851977728):raise ValueError('invalid event')
  before=image[off:off+n];ctx=contexts[i]
  if hashlib.sha256(before).hexdigest()!=e['before_sha256']:raise ValueError('input mismatch')
  plain=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
  if hashlib.sha256(plain).hexdigest()!=e['after_sha256']:raise ValueError('output mismatch')
  count+=1;total+=n
  if n<5:continue
  vals=np.ndarray((n-3,),dtype='<u4',buffer=plain,strides=(1,));idx=np.arange(n-3,dtype=np.uint32);targets=vals+idx+np.uint32((rva+4)&0xffffffff)
  for jj in np.flatnonzero((targets>=a.start)&(targets<a.end)):
   j=int(jj);start=None
   if j>=1 and plain[j-1] in (0xe8,0xe9):start=j-1
   elif j>=2 and plain[j-2]==0x0f and 0x80<=plain[j-1]<=0x8f:start=j-2
   if start is None:continue
   ins=list(cs.disasm(plain[start:j+4],va+start))
   if len(ins)==1 and ins[0].size==j+4-start:
    hits.append({'event':i,'site':hex(va+start),'target':hex(base+int(targets[j])),'instruction':ins[0].mnemonic+' '+ins[0].op_str})
print(json.dumps({'text_events_verified':count,'bytes_replayed':total,'range':[hex(base+a.start),hex(base+a.end)],'hits':hits,'warning':'Candidates can be overlapping decodes or unreachable; synthetic model only.'}))
