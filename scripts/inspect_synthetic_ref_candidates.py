"""Verify modeled events and disassemble candidate RIP-relative references."""
import argparse,hashlib,json,mmap
from pathlib import Path
from Crypto.Cipher import AES
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_MEM,X86_REG_RIP
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('candidates',type=Path);p.add_argument('--min-event',type=int,default=0);a=p.parse_args()
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
x=json.loads(a.trace.read_text());hits=[h for h in json.loads(a.candidates.read_text())['hits'] if h['event']>=a.min_event];groups={}
for h in hits:groups.setdefault(h['event'],[]).append(h)
cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;results=[]
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for i,hs in groups.items():
  e=x['fast_transform_events'][i];ctx=x['transform_entries'][i];va=int(e['data'],16);rva=va-0x140000000;n=e['length'];before=image[rva-0xa00:rva-0xa00+n]
  if hashlib.sha256(before).hexdigest()!=e['before_sha256']:raise ValueError('input mismatch')
  after=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
  if hashlib.sha256(after).hexdigest()!=e['after_sha256']:raise ValueError('output mismatch')
  for h in hs:
   k=h['offset_in_event'];target=int(h['target_va'],16);matches=[]
   for start in range(max(0,k-7),k):
    ins=list(cs.disasm(after[start:k+4],va+start))
    if len(ins)==1 and ins[0].address+ins[0].size==va+k+4 and any(o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP and ins[0].address+ins[0].size+o.mem.disp==target for o in ins[0].operands):matches.append({'address':hex(ins[0].address),'instruction':ins[0].mnemonic+' '+ins[0].op_str})
   results.append({'event':i,'target_va':h['target_va'],'disp_va':h['disp_va'],'decodes':matches})
print(json.dumps({'candidate_events_verified':len(groups),'candidates':results,'warning':'Overlapping decodes and synthetic model do not establish reachability.'}))
