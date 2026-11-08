"""Bounded static x64 instruction graph; direct branches only, no execution."""
import argparse,json
from collections import deque
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64,CS_GRP_JUMP,CS_GRP_CALL,CS_GRP_RET
from capstone.x86_const import X86_OP_IMM
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('va',type=lambda x:int(x,0));p.add_argument('--limit',type=int,default=100);a=p.parse_args()
if not 1<=a.limit<=100000:raise ValueError('limit must be 1..100000')
md=Cs(CS_ARCH_X86,CS_MODE_64);md.detail=True;q=deque([a.va]);seen=set();base=0x140000000;va_start=0x1000;raw_start=0x600;raw_size=851977728
with a.pe.open('rb') as f:
 while q and len(seen)<a.limit:
  va=q.popleft()
  if va in seen:continue
  seen.add(va);rva=va-base
  if not va_start<=rva<va_start+raw_size:
   print(json.dumps({'va':hex(va),'status':'outside_text'}));continue
  f.seek(raw_start+rva-va_start);data=f.read(15);i=next(md.disasm(data,va,count=1),None)
  if i is None:print(json.dumps({'va':hex(va),'status':'undecodable'}));continue
  fall=va+i.size;isjump=i.group(CS_GRP_JUMP);iscall=i.group(CS_GRP_CALL);isret=i.group(CS_GRP_RET);direct=bool(i.operands and i.operands[0].type==X86_OP_IMM);target=i.operands[0].imm if direct and (isjump or iscall) else None
  edges=[]
  if target is not None:edges.append(('call' if iscall else 'branch',target))
  if not isret and (not isjump or i.mnemonic!='jmp'):edges.append(('fallthrough',fall))
  print(json.dumps({'va':hex(va),'size':i.size,'bytes':bytes(i.bytes).hex(),'mnemonic':i.mnemonic,'operands':i.op_str,'edges':[{'kind':k,'va':hex(v)} for k,v in edges]}))
  for _,dest in edges:
   if dest not in seen:q.append(dest)
 print(json.dumps({'kind':'summary','visited':len(seen),'remaining_queue':len(q),'limit':a.limit,'warning':'Static possibilities only; fallthrough after a call is not evidence it returns.'}))
