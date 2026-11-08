"""Analyze paired fake-cache flush ranges in the second-worker synthetic text image."""
import argparse
import collections
import hashlib
import json
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_IMM,X86_OP_MEM,X86_REG_RIP

p=argparse.ArgumentParser()
p.add_argument('trace',type=Path)
p.add_argument('text',type=Path)
p.add_argument('registry',type=Path)
a=p.parse_args()
x=json.loads(a.trace.read_text(encoding='utf-8-sig'))
with a.text.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!=x.get('second_text_sha256'):raise ValueError('text digest differs from trace')
flush=[z for z in x.get('fake_worker_cache_calls',[]) if z['import'].lower().endswith('flushinstructioncache')]
if len(flush)%2:raise ValueError('unpaired cache flushes')
reg=json.loads(a.registry.read_text(encoding='utf-8-sig'))
tables=[(0x140000000+int(t['rva'],16)-32,0x140000000+int(t['rva'],16)+16*t['entries']+32) for t in reg['tables']]
cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;rows=[];refs=[];mnemonics=collections.Counter()
with a.text.open('rb') as f:
    for i in range(0,len(flush),2):
        body,head=flush[i:i+2];body_addr=int(body['address'],16);begin=int(head['address'],16);end=body_addr+body['length']
        if head['length']!=8 or begin+8!=body_addr or not 0x140001000<=begin<end<=0x172c83600:raise ValueError(f'unexpected flush pair {i//2}')
        f.seek(begin-0x140001000);blob=f.read(end-begin);ins=list(cs.disasm(blob,begin))
        used=sum(z.size for z in ins);calls=[]
        for op in ins:
            mnemonics[op.mnemonic]+=1
            for operand in op.operands:
                if operand.type==X86_OP_MEM and operand.mem.base==X86_REG_RIP:
                    target=op.address+op.size+operand.mem.disp
                    if any(lo<=target<hi for lo,hi in tables):refs.append({'site':hex(op.address),'target':hex(target),'instruction':op.mnemonic+' '+op.op_str})
                if op.mnemonic in ('call','jmp') and operand.type==X86_OP_IMM:calls.append(hex(operand.imm))
        rows.append({'start':hex(begin),'end_exclusive':hex(end),'bytes':len(blob),'decoded_bytes':used,
                     'instruction_count':len(ins),'direct_calls_or_jumps':calls[:30]})
print(json.dumps({'ranges':len(rows),'fully_decoded_ranges':sum(r['bytes']==r['decoded_bytes'] for r in rows),
                  'mnemonic_counts':dict(mnemonics),'registry_rip_candidates':refs,'patch_ranges':rows,
                  'warning':'Synthetic worker patches and linear bounded disassembly; valid boundaries, real execution and Vault linkage are unverified.'},indent=2))
