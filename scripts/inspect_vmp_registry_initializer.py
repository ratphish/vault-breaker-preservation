"""Verify one original-byte class-table initializer and its bounded synthetic probe."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_MEM,X86_REG_RIP

p=argparse.ArgumentParser()
p.add_argument('pe',type=Path)
p.add_argument('text',type=Path)
p.add_argument('rdata',type=Path)
p.add_argument('registry',type=Path)
p.add_argument('probe',type=Path)
a=p.parse_args()
with a.pe.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong executable')
pe=pefile.PE(str(a.pe),fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase;site=0x14dadd9a9
original=pe.get_data(site-base,46)
with a.text.open('rb') as f:f.seek(site-(base+0x1000));modeled=f.read(46)
if original!=modeled:raise ValueError('initializer differs from original bytes')
cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;ins=list(cs.disasm(original,site))
if len(ins)<7 or [x.mnemonic for x in ins[:7]]!=['lea','mov','mov','mov','lea','add','jmp']:raise ValueError('unexpected initializer instructions')
def rip_target(i):
    operands=[o for o in i.operands if o.type==X86_OP_MEM and o.mem.base==X86_REG_RIP]
    if len(operands)!=1:raise ValueError('missing RIP-relative operand')
    return i.address+i.size+operands[0].mem.disp
table_pointer=rip_target(ins[0]);count_global=rip_target(ins[1]);pointer_global=rip_target(ins[3]);descriptor_global=rip_target(ins[4])
if (table_pointer,count_global,pointer_global,descriptor_global)!=(0x172ed1350,0x178e76580,0x178e76578,0x178e76578):raise ValueError('unexpected initializer targets')
if ins[1].operands[1].imm!=1886 or ins[2].operands[1].imm!=1 or ins[6].operands[0].imm!=0x16f8d4c40:raise ValueError('unexpected initializer operands')
r=a.rdata.read_bytes();start=table_pointer-0x172c84000-8;count=1886
if start<0 or start+16*count>len(r):raise ValueError('table out of bounds')
rows=[struct.unpack_from('<QQ',r,start+16*i) for i in range(count)]
if any(not (rows[i][0]<rows[i+1][0] and rows[i][0]<=0xffffffff) for i in range(count-1)):raise ValueError('hash order mismatch')
if any(not 0x173534000<=ptr<0x1792a6be1 for _,ptr in rows):raise ValueError('table pointer outside modeled data')
reg=json.loads(a.registry.read_text(encoding='utf-8-sig'));matched=[]
for row in reg['rows']:
    for candidate in row['registry_candidates']:
        off=int(candidate['rdata_offset'],16)
        if start<=off<start+16*count:matched.append({'parent_type':row['parent_type'],'class_hash':row['class_hash'],'vmp_offset':row['vmp_offset']})
probe=json.loads(a.probe.read_text(encoding='utf-8-sig'))
if probe['stop']!={'kind':'target_reached','address':'0x16f8d4c40'}:raise ValueError('callee not reached in probe')
expected={(hex(count_global),'0x75e'),(hex(pointer_global),hex(table_pointer))}
observed={(z['address'],z['value']) for z in probe.get('image_write_samples',[])}
if not expected<=observed:raise ValueError('probe writes differ')
print(json.dumps({'initializer':hex(site),'original_bytes_match':True,'table_start':hex(table_pointer-8),
                  'pointer_stored':hex(table_pointer),'entry_count':count,'pointer_global':hex(pointer_global),
                  'count_global':hex(count_global),'callee':hex(0x16f8d4c40),
                  'matched_embedded_records':len(matched),'slot_related_parent_records':sum(z['parent_type']=='8080b8e2' for z in matched),
                  'records':matched,'warning':'Original instructions and synthetic data agree; real execution and any Vault-specific binding remain unverified.'},indent=2))
