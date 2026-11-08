"""Check three original data/table pointers against modeled direct call-site instructions."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86_const import X86_OP_MEM,X86_OP_IMM,X86_REG_RIP,X86_REG_RCX
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('text',type=Path);a=p.parse_args()
for path,want in [(a.pe,'d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'),(a.text,'e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca')]:
 with path.open('rb') as f:
  if hashlib.file_digest(f,'sha256').hexdigest()!=want:raise ValueError('wrong input')
pe=pefile.PE(str(a.pe),fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase;groups=[(0x1744f03b0,0x172d2d2f8,0x16f551330,[0x17043d5a6,0x17043d604]),(0x1744f04a0,0x172d2d318,0x17042dda0,[0x16f6e99e3]),(0x1744f04d0,0x172d2d338,0x170f12dc0,[0x16f6e9a86])];cs=Cs(CS_ARCH_X86,CS_MODE_64);cs.detail=True;out=[]
with a.pe.open('rb') as original,a.text.open('rb') as modeled:
 for global_va,table_va,method,calls in groups:
  original.seek(pe.get_offset_from_rva(global_va-base));ptr=struct.unpack('<Q',original.read(8))[0]
  original.seek(pe.get_offset_from_rva(table_va-base));table=list(struct.unpack('<4Q',original.read(32)))
  if ptr!=table_va or table[1]!=method:raise ValueError('original pointer mismatch')
  decoded=[]
  for va in calls:
   modeled.seek(va-(base+0x1000));ins=list(cs.disasm(modeled.read(12),va))
   if len(ins)!=2 or ins[0].mnemonic!='lea' or len(ins[0].operands)!=2 or ins[0].operands[0].reg!=X86_REG_RCX or ins[0].operands[1].type!=X86_OP_MEM or ins[0].operands[1].mem.base!=X86_REG_RIP or ins[0].address+ins[0].size+ins[0].operands[1].mem.disp!=global_va or ins[1].mnemonic!='call' or ins[1].operands[0].type!=X86_OP_IMM or ins[1].operands[0].imm!=method:raise ValueError(f'call-site mismatch {va:x}')
   decoded.append({'site':hex(va),'lea_target':hex(global_va),'direct_call':hex(method)})
  out.append({'global':hex(global_va),'table':hex(table_va),'original_table_entries':[hex(v) for v in table],'call_sites':decoded})
print(json.dumps({'groups':out,'warning':'Original pointers plus synthetic decoded call sites; labels, function boundaries, execution and relation to Vault Breaker remain unproven.'},indent=2))
