"""Verify one protected TLS continuation dispatcher with original PE bytes in Unicorn."""
import argparse,hashlib,json,mmap,struct
from pathlib import Path
import pefile
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_INVALID,UC_HOOK_MEM_WRITE,UC_PROT_ALL
from unicorn.x86_const import *
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('--target-offset',type=lambda s:int(s,0),default=0);p.add_argument('--inline',action='store_true');a=p.parse_args()
if a.target_offset not in (0,0x100):raise ValueError('use one of two synthetic targets')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
pe=pefile.PE(str(a.pe),fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase;secs=[(s.VirtualAddress,max(s.Misc_VirtualSize,s.SizeOfRawData),s.PointerToRawData,s.SizeOfRawData) for s in pe.sections];stack=0x700000000000;teb=0x710000000000;target=0x720000000000+a.target_offset;table=0x740000000000;block=0x750000000000;uc=Uc(UC_ARCH_X86,UC_MODE_64);uc.mem_map(stack,0x200000);uc.mem_map(teb,0x2000);uc.mem_map(0x720000000000,0x1000);uc.mem_write(target,b'\x90');uc.mem_map(table,0x10000);uc.mem_map(block,0x20000);uc.mem_write(table,struct.pack('<Q',block)*8192);uc.mem_write(teb+0x58,struct.pack('<Q',table));uc.mem_write(block+0x1210,struct.pack('<Q',target));uc.reg_write(UC_X86_REG_GS_BASE,teb)
regs=[('rax',UC_X86_REG_RAX),('rbx',UC_X86_REG_RBX),('rcx',UC_X86_REG_RCX),('rdx',UC_X86_REG_RDX),('rsi',UC_X86_REG_RSI),('rdi',UC_X86_REG_RDI),('rbp',UC_X86_REG_RBP),('r8',UC_X86_REG_R8),('r9',UC_X86_REG_R9),('r10',UC_X86_REG_R10),('r11',UC_X86_REG_R11),('r12',UC_X86_REG_R12),('r13',UC_X86_REG_R13),('r14',UC_X86_REG_R14),('r15',UC_X86_REG_R15)]
for i,(_,r) in enumerate(regs):uc.reg_write(r,0x1111000000000000+i*0x10101)
uc.reg_write(UC_X86_REG_RSP,stack+0x1ff000);uc.reg_write(UC_X86_REG_EFLAGS,0x246);before={name:uc.reg_read(r) for name,r in regs};before['rsp']=uc.reg_read(UC_X86_REG_RSP);before['eflags']=uc.reg_read(UC_X86_REG_EFLAGS);pages=set();state={'stop':None,'instructions':0,'trace':[],'nonstack_writes':0}
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 def invalid(uc,access,addr,size,value,user):
  rva=addr-base;sec=next((s for s in secs if s[0]<=rva<s[0]+s[1]),None);page=addr&~0xfff
  if sec is None or page in pages:state['stop']={'kind':'unmapped','address':hex(addr),'rip':hex(uc.reg_read(UC_X86_REG_RIP))};return False
  uc.mem_map(page,4096,UC_PROT_ALL);pages.add(page);v,_,raw,rawsize=sec;lo=max(page-base,v);hi=min(page-base+4096,v+rawsize)
  if hi>lo:uc.mem_write(base+lo,image[raw+lo-v:raw+hi-v])
  return True
 def code(uc,addr,size,user):
  state['instructions']+=1;state['trace'].append(hex(addr))
  if a.inline and addr==0x162478533:
   sp=uc.reg_read(UC_X86_REG_RSP)
   if not stack+88<=sp<=stack+0x200000-8:state['stop']={'kind':'unsafe_stack'};uc.emu_stop();return
   writes=[(sp-8,target),(sp-16,uc.reg_read(UC_X86_REG_RAX)),(sp-24,0x162478547),(sp-32,uc.reg_read(UC_X86_REG_EFLAGS)),(sp-40,uc.reg_read(UC_X86_REG_RCX)),(sp-48,uc.reg_read(UC_X86_REG_RDX)),(sp-88,0x171a1191c)]
   for address,value in writes:uc.mem_write(address,struct.pack('<Q',value))
   uc.reg_write(UC_X86_REG_RIP,target);return
  if addr==target:state['stop']={'kind':'target_reached'};uc.emu_stop();return
  try:op=bytes(uc.mem_read(addr,min(size,4)))
  except UcError:return
  if op.startswith((b'\x0f\x05',b'\x0f\x34',b'\xcd',b'\xcc')):state['stop']={'kind':'host_or_breakpoint','address':hex(addr)};uc.emu_stop()
 def intr(uc,num,user):state['stop']={'kind':'interrupt','number':num};uc.emu_stop()
 def write(uc,access,addr,size,value,user):
  if not stack<=addr<stack+0x200000:state['nonstack_writes']+=1
 uc.hook_add(UC_HOOK_MEM_INVALID,invalid);uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_INTR,intr);uc.hook_add(UC_HOOK_MEM_WRITE,write)
 try:uc.emu_start(0x162478533,0,count=1000,timeout=1000000)
 except UcError as ex:
  if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(ex)}
 if state['stop'] is None:state['stop']={'kind':'budget'}
 after={name:uc.reg_read(r) for name,r in regs};after['rsp']=uc.reg_read(UC_X86_REG_RSP);after['eflags']=uc.reg_read(UC_X86_REG_EFLAGS);state['stack_sha256']=hashlib.sha256(bytes(uc.mem_read(stack,0x200000))).hexdigest();state['tls_sha256']=hashlib.sha256(bytes(uc.mem_read(block,0x20000))).hexdigest();state['inline']=a.inline;state.update(target=hex(target),preserved={k:before[k]==after[k] for k in before},warning='Synthetic TLS and register state; proves only the tested local dispatcher path, not Windows execution or Vault Breaker behavior.')
 print(json.dumps(state))
