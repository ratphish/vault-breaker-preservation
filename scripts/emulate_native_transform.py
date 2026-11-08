"""Execute one native transform in an isolated synthetic Unicorn machine."""
import argparse,hashlib,json,mmap,struct,time
from pathlib import Path
import pefile
from Crypto.Cipher import AES
from unicorn import Uc,UcError,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_INTR,UC_HOOK_MEM_INVALID,UC_HOOK_MEM_WRITE,UC_PROT_ALL
from unicorn.x86_const import UC_X86_REG_RIP,UC_X86_REG_RSP,UC_X86_REG_RCX,UC_X86_REG_RDX,UC_X86_REG_R8,UC_X86_REG_R9,UC_X86_REG_GS_BASE
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('capture',type=Path);p.add_argument('--count',type=int,default=5000000);p.add_argument('--timeout-ms',type=int,default=30000);a=p.parse_args()
if not 1<=a.count<=10000000 or not 1<=a.timeout_ms<=60000:raise ValueError('invalid limit')
with a.pe.open('rb') as f:identity=hashlib.file_digest(f,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected executable SHA-256')
c=json.loads(a.capture.read_text());key=bytes.fromhex(c['key']);counter=bytes.fromhex(c['counter']);data=bytes.fromhex(c['input']);n=c['length']
if len(key)!=16 or len(counter)!=16 or n!=len(data) or not 1<=n<=65536:raise ValueError('invalid capture')
pe=pefile.PE(str(a.pe),fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase;secs=[(s.VirtualAddress,max(s.Misc_VirtualSize,s.SizeOfRawData),s.PointerToRawData,s.SizeOfRawData) for s in pe.sections]
uc=Uc(UC_ARCH_X86,UC_MODE_64);stack=0x730000000000;buf=0x740000000000;uc.mem_map(stack,0x200000);uc.mem_map(buf,0x20000);uc.mem_write(buf+0x100,key);uc.mem_write(buf+0x200,counter);uc.mem_write(buf+0x1000,data);uc.reg_write(UC_X86_REG_RSP,stack+0x1feff8);uc.reg_write(UC_X86_REG_RCX,buf+0x100);uc.reg_write(UC_X86_REG_RDX,buf+0x200);uc.reg_write(UC_X86_REG_R8,buf+0x1000);uc.reg_write(UC_X86_REG_R9,n);uc.reg_write(UC_X86_REG_GS_BASE,0)
state={'instructions':0,'writes':0,'outside_buffer_writes':0,'stop':None};pages=set()
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 def invalid(uc,access,addr,size,value,user):
  rva=addr-base;sec=next((s for s in secs if s[0]<=rva<s[0]+s[1]),None)
  if sec is None:state['stop']={'kind':'unmapped','addr':hex(addr),'rip':hex(uc.reg_read(UC_X86_REG_RIP))};return False
  page=addr&~0xfff
  if page in pages:state['stop']={'kind':'mapped_failure','addr':hex(addr)};return False
  uc.mem_map(page,4096,UC_PROT_ALL);pages.add(page);v,_,raw,rawsize=sec;lo=max(page-base,v);hi=min(page-base+4096,v+rawsize)
  if hi>lo:uc.mem_write(base+lo,image[raw+lo-v:raw+hi-v])
  return True
 def code(uc,addr,size,user):
  state['instructions']+=1
  if addr==0x17004d627:state['stop']={'kind':'bounded_loop_exit','rip':hex(addr)};uc.emu_stop();return
  op=bytes(uc.mem_read(addr,min(size,4)))
  if op.startswith((b'\x0f\x05',b'\x0f\x34',b'\xcd',b'\xcc')):state['stop']={'kind':'host_interface_instruction','rip':hex(addr)};uc.emu_stop()
 def interrupt(uc,num,user):state['stop']={'kind':'interrupt','number':num};uc.emu_stop()
 def write(uc,access,addr,size,value,user):
  if buf+0x1000<=addr<buf+0x1000+n:state['writes']+=1
  elif not stack<=addr<stack+0x200000:state['outside_buffer_writes']+=1
 uc.hook_add(UC_HOOK_MEM_INVALID,invalid);uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_INTR,interrupt);uc.hook_add(UC_HOOK_MEM_WRITE,write)
 start=time.monotonic()
 try:uc.emu_start(0x17004d360,0,timeout=a.timeout_ms*1000,count=a.count)
 except UcError as e:
  if state['stop'] is None:state['stop']={'kind':'unicorn_error','message':str(e),'rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 if state['stop'] is None:state['stop']={'kind':'budget_or_return','rip':hex(uc.reg_read(UC_X86_REG_RIP))}
 result=bytes(uc.mem_read(buf+0x1000,n));ref=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(counter,'big')).encrypt(data);state.update(length=n,output_sha256=hashlib.sha256(result).hexdigest(),expected_sha256=c['expected_sha256'],matches_reference=result==ref,matches_recorded_hash=hashlib.sha256(result).hexdigest()==c['expected_sha256'],elapsed_seconds=round(time.monotonic()-start,3),note='synthetic function probe; no game process or host APIs')
 print(json.dumps(state,indent=2))
