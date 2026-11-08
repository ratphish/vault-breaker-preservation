"""Check bounded AVX model against explicit 32-byte memory and register outcomes."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from synthetic_avx import try_avx
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_INSN_INVALID,UC_HOOK_CODE
from unicorn.x86_const import *
u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(0x100000,0x2000)
# vmovups ymm0,[rax]; vmovups [rbx],ymm0; vpxor xmm0,xmm0,xmm0
u.mem_write(0x100000,bytes.fromhex('c5fc1000c5fc1103c5f9efc0'))
payload=bytes(range(32));u.mem_write(0x100200,payload);u.reg_write(UC_X86_REG_RAX,0x100200);u.reg_write(UC_X86_REG_RBX,0x100300);u.reg_write(UC_X86_REG_EFLAGS,0x246)
allowed=lambda ptr,n,write: (not write and 0x100000<=ptr and ptr+n<=0x100100) or (0x100200<=ptr and ptr+n<=0x100400)
assert try_avx(u,0x100000,4,allowed)['direction']=='load'
assert u.reg_read(UC_X86_REG_YMM0)==int.from_bytes(payload,'little')
assert try_avx(u,0x100004,4,allowed)['direction']=='store'
assert bytes(u.mem_read(0x100300,32))==payload
assert try_avx(u,0x100008,4,allowed)['zeroed']=='ymm0'
assert u.reg_read(UC_X86_REG_YMM0)==0 and u.reg_read(UC_X86_REG_EFLAGS)==0x246
u.reg_write(UC_X86_REG_RBX,0x100500)
assert try_avx(u,0x100004,4,allowed) is None
v=Uc(UC_ARCH_X86,UC_MODE_64);v.mem_map(0x200000,0x2000);v.mem_write(0x200000,bytes.fromhex('c5fc1000c5fc1103cc'));v.mem_write(0x200200,payload);v.reg_write(UC_X86_REG_RAX,0x200200);v.reg_write(UC_X86_REG_RBX,0x200300);events=[]
def on_invalid(uc,user):
 event=try_avx(uc,uc.reg_read(UC_X86_REG_RIP),15,lambda ptr,n,write:(not write and 0x200000<=ptr and ptr+n<=0x200100) or (0x200200<=ptr and ptr+n<=0x200400))
 if event:events.append(event)
 return bool(event)
def stop(uc,addr,size,user):
 if addr==0x200008:uc.emu_stop()
v.hook_add(UC_HOOK_INSN_INVALID,on_invalid);v.hook_add(UC_HOOK_CODE,stop);v.emu_start(0x200000,0,count=20)
assert [x['direction'] for x in events]==['load','store'] and bytes(v.mem_read(0x200300,32))==payload
v.mem_write(0x200ffd,bytes.fromhex('c5fc1103'));v.reg_write(UC_X86_REG_YMM0,int.from_bytes(payload,'little'));v.reg_write(UC_X86_REG_RBX,0x200300)
assert try_avx(v,0x200ffd,4,lambda ptr,n,write:0x200000<=ptr and ptr+n<=0x202000)['direction']=='store'
u.mem_write(0x100010,bytes.fromhex('c5fc2800'));u.reg_write(UC_X86_REG_RAX,0x100200)
assert try_avx(u,0x100010,4,allowed)['instruction']=='vmovaps'
u.reg_write(UC_X86_REG_RAX,0x100201)
assert try_avx(u,0x100010,4,allowed) is None
u.mem_write(0x100020,bytes.fromhex('c4e27d1a00'));u.reg_write(UC_X86_REG_RAX,0x100200)
assert try_avx(u,0x100020,5,allowed)['instruction']=='vbroadcastf128'
assert u.reg_read(UC_X86_REG_YMM0)==int.from_bytes(payload[:16]*2,'little')
u.mem_write(0x100030,bytes.fromhex('c4e27918c0'));u.reg_write(UC_X86_REG_YMM0,(1<<255)|0x3f800000)
assert try_avx(u,0x100030,5,allowed)['instruction']=='vbroadcastss'
assert u.reg_read(UC_X86_REG_YMM0)==sum(0x3f800000<<(32*i) for i in range(4))
u.mem_write(0x100040,bytes.fromhex('c4e37904cb55'));u.reg_write(UC_X86_REG_YMM3,sum((i+1)<<(32*i) for i in range(4)));u.reg_write(UC_X86_REG_YMM1,1<<255)
assert try_avx(u,0x100040,6,allowed)['instruction']=='vpermilps'
assert u.reg_read(UC_X86_REG_YMM1)==sum(2<<(32*i) for i in range(4))
u.mem_write(0x100050,bytes.fromhex('c4e37518c901'));u.reg_write(UC_X86_REG_YMM1,(0x2222<<128)|0x1111)
assert try_avx(u,0x100050,6,allowed)['instruction']=='vinsertf128'
assert u.reg_read(UC_X86_REG_YMM1)==(0x1111<<128)|0x1111
u.mem_write(0x100060,bytes.fromhex('c4e27959c0'));u.reg_write(UC_X86_REG_YMM0,(1<<255)|0x123456789abcdef0)
assert try_avx(u,0x100060,5,allowed)['instruction']=='vpbroadcastq'
assert u.reg_read(UC_X86_REG_YMM0)==0x123456789abcdef0123456789abcdef0 and u.reg_read(UC_X86_REG_EFLAGS)==0x246
u.mem_write(0x100070,bytes.fromhex('c4e3694ac410'));u.reg_write(UC_X86_REG_YMM2,sum((i+1)<<(32*i) for i in range(4)));u.reg_write(UC_X86_REG_YMM4,sum((i+11)<<(32*i) for i in range(4)));u.reg_write(UC_X86_REG_YMM1,0x80000000|(0x80000000<<64));u.reg_write(UC_X86_REG_YMM0,1<<255)
assert try_avx(u,0x100070,6,allowed)['instruction']=='vblendvps'
assert u.reg_read(UC_X86_REG_YMM0)==sum(x<<(32*i) for i,x in enumerate((11,2,13,4))) and u.reg_read(UC_X86_REG_EFLAGS)==0x246
u.mem_write(0x100080,bytes.fromhex('c5fd76c0'));u.reg_write(UC_X86_REG_YMM0,0x123456)
assert try_avx(u,0x100080,4,allowed)['instruction']=='vpcmpeqd'
assert u.reg_read(UC_X86_REG_YMM0)==(1<<256)-1 and u.reg_read(UC_X86_REG_EFLAGS)==0x246
print('PASS: 256-bit load/store, comparison, VEX zero-extension, flags, memory guard, and Unicorn invalid-instruction integration')
