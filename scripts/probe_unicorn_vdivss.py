"""Compare Unicorn's VEX vdivss against SSE divss for fixed IEEE float inputs."""
import json,struct
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import UC_X86_REG_XMM0,UC_X86_REG_XMM1,UC_X86_REG_XMM6
rows=[]
for initial in (0,0x44f00000):
 u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(0x1000,0x1000);u.mem_write(0x1000,bytes.fromhex('c5f25ef0'));u.reg_write(UC_X86_REG_XMM0,0x44870000);u.reg_write(UC_X86_REG_XMM1,0x44f00000);u.reg_write(UC_X86_REG_XMM6,initial);u.emu_start(0x1000,0x1004);rows.append({'instruction':'vdivss xmm6,xmm1,xmm0','initial_destination':hex(initial),'result':hex(u.reg_read(UC_X86_REG_XMM6)&0xffffffff)})
u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(0x1000,0x1000);u.mem_write(0x1000,bytes.fromhex('f30f5ef0'));u.reg_write(UC_X86_REG_XMM0,0x44870000);u.reg_write(UC_X86_REG_XMM6,0x44f00000);u.emu_start(0x1000,0x1004);reference=u.reg_read(UC_X86_REG_XMM6)&0xffffffff
assert reference==0x3fe38e39 and rows[0]['result']=='0x0' and rows[1]['result']==hex(reference)
print(json.dumps({'rows':rows,'sse_reference_bits':hex(reference),'scope':'this Unicorn build, fixed input only; does not validate all AVX instructions'},indent=2))
