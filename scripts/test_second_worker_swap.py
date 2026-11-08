"""Test one bounded patched instruction sequence in an isolated Unicorn instance."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.x86_const import UC_X86_REG_RAX,UC_X86_REG_R10,UC_X86_REG_R11,UC_X86_REG_RIP

p=argparse.ArgumentParser()
p.add_argument('text',type=Path)
a=p.parse_args()
with a.text.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='1c8f2a6e3cc77ad5b373afb368959968c78e571706974db051a32fabd0af459e':raise ValueError('unexpected modeled text')
    f.seek(0x16f9fca8e-0x140001000);code=f.read(64)
mask=0xf043acb4;results=[]
for left,right in [(0x10,0x34),(0x20,0x20)]:
    u=Uc(UC_ARCH_X86,UC_MODE_64);page=0x16f9fc000;table=0x770000000000;data=0x780000000000
    for addr in (page,table,data):u.mem_map(addr,0x1000)
    u.mem_write(0x16f9fca8e,code);u.mem_write(table,struct.pack('<II',left^mask,right^mask))
    u.mem_write(data+left,struct.pack('<I',0x12345678));u.mem_write(data+right,struct.pack('<I',0x9abcdef0))
    before_left=struct.unpack('<I',u.mem_read(data+left,4))[0];before_right=struct.unpack('<I',u.mem_read(data+right,4))[0]
    u.reg_write(UC_X86_REG_RAX,table);u.reg_write(UC_X86_REG_R10,0);u.reg_write(UC_X86_REG_R11,data)
    writes=[]
    def write(uc,access,addr,size,value,user):writes.append((addr,size,value))
    def code_hook(uc,addr,size,user):
        if addr==0x16f9fcab9:uc.emu_stop()
    u.hook_add(UC_HOOK_MEM_WRITE,write);u.hook_add(UC_HOOK_CODE,code_hook)
    u.emu_start(0x16f9fca8e,0,count=100)
    after_left=struct.unpack('<I',u.mem_read(data+left,4))[0];after_right=struct.unpack('<I',u.mem_read(data+right,4))[0]
    if u.reg_read(UC_X86_REG_RIP)!=0x16f9fcab9 or u.reg_read(UC_X86_REG_R10)!=1 or u.reg_read(UC_X86_REG_RAX)!=table+8:raise ValueError('unexpected register state')
    if (after_left,after_right)!=(before_right,before_left) or len(writes)!=2:raise ValueError('unexpected swap')
    results.append({'left_offset':hex(left),'right_offset':hex(right),'same_address':left==right,'writes':len(writes),'swap_matches':True})
print(json.dumps({'sequence_start':'0x16f9fca8e','bounded_stop':'0x16f9fcab9','cases':results,
                  'warning':'Tests one sequence from a synthetic patched image; real runtime reachability and full function behavior remain unverified.'},indent=2))
