"""Round-trip sparse memory, machine context and metadata through private snapshots."""
import sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from synthetic_checkpoint import save,restore
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn.x86_const import *
with tempfile.TemporaryDirectory(dir=r'D:\Marathon-preservation\analysis',prefix='checkpoint-test-') as temp:
 root=Path(temp)/'snapshot';u=Uc(UC_ARCH_X86,UC_MODE_64);u.mem_map(0x100000,0x2000);u.mem_map(0x200000,0x1000);u.mem_write(0x100fff,b'cross page');u.mem_write(0x200100,b'second region');u.reg_write(UC_X86_REG_RAX,0x12345678);u.reg_write(UC_X86_REG_GS_BASE,0x100000);u.reg_write(UC_X86_REG_YMM0,(1<<200)+123)
 report=save(u,root,{'phase':'test'},['a','b'],'test-identity');v=Uc(UC_ARCH_X86,UC_MODE_64);v.mem_map(0x100000,0x1000);state,recent=restore(v,root,'test-identity')
 assert bytes(v.mem_read(0x100fff,10))==b'cross page' and bytes(v.mem_read(0x200100,13))==b'second region'
 assert v.reg_read(UC_X86_REG_RAX)==0x12345678 and v.reg_read(UC_X86_REG_GS_BASE)==0x100000 and v.reg_read(UC_X86_REG_YMM0)==(1<<200)+123
 assert state=={'phase':'test'} and recent==['a','b'] and report['bytes']==0x3000
 try:restore(v,root,'wrong-identity');raise AssertionError('identity was not checked')
 except ValueError:pass
print('PASS: sparse-memory, CPU context, metadata and identity round trip')
