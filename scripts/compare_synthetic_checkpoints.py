"""Compare independent synthetic checkpoint memory and architectural registers."""
import argparse,ctypes,hashlib,json
from pathlib import Path
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64
from unicorn import x86_const as x
p=argparse.ArgumentParser();p.add_argument('left',type=Path);p.add_argument('right',type=Path);a=p.parse_args()
def read(root):
 m=json.loads((root/'manifest.json').read_text(encoding='utf-8'));raw=(root/'context.bin').read_bytes()
 if hashlib.sha256(raw).hexdigest()!=m['context_sha256']:raise ValueError('context digest mismatch')
 u=Uc(UC_ARCH_X86,UC_MODE_64);ctx=u.context_save()
 if ctx.size!=len(raw):raise ValueError('incompatible context')
 ctypes.memmove(ctx.context,raw,len(raw));u.context_restore(ctx)
 names=['RAX','RBX','RCX','RDX','RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15','RIP','EFLAGS','GS_BASE','FS_BASE','MXCSR']+['YMM'+str(i) for i in range(16)]
 regs={name:hex(u.reg_read(getattr(x,'UC_X86_REG_'+name))) for name in names}
 regions={}
 for region in m['regions']:
  with (root/region['file']).open('rb') as f:
   digest=hashlib.file_digest(f,'sha256').hexdigest()
  if digest!=region['sha256'] or (root/region['file']).stat().st_size!=region['size']:raise ValueError('checkpoint region mismatch')
  regions[(region['start'],region['size'],region['permissions'])]=digest
 return m,regs,regions
l,lr,lm=read(a.left);r,rr,rm=read(a.right)
if l['identity']!=r['identity']:raise ValueError('different model identity')
regdiff={k:[lr[k],rr[k]] for k in lr if lr[k]!=rr[k]};keys=set(lm)|set(rm);memdiff=[{'region':str(k),'left':lm.get(k),'right':rm.get(k)} for k in sorted(keys) if lm.get(k)!=rm.get(k)]
leftstop=l['state']['stop'];rightstop=r['state']['stop'];print(json.dumps({'left_stop':leftstop,'right_stop':rightstop,'register_differences':regdiff,'region_hash_differences':memdiff,'match':not regdiff and not memdiff and leftstop==rightstop,'limits':'Compares saved region hashes and selected architectural registers in synthetic state; does not prove Windows equivalence.'},indent=2))
