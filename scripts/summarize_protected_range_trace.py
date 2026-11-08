"""Build a private, bounded instruction-level synthetic trace with verified original bytes."""
import argparse,hashlib,json,mmap
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('out',type=Path);a=p.parse_args();out=a.out.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('new private output required')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
x=json.loads(a.trace.read_text());ev=x['range_events'];dispatch=x['dispatch_events']
if any(z.get('matched') is not True for z in dispatch):raise ValueError('unverified dispatch')
c=Cs(CS_ARCH_X86,CS_MODE_64);j=0;matches=0;ops={}
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image,out.open('x',encoding='utf-8') as dst:
 for i,e in enumerate(ev):
  va=int(e['pc'],16);raw=bytes.fromhex(e['bytes']);off=va-0x140000000-0xa00
  if image[off:off+len(raw)]!=raw:raise ValueError(f'instruction differs from original at {va:x}')
  ins=list(c.disasm(raw,va))
  if len(ins)!=1 or ins[0].size!=len(raw):raise ValueError('invalid recorded instruction')
  nxt=ev[i+1] if i+1<len(ev) else None;between=[]
  while j<len(dispatch) and dispatch[j]['instruction']<=e['instruction']:j+=1
  while j<len(dispatch) and nxt and dispatch[j]['instruction']<nxt['instruction']:
   between.append({'source':dispatch[j]['source'],'continuation':dispatch[j]['continuation']});j+=1
  delta={k:[e['regs'][k],nxt['regs'][k]] for k in e['regs'] if nxt and e['regs'][k]!=nxt['regs'][k]}
  row={'ordinal':i,'instruction':e['instruction'],'pc':e['pc'],'operation':ins[0].mnemonic+' '+ins[0].op_str,'next_recorded_pc':nxt['pc'] if nxt else None,'register_changes_before_next_recorded_pc':delta,'intervening_dispatches':between}
  dst.write(json.dumps(row)+'\n');matches+=len(between);ops[ins[0].mnemonic]=ops.get(ins[0].mnemonic,0)+1
print(json.dumps({'range_instructions_verified_against_original':len(ev),'intervening_dispatches_mapped':matches,'mnemonic_counts':ops,'warning':'Observed under fake loader, synthetic TLS and fixed timestamp; register deltas include all unrecorded protected instructions and are not individual instruction semantics.'}))
