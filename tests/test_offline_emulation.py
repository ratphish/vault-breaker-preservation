"""Regression-check the bounded, synthetic model against this user's pinned build."""
import json,os,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1];exe=Path(r'D:\Marathon-preservation\build-26136895-20261031\Marathon.exe');env=os.environ.copy();env['PYTHONPATH']=r'D:\Marathon-preservation\tools\python'
def run(count,stub):
 args=[sys.executable,str(root/'scripts/emulate_pe_entry.py'),str(exe),'--count',str(count),'--timeout-ms','30000','--intercept-imports','--follow-thread']
 if stub:args.append('--stub-virtualprotect')
 return json.loads(subprocess.check_output(args,env=env,text=True))
c=run(100000,False);assert c['stop']['import']=='KERNEL32.dll!VirtualProtect' and c['rdata_writes']==0
x=run(1000000,True);y=run(1000000,True)
keys=['instructions','stop','rdata_writes','rdata_changed_writes','rdata_compare_failures','rdata_xor_checked','rdata_xor_matched','rdata_site_counts','rdata_page_counts','initial_stop','stubbed_virtualprotect','first_pcs','last_pcs']
assert all(x[k]==y[k] for k in keys)
assert x['initial_stop']['stop']['import']=='KERNEL32.dll!CreateThread'
assert x['stubbed_virtualprotect'][0]['registers']['rcx']=='0x172c84000'
assert x['rdata_writes']==2424 and x['rdata_changed_writes']==2409 and x['rdata_compare_failures']==0 and x['rdata_xor_checked']==2424 and x['rdata_xor_matched']==2424 and x['rdata_site_counts']=={'0x17004d61e':2424}
print('PASS: control stops before writes; two bounded synthetic runs reproduce the import sequence and write observations')
