"""Index private Ghidra window logs into private JSONL for local code searches."""
import argparse,json,re
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('batch_root',type=Path);p.add_argument('output',type=Path);a=p.parse_args();out=a.output.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('output must be a new private file')
pat=re.compile(r'BATCH_RESULT start=(\S+) completed=(\w+) error=([^\r\n]*)\s*\(GhidraScript\)\s*\nINFO\s+BatchBoundedFunctions\.java>\s*\n(.*?)\n\s*\(GhidraScript\)',re.S)
files=count=0
with out.open('x',encoding='utf-8') as dst:
 for path in sorted(a.batch_root.glob('*/stdout.txt')):
  raw=path.read_bytes();s=raw.decode('utf-16' if raw.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8')
  if 'Import succeeded' not in s:raise ValueError(f'incomplete log: {path}')
  files+=1
  for m in pat.finditer(s):
   dst.write(json.dumps({'window':path.parent.name,'address':'0x'+m.group(1),'completed':m.group(2)=='true','error':m.group(3).strip(),'pseudocode':m.group(4)})+'\n');count+=1
print(json.dumps({'logs':files,'records':count,'warning':'Synthetic model and bounded Ghidra pseudocode; not verified source or behavior.'}))
