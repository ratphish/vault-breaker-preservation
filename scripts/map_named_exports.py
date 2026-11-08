"""Attach shipped export names to exact-address private decompiler records."""
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('exports',type=Path);p.add_argument('output',type=Path);p.add_argument('indexes',nargs='+',type=Path);a=p.parse_args();out=a.output.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('new private output required')
exports=[json.loads(l) for l in a.exports.read_text().splitlines() if l.startswith('{')];by={}
for e in exports:
 if not e.get('forwarded'):by.setdefault(hex(0x140000000+int(e['rva'],16)),[]).append(e)
seen=set();count=0
with out.open('x',encoding='utf8') as dst:
 for path in a.indexes:
  with path.open(encoding='utf8') as f:
   for line in f:
    row=json.loads(line)
    for e in by.get(row['address'],[]):
     key=(e['name'],row['address'])
     if key in seen:continue
     seen.add(key);dst.write(json.dumps({'export':e['name'],'address':row['address'],'index':path.name,'completed':row['completed'],'error':row['error'],'pseudocode':row['pseudocode']})+'\n');count+=1
print(json.dumps({'exports':len(exports),'matched_named_exports':count,'warning':'Only address/name identity is from the PE; synthetic pseudocode is unvalidated and may decode protected stubs.'}))
