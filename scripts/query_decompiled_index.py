"""Search local synthetic Ghidra indexes without claiming source equivalence."""
import argparse,json,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('indexes',nargs='+',type=Path);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--address');g.add_argument('--text');p.add_argument('--limit',type=int,default=10);a=p.parse_args()
if not 1<=a.limit<=100:raise ValueError('limit must be 1..100')
wanted=hex(int(a.address,0)) if a.address else None;needle=a.text.lower() if a.text else None;count=0
for path in a.indexes:
 with path.open(encoding='utf-8') as f:
  for line in f:
   x=json.loads(line)
   if (wanted is not None and x['address'].lower()!=wanted) or (needle is not None and needle not in x['pseudocode'].lower()):continue
   print(json.dumps(x));count+=1
   if count>=a.limit:break
 if count>=a.limit:break
print(f'found={count}; synthetic bounded pseudocode, not verified original source',file=sys.stderr)
