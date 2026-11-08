"""Sample entropy across a file span; does not classify packing or encryption."""
import argparse,collections,json,math
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('--offset',type=lambda x:int(x,0),required=True);p.add_argument('--length',type=lambda x:int(x,0),required=True);p.add_argument('--stride',type=int,default=16*1024*1024);p.add_argument('--sample',type=int,default=65536);a=p.parse_args()
with a.file.open('rb') as f:
 for x in range(0,a.length,a.stride):
  f.seek(a.offset+x);b=f.read(min(a.sample,a.length-x))
  if not b:raise ValueError('file shorter than requested')
  ent=-sum((n/len(b))*math.log2(n/len(b)) for n in collections.Counter(b).values())
  print(json.dumps({'offset':f'0x{a.offset+x:x}','bytes':len(b),'entropy':round(ent,4)}))
