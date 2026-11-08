"""Find exact 32-bit little-endian candidates in a file; matches may be incidental."""
import argparse,json,mmap,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('ids',nargs='+');p.add_argument('--max-hits',type=int,default=100);a=p.parse_args()
with a.file.open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
 for value in a.ids:
  n=int(value,16);pat=struct.pack('<I',n);start=0;hits=[];truncated=False
  while True:
   off=mm.find(pat,start)
   if off<0:break
   if len(hits)>=a.max_hits:truncated=True;break
   hits.append(off);start=off+1
  print(json.dumps({'id':f'{n:08X}','little_endian':pat.hex(),'hits':hits,'truncated':truncated}))
