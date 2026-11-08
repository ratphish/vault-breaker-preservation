"""Search exact text in a private synthetic image; bounded offsets, no content dump."""
import argparse,json,hashlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('terms',nargs='+');p.add_argument('--limit',type=int,default=30);a=p.parse_args();b=a.file.read_bytes();print(json.dumps({'kind':'identity','sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b)}))
for term in a.terms:
 for enc in ('ascii','utf-16le'):
  needle=term.encode(enc);hay=b.lower();needle=needle.lower();pos=0;hits=[]
  while True:
   i=hay.find(needle,pos)
   if i<0:break
   if len(hits)>=a.limit:break
   hits.append(i);pos=i+1
  print(json.dumps({'term':term,'encoding':enc,'offsets':hits,'truncated':len(hits)>=a.limit}))
