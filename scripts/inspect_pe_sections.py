"""Summarize PE section layout and entropy of a bounded prefix of each section."""
import argparse, math, struct, json, collections
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);a=p.parse_args()
with a.pe.open('rb') as f:
 def readat(pos,n):
  f.seek(pos);b=f.read(n)
  if len(b)!=n: raise ValueError('truncated PE')
  return b
 if readat(0,2)!=b'MZ':raise ValueError('missing MZ')
 pe=struct.unpack('<I',readat(0x3c,4))[0]
 if readat(pe,4)!=b'PE\0\0':raise ValueError('missing PE signature')
 coff=readat(pe+4,20);_,nsec,_,_,_,optsize,_=struct.unpack('<HHIIIHH',coff)
 for i in range(nsec):
  h=readat(pe+24+optsize+i*40,40);name=h[:8].rstrip(b'\0').decode('ascii','replace');vs,va,rs,raw=struct.unpack_from('<IIII',h,8);flags=struct.unpack_from('<I',h,36)[0];size=min(rs,1048576);sample=readat(raw,size) if size else b''
  counts=collections.Counter(sample); entropy=-sum((n/size)*math.log2(n/size) for n in counts.values()) if size else None
  print(json.dumps({'name':name,'virtual_address':f'0x{va:x}','virtual_size':vs,'file_offset':f'0x{raw:x}','raw_size':rs,'flags':f'0x{flags:08x}','sample_bytes':size,'sample_entropy_bits_per_byte':round(entropy,4) if entropy is not None else None}))
