"""Read file-backed standard PE imports; delay and dynamic imports are excluded."""
import argparse,struct,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);a=p.parse_args()
with a.pe.open('rb') as f:
 def at(off,n):
  f.seek(off);b=f.read(n)
  if len(b)!=n:raise ValueError('truncated input')
  return b
 def u32(off):return struct.unpack('<I',at(off,4))[0]
 if at(0,2)!=b'MZ':raise ValueError('missing MZ')
 pe=u32(0x3c)
 if at(pe,4)!=b'PE\0\0':raise ValueError('missing PE')
 machine,nsec,_,_,_,osize,_=struct.unpack('<HHIIIHH',at(pe+4,20));opt=pe+24;magic=struct.unpack('<H',at(opt,2))[0];plus=magic==0x20b;base=112 if plus else 96 if magic==0x10b else None
 if base is None:raise ValueError('bad optional header')
 rva,size=struct.unpack('<II',at(opt+base+8,8));secs=[]
 for i in range(nsec):
  h=at(opt+osize+i*40,40);vs,va,rs,raw=struct.unpack_from('<IIII',h,8);secs.append((va,rs,raw))
 def locate(addr,n=1):
  m=[raw+addr-va for va,rs,raw in secs if va<=addr and addr+n<=va+rs]
  if len(m)!=1:raise ValueError(f'RVA {addr:x} has {len(m)} file mappings')
  return m[0]
 def cstr(addr):
  off=locate(addr);f.seek(off);b=f.read(512)
  if b'\0' not in b:raise ValueError('unterminated string')
  return b.split(b'\0',1)[0].decode('ascii','replace')
 if not rva: print(json.dumps({'imports':[]}));raise SystemExit
 if size<20 or size>1024*1024:raise ValueError('implausible import directory')
 out=[];terminated=False
 for j in range(size//20):
  ilt,ts,chain,name,iat=struct.unpack('<IIIII',at(locate(rva+j*20,20),20))
  if (ilt,ts,chain,name,iat)==(0,0,0,0,0):terminated=True;break
  dll=cstr(name);table=ilt or iat;width=8 if plus else 4;fmt='<Q' if plus else '<I'; funcs=[]
  for k in range(65536):
   value=struct.unpack(fmt,at(locate(table+k*width,width),width))[0]
   if value==0:break
   if value>>(width*8-1):funcs.append({'ordinal':value&0xffff})
   else:funcs.append({'name':cstr((value & ((1 << (width*8-1))-1))+2)})
  else:raise ValueError('unterminated thunk table')
  out.append({'dll':dll,'functions':funcs})
 if not terminated:raise ValueError('unterminated descriptor table')
 print(json.dumps({'imports':out},indent=2))
