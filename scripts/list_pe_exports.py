"""List matching PE export names without loading the image or executing it."""
import argparse, struct, json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('--needle',action='append',required=True);a=p.parse_args()
with a.pe.open('rb') as f:
 def readat(off,n):
  f.seek(off);b=f.read(n)
  if len(b)!=n:raise ValueError('truncated file')
  return b
 def u32(off):return struct.unpack('<I',readat(off,4))[0]
 if readat(0,2)!=b'MZ':raise ValueError('not PE')
 pe=u32(0x3c)
 if readat(pe,4)!=b'PE\0\0':raise ValueError('bad signature')
 coff=readat(pe+4,20);machine,nsec,_,_,_,osize,_=struct.unpack('<HHIIIHH',coff);opt=pe+24;magic=struct.unpack('<H',readat(opt,2))[0];d=opt+(112 if magic==0x20b else 96 if magic==0x10b else -1000000)
 export_rva,export_size=struct.unpack('<II',readat(d,8));sections=[]
 for i in range(nsec):
  h=readat(opt+osize+i*40,40);name=h[:8].rstrip(b'\0').decode('ascii','replace');vsize,va,rsize,raw=struct.unpack_from('<IIII',h,8);sections.append((va,vsize,rsize,raw,name))
 def mapped(rva):
  m=[(raw+rva-va,rsize-(rva-va)) for va,vs,rsize,raw,name in sections if va<=rva<va+rsize]
  if len(m)!=1:raise ValueError(f'RVA {rva:x} has {len(m)} file mappings')
  return m[0]
 def rva_bytes(rva,n):
  off,available=mapped(rva)
  if n>available:raise ValueError('read crosses section')
  return readat(off,n)
 def cstr(rva):
  off,available=mapped(rva);return readat(off,min(available,1024)).split(b'\0',1)[0].decode('ascii','replace')
 e=rva_bytes(export_rva,40)
 _,_,_,_,_,base,nfunc,nnames,funcrva,namesrva,ordrva=struct.unpack('<IIHHIIIIIII',e)
 if nnames>2000000 or nfunc>2000000:raise ValueError('implausible export count')
 funcs=rva_bytes(funcrva,nfunc*4);names=rva_bytes(namesrva,nnames*4);ords=rva_bytes(ordrva,nnames*2)
 matches=0
 for i in range(nnames):
  name=cstr(struct.unpack_from('<I',names,i*4)[0])
  if not any(n.casefold() in name.casefold() for n in a.needle):continue
  ordinal=struct.unpack_from('<H',ords,i*2)[0]
  if ordinal>=nfunc:raise ValueError('invalid ordinal')
  addr=struct.unpack_from('<I',funcs,ordinal*4)[0];forwarded=export_rva<=addr<export_rva+export_size
  try:offset=mapped(addr)[0]
  except ValueError:offset=None
  print(json.dumps({'name':name,'ordinal':ordinal+base,'rva':f'0x{addr:x}','file_offset':f'0x{offset:x}' if offset is not None else None,'forwarded':forwarded}));matches+=1
 print(f'export_names={nnames} functions={nfunc} matches={matches}',file=__import__('sys').stderr)

