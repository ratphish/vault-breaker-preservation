"""Enumerate three observed string-array members for every activity-name table row."""
import json,struct,sys,hashlib
from pathlib import Path
b=Path(sys.argv[1]).read_bytes();assert hashlib.sha256(b).hexdigest()=='4a431942d85f7e0e41318e6ed42f4287c0693c01c3d577c3e7db4a14e88c4ef0'
def strings(obj,off):
 p=obj+off;count,rel=struct.unpack_from('<Qq',b,p)
 if not count:
  assert not rel;return []
 assert count<=100 and rel
 t=p+8+rel;assert 0<=t<=len(b)-16-8*count and struct.unpack_from('<QI',b,t)==(count,0x80802e8d)
 out=[]
 for j in range(count):
  q=t+16+8*j;v=q+struct.unpack_from('<q',b,q)[0];assert 0<=v<len(b);end=b.find(b'\0',v);assert end>=v;out.append(b[v:end].decode('ascii'))
 return out
rows=[]
for i in range(24):
 p=0x30+16*i;k,rel=struct.unpack_from('<Qq',b,p);o=p+8+rel;assert struct.unpack_from('<Q',b,o)[0]==k
 q=o+8;v=q+struct.unpack_from('<q',b,q)[0];end=b.find(b'\0',v);assert 0<=v<end<len(b)
 rows.append({'key':f'{k:08X}','name':b[v:end].decode('ascii'),'lists':{hex(x):strings(o,x) for x in (0x20,0x30,0x40)}})
print(json.dumps({'rows':rows,'limitation':'Structural string grouping, not established execution or authority'},indent=2))
