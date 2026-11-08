"""Compare bounded relative string arrays of the three Cryo activity records."""
import hashlib,json,struct,sys
from pathlib import Path
b=Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(b).hexdigest()=='4a431942d85f7e0e41318e6ed42f4287c0693c01c3d577c3e7db4a14e88c4ef0'
def array(obj,off):
 field=obj+off;count,rel=struct.unpack_from('<Qq',b,field)
 if count==0:
  assert rel==0
  return []
 assert 0<count<=100 and rel
 table=field+8+rel;assert 0<=table<=len(b)-16-count*8
 assert struct.unpack_from('<QI',b,table)==(count,0x80802e8d)
 out=[]
 for i in range(count):
  p=table+16+8*i;pos=p+struct.unpack_from('<q',b,p)[0];assert 0<=pos<len(b)
  end=b.find(b'\0',pos);assert end>=pos;out.append(b[pos:end].decode('ascii'))
 return out
rows={}
for name,obj,key in [('standard',0x7f48,0xab661274),('rated',0x8790,0x905bbcff),('vault_breaker',0x91c8,0xbbd96908)]:
 assert struct.unpack_from('<I',b,obj)[0]==key
 rows[name]={hex(off):array(obj,off) for off in (0x20,0x30,0x40)}
print(json.dumps(rows,indent=2))
