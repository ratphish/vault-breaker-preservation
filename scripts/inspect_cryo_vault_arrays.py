"""Check the two observed string-array fields of the Cryo Vault investment object."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('record',type=Path);a=p.parse_args();b=a.record.read_bytes()
assert hashlib.sha256(b).hexdigest()== '4a431942d85f7e0e41318e6ed42f4287c0693c01c3d577c3e7db4a14e88c4ef0'
obj=0x91c8;assert struct.unpack_from('<I',b,obj)[0]==0xbbd96908
rows=[]
for off,expected in ((0x20,3),(0x40,2)):
 field=obj+off;count,rel=struct.unpack_from('<Qq',b,field);assert count==expected
 table=field+8+rel;assert 0<=table<=len(b)-16-8*count
 assert struct.unpack_from('<Q',b,table)[0]==count
 values=[]
 for i in range(count):
  q=table+16+8*i;pos=q+struct.unpack_from('<q',b,q)[0];assert 0<=pos<len(b)
  end=b.find(b'\0',pos);assert end>=pos;values.append(b[pos:end].decode('ascii'))
 rows.append({'member_offset':hex(off),'table':hex(table),'values':values})
assert rows[0]['values']==['activity_exp.cryo.standard_synced','activity_exp.cryo.standard_server','activity_exp.cryo.vault_breaker_server']
assert rows[1]['values']==['solo_synced','vb_solo_synced']
print(json.dumps({'object':hex(obj),'arrays':rows},indent=2))
