"""Inspect the observed 80808CEB activity-name table; does not infer gameplay authority."""
import argparse, hashlib, json, struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('record',type=Path);a=p.parse_args();b=a.record.read_bytes()
assert len(b)>=0x30 and struct.unpack_from('<Q',b,0)[0]==len(b)
count=struct.unpack_from('<Q',b,8)[0];start=0x10+struct.unpack_from('<q',b,0x10)[0]+0x10
assert start==0x30 and 0<count<=10000 and start+count*16<=len(b)
def fnv1(value):
 h=0x811c9dc5
 for byte in value.encode('ascii'):h=((h*0x1000193)&0xffffffff)^byte
 return h
rows=[]
for i in range(count):
 o=start+i*16;key,rel=struct.unpack_from('<Qq',b,o);target=o+8+rel
 assert 0<=target<=len(b)-16 and struct.unpack_from('<Q',b,target)[0]==key
 ptr=target+8;dest=ptr+struct.unpack_from('<q',b,ptr)[0];assert 0<=dest<len(b)
 end=b.find(b'\0',dest);assert end>=dest
 name=b[dest:end].decode('ascii');assert key==fnv1(name)
 rows.append(dict(index=i,row=hex(o),key=f'{key:08X}',record=hex(target),name=name,name_offset=hex(dest)))
print(json.dumps(dict(sha256=hashlib.sha256(b).hexdigest(),count=count,rows=rows,limit='Observed table structure only; field semantics and runtime use require independent validation'),indent=2))
