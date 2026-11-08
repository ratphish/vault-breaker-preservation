"""Cross-index Vault Breaker pedestal implementation-named slots and serialized references."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('metadata',type=Path);p.add_argument('component',type=Path);a=p.parse_args();m=a.metadata.read_bytes();b=a.component.read_bytes()
if hashlib.sha256(m).hexdigest()!='c2e7983eaf8c318fc8a1dcde68b9a95ab52c3aa7864dcf216cb0dfd73bc253ff' or hashlib.sha256(b).hexdigest()!='61627badcce9b834fa028c267a5981a9321b855b0ecc48188281da2cb9dd16ba':raise ValueError('unexpected snapshot inputs')
slots={}
for off in range(0,len(m)-24,8):
 rel=struct.unpack_from('<q',m,off)[0];tag,slot,flag=struct.unpack_from('<III',m,off+8);pos=off+rel
 if tag!=0x80b38561 or flag!=0x16 or not 0<=pos<len(m):continue
 end=m.find(b'\0',pos,min(len(m),pos+200))
 if end<0:continue
 try:name=m[pos:end].decode('ascii')
 except UnicodeDecodeError:continue
 if slot in slots:raise ValueError(f'duplicate slot {slot}')
 slots[slot]={'slot':slot,'name':name,'metadata_record':hex(off),'component_pair_offsets':[]}
for off in range(0,len(b)-7,4):
 tag,slot=struct.unpack_from('<II',b,off)
 if tag==0x80b38561 and slot in slots:slots[slot]['component_pair_offsets'].append(hex(off))
if len(slots)!=6:raise ValueError('unexpected slot count')
print(json.dumps({'metadata':'80B38561','component':'80B38567','slots':[slots[k] for k in sorted(slots)],'warning':'Named serialized slot descriptors and raw matching pairs; native code addresses and behavior are not established.'},indent=2))
