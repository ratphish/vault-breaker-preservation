"""Check the nine serialized Vault Breaker handler wrappers after normalizing references."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('component',type=Path);a=p.parse_args();b=a.component.read_bytes()
if hashlib.sha256(b).hexdigest()!='70ccaa2ce14425d4603690cf043ad0c69921af49b607bf1d7dea94a0389741cc':raise ValueError('unexpected activity component')
items=[('main',0x1440,1),('vault_1',0x14f0,0x15),('vault_2',0x15a0,0x16),('vault_3',0x1650,0x17),('vault_5',0x1700,0x18),('vault_4',0x17b0,0x19),('vault_6',0x1860,0x1a),('secret_lab',0x1910,0x1b),('vault_7',0x19c0,0x1d)];rows=[];normalized=[]
for name,o,slot in items:
 if struct.unpack_from('<II',b,o)!=(0x80b37fed,0x8080ab7a) or struct.unpack_from('<II',b,o+0x20)!=(0x80b37c7e,slot) or struct.unpack_from('<III',b,o+0x40)!=(0x80b37fed,0x8080b8f1,o):raise ValueError(f'unexpected wrapper {name}')
 block=bytearray(b[o:o+0xb0])
 for begin,end in [(8,12),(16,24),(36,40),(72,76)]:block[begin:end]=bytes(end-begin)
 digest=hashlib.sha256(block).hexdigest();normalized.append(digest);rows.append({'name':name,'component_offset':hex(o),'slot':hex(slot),'normalized_sha256':digest})
if len(set(normalized))!=1:raise ValueError('normalized wrappers differ')
print(json.dumps({'wrappers':rows,'same_after_normalizing_four_reference_fields':True,'warning':'Generic serialized wrapper similarity does not establish where code resides or rule out implementation data elsewhere.'},indent=2))
