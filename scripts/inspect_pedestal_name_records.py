"""Check all selected Cryo pedestal name records against their own decoded components."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('components',type=Path);p.add_argument('names',type=Path);a=p.parse_args();rows=[]
for path in sorted(a.components.glob('*.bin')):
 b=path.read_bytes();component=int(path.stem,16)
 if len(b)<0x254:raise ValueError('short component')
 tag,shared=struct.unpack_from('<II',b,0x80);np=a.names/f'{tag:08X}.bin';name=np.read_bytes()
 if len(name)<0x98 or struct.unpack_from('<I',name,0x64)[0]!=0x8080ab89:raise ValueError('unexpected name record')
 pos=0x68+struct.unpack_from('<q',name,0x68)[0];end=name.index(0,pos);value=name[pos:end].decode('ascii');ref,marker,field=struct.unpack_from('<III',name,0x88)
 if value!='o_pedestal' or ref!=component or marker!=0x8080b8f9 or field+4>len(b):raise ValueError('name or target mismatch')
 rows.append({'component':path.stem,'component_sha256':hashlib.sha256(b).hexdigest(),'name_tag':f'{tag:08X}','name_sha256':hashlib.sha256(name).hexdigest(),'shared_tag':f'{shared:08X}','field_offset':hex(field),'field_value':hex(struct.unpack_from('<I',b,field)[0])})
if len(rows)!=12 or len({x['component'] for x in rows})!=12:raise ValueError('expected 12 components')
print(json.dumps({'count':len(rows),'rows':rows,'warning':'Serialized references and default words; runtime meaning and grouping are not established.'},indent=2))
