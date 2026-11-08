"""Validate selected Vault Breaker name and listener reference records from decoded tags."""
import argparse,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('directory',type=Path);p.add_argument('--metadata',type=Path,required=True);a=p.parse_args();root=a.directory
expected={'80B37FEB':'a16aca052bda3a2f92e491299a8e9f41adc221cc59f6a813ceef0e675ac6d783','80B37FEC':'a2416ea3c72d8c7c0d95bf29c18b2166ff44cc02459a21ca213192ced7b05c8b','80B37FED':'70ccaa2ce14425d4603690cf043ad0c69921af49b607bf1d7dea94a0389741cc'}
b={}
for tag,digest in expected.items():
 b[tag]=(root/(tag+'.bin')).read_bytes()
 if hashlib.sha256(b[tag]).hexdigest()!=digest:raise ValueError(f'unexpected decoded tag {tag}')
refs=b['80B37FEB'];names=b['80B37FEC'];component=b['80B37FED'];base=0xb0
metadata=a.metadata.read_bytes()
if hashlib.sha256(metadata).hexdigest()!='47ac143f154f28a237e7beb77d4c45f030eda9b28404ee8f35d5bc6bd40219f4':raise ValueError('unexpected activity metadata')
named={}
for off in range(0,len(metadata)-24,8):
 rel=struct.unpack_from('<q',metadata,off)[0];typ,field,flag=struct.unpack_from('<III',metadata,off+8);pos=off+rel
 if typ!=0x8080a23f or flag!=0x1e or not 0<=pos<len(metadata):continue
 end=metadata.find(b'\0',pos,min(len(metadata),pos+200))
 if end<0:continue
 try:name=metadata[pos:end].decode('ascii')
 except UnicodeDecodeError:continue
 if not name.startswith('il_'):continue
 if base+field in named:raise ValueError('duplicate listener metadata offset')
 named[base+field]={'name':name,'metadata_offset':hex(off)}
fields={};slots={}
for off in range(0,len(metadata)-24,8):
 rel=struct.unpack_from('<q',metadata,off)[0];typ,value,flag=struct.unpack_from('<III',metadata,off+8);pos=off+rel
 if not 0<=pos<len(metadata):continue
 end=metadata.find(b'\0',pos,min(len(metadata),pos+200))
 if end<0:continue
 try:name=metadata[pos:end].decode('ascii')
 except UnicodeDecodeError:continue
 if typ in (0x80800070,0x80800007) and name.startswith(('sh_','i_')):fields.setdefault(base+value,[]).append({'name':name,'type':hex(typ),'metadata_offset':hex(off)})
 if typ==0x80b37c7e and flag==0x16:slots.setdefault(value,[]).append(name)
known={0x2e0:1,0x440:2,0x650:3,0xb20:4,0x860:5,0xd30:6,0xff0:7};listeners=[]
for row in range(2,28):
 off=0xb0+row*0x28;v=struct.unpack_from('<10I',refs,off);relative=v[1];component_off=base+relative
 if v[3:6]!=(0x8080a23f,0x80b37fed,0x8080baf4):raise ValueError(f'unexpected reference row {row}')
 tag,marker,back=struct.unpack_from('<III',component,component_off)
 if (tag,marker)!=(0x80b37fed,0x8080a240):raise ValueError(f'unexpected listener row {row}')
 ref_tag,ref_marker,ref_back=struct.unpack_from('<III',component,back)
 if (ref_tag,ref_marker,ref_back)!=(0x80b37fed,0x8080a23f,component_off) or v[6]!=back+0x10 or v[8]!=struct.unpack_from('<I',component,back+0x18)[0]:raise ValueError(f'bad listener cross-link row {row}')
 if component_off not in named:raise ValueError(f'missing listener name row {row}')
 nearby=[]
 for delta in (0xa0,0xa4):
  field_off=component_off+delta
  for field in fields.get(field_off,[]):nearby.append({**field,'file_offset':hex(field_off),'raw_u32':hex(struct.unpack_from('<I',component,field_off)[0])})
 bindings=[]
 for at in range(component_off,component_off+0xb0-7,4):
  tag,slot=struct.unpack_from('<II',component,at)
  if tag==0x80b37c7e and slot in slots:bindings.append({'file_offset':hex(at),'slot':hex(slot),'names':slots[slot]})
 listeners.append({'row':row,'row_offset':hex(off),'listener_offset':hex(component_off),'reference_offset':hex(back),'target_tag':hex(v[8]),'vault':known.get(component_off),'nearby_metadata_fields':nearby,'named_slot_bindings':bindings,**named[component_off]})
if set(known)!=set(v['listener_offset'] and int(v['listener_offset'],16) for v in listeners if v['vault'] is not None):raise ValueError('missing selected vault listener')
name_rows=[]
for i in range(9):
 off=0x160+i*0x38;rel=struct.unpack_from('<q',names,off+8)[0];pos=off+8+rel;end=names.index(0,pos);name=names[pos:end].decode('ascii');tag,marker,field=struct.unpack_from('<III',names,off+0x28)
 if tag!=0x80b37fed or marker!=0x8080b8f9 or field+4>len(component):raise ValueError(f'bad name row {i}')
 name_rows.append({'name':name,'record_offset':hex(off),'component_offset':hex(field),'serialized_word':hex(struct.unpack_from('<I',component,field)[0])})
print(json.dumps({'listener_rows_verified':len(listeners),'listeners':listeners,'name_rows':name_rows,'warning':'Raw serialized cross-links and names; behavior, runtime values and code targets remain unknown.'},indent=2))
