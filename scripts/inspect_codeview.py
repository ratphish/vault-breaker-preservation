"""Read CodeView identities from the preserved PE; no symbol-server access."""
import argparse,hashlib,json,uuid,struct
from pathlib import Path
import pefile
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);a=p.parse_args()
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
pe=pefile.PE(str(a.pe),fast_load=True);pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']]);records=[]
with a.pe.open('rb') as f:
 for e in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
  if e.struct.Type!=2 or e.struct.SizeOfData<25:continue
  off=pe.get_offset_from_rva(e.struct.AddressOfRawData);f.seek(off);b=f.read(e.struct.SizeOfData)
  if b[:4]!=b'RSDS':continue
  path=b[24:].split(b'\0',1)[0].decode('utf-8','replace');records.append({'pdb_name':path.replace('\\','/').split('/')[-1],'guid':str(uuid.UUID(bytes_le=b[4:20])),'age':struct.unpack_from('<I',b,20)[0],'debug_rva':hex(e.struct.AddressOfRawData),'file_offset':hex(off),'record_sha256':hashlib.sha256(b).hexdigest()})
print(json.dumps({'records':records,'warning':'A CodeView identity does not establish that the matching PDB is available or that symbols correspond to modeled bytes.'}))
