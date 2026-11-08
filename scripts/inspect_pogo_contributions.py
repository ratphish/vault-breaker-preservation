"""Read bounded linker contribution records from the original PE debug directory."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);a=p.parse_args()
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
pe=pefile.PE(str(a.pe),fast_load=True);pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']]);candidates=[e for e in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]) if e.struct.Type==13]
if len(candidates)!=1:raise ValueError('expected one type-13 debug record')
e=candidates[0];b=pe.get_data(e.struct.AddressOfRawData,e.struct.SizeOfData);off=4;out=[]
while off+8<=len(b):
 rva,size=struct.unpack_from('<II',b,off);end=b.find(b'\0',off+8)
 if end<0:raise ValueError('unterminated contribution name')
 name=b[off+8:end].decode('ascii')
 if not name:break
 if rva+size>pe.OPTIONAL_HEADER.SizeOfImage:raise ValueError('contribution outside image')
 out.append({'rva':hex(rva),'size':size,'name':name});off=(end+4)&~3
print(json.dumps({'signature':b[:4].hex(),'records':out,'warning':'PE debug contribution labels do not establish code validity or function boundaries.'}))
