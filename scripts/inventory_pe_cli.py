"""Inventory PE files and report whether a CLI header is declared."""
import argparse, struct, json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args()
for path in sorted(a.root.rglob('*')):
 if not path.is_file() or path.suffix.lower() not in {'.dll','.exe'}:continue
 try:
  with path.open('rb') as f:
   def at(pos,n):
    f.seek(pos);b=f.read(n)
    if len(b)!=n:raise ValueError('truncated file')
    return b
   if at(0,2)!=b'MZ':raise ValueError('missing MZ')
   pe=struct.unpack('<I',at(0x3c,4))[0]
   if at(pe,4)!=b'PE\0\0':raise ValueError('missing PE')
   machine,nsec,_,_,_,optsize,_=struct.unpack('<HHIIIHH',at(pe+4,20));opt=pe+24;magic=struct.unpack('<H',at(opt,2))[0]
   base=112 if magic==0x20b else 96 if magic==0x10b else None
   if base is None:raise ValueError('unknown optional header')
   count=struct.unpack('<I',at(opt+base-4,4))[0]; cli_rva=cli_size=0
   if count>14 and optsize>=base+15*8:cli_rva,cli_size=struct.unpack('<II',at(opt+base+14*8,8))
   print(json.dumps({'path':path.relative_to(a.root).as_posix(),'machine':f'0x{machine:04x}','size':path.stat().st_size,'cli_directory_present':bool(cli_rva and cli_size)}))
 except (OSError,ValueError,struct.error) as e:print(json.dumps({'path':path.relative_to(a.root).as_posix(),'error':str(e)}))
