"""Find candidate package IDs by header field 0x10; this does not validate packages."""
import argparse,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('dir',type=Path);p.add_argument('ids',nargs='+',type=lambda s:int(s,16));a=p.parse_args();found={i:[] for i in a.ids};errors=0;count=0
for f in a.dir.glob('*.pkg'):
 try:
  with f.open('rb') as h:h.seek(0x10);raw=h.read(2)
  if len(raw)!=2:raise ValueError('short header')
  i=struct.unpack('<H',raw)[0];count+=1
  if i in found:found[i].append(f.name)
 except (OSError,ValueError):errors+=1
print('package_files',count,'errors',errors,'candidate_ids',len(found))
for i,paths in found.items():print(f'{i:04X}',len(paths),*paths[:5])
