"""Search this build's exception-directory entries for an RVA; offsets are build-specific."""
import argparse,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('rva',type=lambda s:int(s,0));a=p.parse_args()
with a.pe.open('rb') as f:
 f.seek(0x3c);pe=struct.unpack('<I',f.read(4))[0];f.seek(pe+24+112+3*8);rva,size=struct.unpack('<II',f.read(8))
 if (rva,size)!=(0x392a7000,3509556):raise ValueError('Unexpected build or exception directory')
 f.seek(0x35309200);data=f.read(size)
 if len(data)!=size:raise ValueError('Truncated exception directory')
 print('exception_rva',hex(rva),'bytes',size)
 for i in range(0,len(data)-11,12):
  begin,end,unwind=struct.unpack_from('<III',data,i)
  if begin<=a.rva<end and 0x1000<=begin<end<=0x32c84000 and end-begin<0x100000:
   print('entry_offset',hex(i),'begin',hex(begin),'end',hex(end),'unwind',hex(unwind))
