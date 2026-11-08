"""Summarize bounded PE exception-directory ranges for build 26136895."""
import argparse,struct,collections
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);a=p.parse_args()
with a.pe.open('rb') as f:
 f.seek(0x3c);pe=struct.unpack('<I',f.read(4))[0];f.seek(pe+24+112+3*8);rva,size=struct.unpack('<II',f.read(8))
 if (rva,size)!=(0x392a7000,3509556):raise ValueError('Unexpected build or directory')
 f.seek(0x35309200);data=f.read(size)
 if len(data)!=size:raise ValueError('Truncated directory')
counts=collections.Counter();sample={};valid=0
for i in range(0,len(data)-11,12):
 begin,end,unwind=struct.unpack_from('<III',data,i)
 if 0x1000<=begin<end<=0x32c84000 and end-begin<0x100000:
  valid+=1;bucket=begin//0x1000000;counts[bucket]+=1;sample.setdefault(bucket,(begin,end,unwind))
print('plausible_range_records',valid)
for k in sorted(counts):print(f'{k:02x}',counts[k],*(f'{v:08x}' for v in sample[k]))
