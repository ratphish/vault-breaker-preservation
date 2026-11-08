"""Bound PE unwind rows covering modeled registry call sites."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);a=p.parse_args()
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
pe=pefile.PE(str(a.pe),fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase;d=pe.OPTIONAL_HEADER.DATA_DIRECTORY[3];raw=pe.get_data(d.VirtualAddress,d.Size);rows=list(struct.iter_unpack('<III',raw));out=[]
for address in (0x17100ec16,0x1714e2875,0x17126ff30,0x16f476730):
 r=address-base;valid=[(b,e,u) for b,e,u in rows if 0x1000<=b<=r<e<=0x32c84000 and 0x32c84000<=u<0x33534000]
 if len(valid)!=1:raise ValueError('unexpected valid unwind-row count for '+hex(address))
 b,e,u=valid[0];out.append({'address':hex(address),'begin':hex(base+b),'end':hex(base+e),'unwind_rva':hex(u)})
print(json.dumps({'entries':len(rows),'scopes':out,'warning':'PE unwind bounds and modeled call candidates do not establish runtime reachability or decompiled function semantics.'},indent=2))

