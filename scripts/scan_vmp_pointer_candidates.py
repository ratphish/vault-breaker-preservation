"""Find aligned 64-bit candidates that numerically point into the modeled VMP section."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path
import numpy as np

p=argparse.ArgumentParser()
p.add_argument('images',nargs='+',type=Path)
a=p.parse_args()
lo=0x179600000;hi=lo+0x676200
out=[]
for path in a.images:
    with path.open('rb') as f:
        digest=hashlib.file_digest(f,'sha256').hexdigest();f.seek(0)
        with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
            count=len(image)//8;values=np.ndarray((count,),dtype='<u8',buffer=image)
            positions=np.flatnonzero((values>=lo)&(values<hi))
            if len(positions)>100000:raise ValueError('unexpectedly many candidates')
            hits=[{'offset':hex(int(i)*8),'value':hex(int(values[i]))} for i in positions]
            del values
    out.append({'file':path.name,'sha256':digest,'aligned_candidates':len(hits),'hits':hits})
print(json.dumps({'range':[hex(lo),hex(hi)],'images':out,
                  'warning':'Numerical aligned candidates only; pointer type, target entry and reachability are unverified.'},indent=2))
