"""Scan a build-specific .text for 32-bit displacements ending at target RVA."""
import argparse,json,mmap,struct
from pathlib import Path
import numpy as np
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('target_rva',type=lambda s:int(s,0));a=p.parse_args()
raw=0x600;text_rva=0x1000;size=851977728;chunk=8*1024*1024;hits=[]
with a.pe.open('rb') as f, mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
 for start in range(0,size-3,chunk):
  n=min(chunk,size-3-start);vals=np.ndarray((n,),dtype='<u4',buffer=mm,offset=raw+start,strides=(1,));idx=np.arange(n,dtype=np.uint32);want=np.uint32((a.target_rva-text_rva-start-4)&0xffffffff);indices=np.flatnonzero(vals+idx==want)
  for i in indices:
   rel=start+int(i);off=raw+rel;lo=max(raw,off-8);hi=min(raw+size,off+12);hits.append({'disp_file_offset':hex(off),'disp_rva':hex(text_rva+rel),'window_start':hex(lo),'window_hex':mm[lo:hi].hex()})
  del vals,idx,indices
print(json.dumps({'target_rva':hex(a.target_rva),'hits':hits,'count':len(hits),'note':'Raw displacement candidates only; instruction boundaries and runtime reachability unverified.'}))
