"""Read an empirically observed build-specific handle-map layout without mutation."""
import argparse,bisect,hashlib,json,struct
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('file',type=Path);p.add_argument('tags',nargs='*',help='32-bit hex IDs');a=p.parse_args();b=a.file.read_bytes()
if len(b)<8:raise ValueError('short header')
n,unknown=struct.unpack_from('<II',b)
if n>10_000_000 or len(b)!=8+10*n:raise ValueError('length does not match candidate layout')
rows=[(struct.unpack_from('<I',b,8+7*i)[0],int.from_bytes(b[12+7*i:15+7*i],'little')) for i in range(n)]
tail_at=8+7*n;tail=[int.from_bytes(b[tail_at+3*i:tail_at+3*i+3],'little') for i in range(n)]
keys=[x for x,v in rows];ordered=all(keys[i]<=keys[i+1] for i in range(n-1));vals=[v for _,v in rows if v!=0xffffff]+[v for v in tail if v!=0xffffff]
if not ordered or len(vals)!=n or set(vals)!=set(range(n)):raise ValueError('candidate sorted/permutation invariants failed')
print(json.dumps({'kind':'summary','sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'count':n,'unknown_header':f'{unknown:08X}','first_array_valid':sum(v!=0xffffff for _,v in rows),'second_array_valid':sum(v!=0xffffff for v in tail),'sorted_ids':ordered,'unique_ids':len(set(keys)),'values_partition_zero_to_count_minus_one':True}))
for text in a.tags:
 target=int(text,16);lo=bisect.bisect_left(keys,target);hi=bisect.bisect_right(keys,target)
 for i in range(lo,hi):
  v=rows[i][1];w=tail[i];print(json.dumps({'kind':'row','tag':f'{target:08X}','row_index':i,'row_offset':8+7*i,'first_u24':f'{v:06X}','second_u24_same_index':f'{w:06X}'}))
 if lo==hi:print(json.dumps({'kind':'not_found','tag':f'{target:08X}'}))
