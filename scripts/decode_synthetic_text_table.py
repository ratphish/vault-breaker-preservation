"""Decode the observed synthetic loader table and extrapolate remaining text events."""
import argparse,hashlib,json,mmap,struct
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('out',type=Path);a=p.parse_args();out=a.out.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('output must be new and private')
with a.pe.open('rb') as f:
 if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
x=json.loads(a.trace.read_text());events=x['fast_transform_events'];contexts=x['transform_entries'];start=next(i for i,e in enumerate(events) if e.get('region')=='text');observed=len(events)-start
if start!=63666 or len(contexts)!=len(events) or any(e.get('region')!='text' for e in events[start:]):raise ValueError('unexpected trace layout')
ctx0=contexts[start];key=bytes.fromhex(ctx0['rcx_bytes'])[:16];iv=bytes.fromhex(ctx0['rdx_bytes'])[:16];base=0x140000000;table=0xa21f8;count=0x2a472;mask=0x4f56789a;last=0;extra=0;total=0
if observed>count:raise ValueError('too many observed events')
with a.pe.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as image:
 for j in range(count):
  begin,end=struct.unpack_from('<II',image,table-0xa00+j*8);begin^=mask;end^=mask;n=end-begin+1
  if not 0x1000<=begin<=end<0x32c84000 or begin<last or (begin<table+count*8 and end+1>table):raise ValueError(f'bad or table-overlapping descriptor {j}')
  last=end+1;before=image[begin-0xa00:begin-0xa00+n];after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv,'big')).encrypt(before)
  event={'region':'text','data':hex(base+begin),'length':n,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest()};ctx=dict(ctx0);ctx['r8']=hex(base+begin);ctx['r9']=hex(n)
  if j<observed:
   if event!=events[start+j] or ctx!=contexts[start+j]:raise ValueError(f'trace mismatch {j}')
  else:events.append(event);contexts.append(ctx);extra+=1
  total+=n
x['stop']={'kind':'synthetic_table_extrapolation','observed_text_events':observed,'extrapolated_text_events':extra};x['table_extrapolation']={'table_rva':hex(table),'count':count,'mask':hex(mask),'text_bytes':total,'warning':'Decoded table and extrapolated transformations from synthetic captured key/counter; not a Windows runtime trace.'}
with out.open('x',encoding='utf8') as f:json.dump(x,f,separators=(',',':'))
print(json.dumps({'observed_text_events_verified':observed,'extrapolated_text_events':extra,'total_text_events':count,'text_bytes':total,'first_descriptor_rva':hex(table),'last_covered_end':hex(last),'output':str(out),'warning':x['table_extrapolation']['warning']}))
