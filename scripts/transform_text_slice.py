"""Transform a bounded PE text slice from captured synthetic inputs; private output only."""
import argparse,hashlib,json,math,collections
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
out=a.output.resolve()
if out.exists() or out.is_relative_to(Path(__file__).resolve().parents[1]) or not out.parent.is_dir():raise ValueError('output must be a new path outside the repository')
with a.pe.open('rb') as f:identity=hashlib.file_digest(f,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected PE identity')
x=json.loads(a.trace.read_text());c=x['transform_entries'][-1];va=int(c['r8'],16);n=int(c['r9'],16)
if x['stop'].get('kind')!='aes_scope_or_stack_guard' or va!=0x140001000 or n!=150608 or x['exec_writes']!=0:raise ValueError('unexpected model boundary')
key=bytes.fromhex(c['rcx_bytes'])[:16];iv=bytes.fromhex(c['rdx_bytes'])[:16]
with a.pe.open('rb') as f:f.seek(0x600);before=f.read(n)
if len(before)!=n:raise ValueError('short input')
after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv,'big')).encrypt(before)
with out.open('xb') as f:f.write(after)
def ent(b):return -sum((n/len(b))*math.log2(n/len(b)) for n in collections.Counter(b).values())
print(json.dumps({'synthetic':True,'va':hex(va),'length':n,'before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(after).hexdigest(),'before_entropy':round(ent(before),5),'after_entropy':round(ent(after),5),'different_bytes':sum(x!=y for x,y in zip(before,after)),'warning':'Synthetic transformation using captured modeled inputs; not validated runtime memory.'}))
