"""Derive one modeled text range from on-disk bytes and captured synthetic inputs."""
import argparse,hashlib,json
from pathlib import Path
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('index',type=int);p.add_argument('out_dir',type=Path);a=p.parse_args();root=a.out_dir.resolve()
if root.is_relative_to(Path(__file__).resolve().parents[1]) or root.exists():raise ValueError('output directory must be new and outside repository')
with a.pe.open('rb') as f:identity=hashlib.file_digest(f,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected PE identity')
x=json.loads(a.trace.read_text());event=x['fast_transform_events'][a.index];ctx=x['transform_entries'][a.index];va=int(event['data'],16);n=event['length'];rva=va-0x140000000
if event.get('region')!='text' or not (0x1000<=rva and rva+n<=0x1000+851977728):raise ValueError('event outside .text')
with a.pe.open('rb') as f:f.seek(rva-0xa00);before=f.read(n)
if hashlib.sha256(before).hexdigest()!=event['before_sha256']:raise ValueError('file bytes differ from modeled event input; possible overlap or self-modification')
key=bytes.fromhex(ctx['rcx_bytes'])[:16];iv=bytes.fromhex(ctx['rdx_bytes'])[:16];after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv,'big')).encrypt(before)
if hashlib.sha256(after).hexdigest()!=event['after_sha256']:raise ValueError('modeled output mismatch')
root.mkdir();(root/'synthetic-range.bin').write_bytes(after);capture={'index':a.index,'length':n,'key':key.hex(),'counter':iv.hex(),'input':before.hex(),'expected_sha256':event['after_sha256'],'data_rva':hex(rva)};(root/'native-transform-input.json').write_text(json.dumps(capture))
print(json.dumps({'event':a.index,'va':hex(va),'length':n,'input_sha256':event['before_sha256'],'output_sha256':event['after_sha256'],'note':'synthetic captured inputs; not validated runtime memory'}))
