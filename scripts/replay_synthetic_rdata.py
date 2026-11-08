"""Replay private synthetic AES events against a PE section; verify every recorded hash."""
import argparse,hashlib,json,struct
from pathlib import Path
import pefile
from Crypto.Cipher import AES
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('trace',type=Path);p.add_argument('expected_image',type=Path);p.add_argument('--capture-index',type=int);p.add_argument('--capture-file',type=Path);a=p.parse_args()
if (a.capture_index is None)!=(a.capture_file is None):raise ValueError('capture index and file must be supplied together')
if a.capture_file is not None and (a.capture_file.exists() or a.capture_file.resolve().is_relative_to(Path(__file__).resolve().parents[1])):raise ValueError('capture must be a new path outside the repository')
with a.pe.open('rb') as f:identity=hashlib.file_digest(f,'sha256').hexdigest()
if identity!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('unexpected PE identity')
x=json.loads(a.trace.read_text(encoding='utf-8-sig'));events=x['fast_transform_events'];contexts=x['transform_entries']
if len(events)!=len(contexts) or x.get('stop',{}).get('import')!='<synthetic-thread-return>':raise ValueError('incomplete synthetic trace')
pe=pefile.PE(str(a.pe),fast_load=True);pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']]);section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.rdata');base=pe.OPTIONAL_HEADER.ImageBase;start=base+section.VirtualAddress
with a.pe.open('rb') as f:f.seek(section.PointerToRawData);buf=bytearray(f.read(section.SizeOfRawData))
if len(buf)!=section.SizeOfRawData:raise ValueError('short section')
marker=0x720000000000;patched=0
for desc in pe.DIRECTORY_ENTRY_IMPORT:
 for item in desc.imports:
  offset=item.address-start
  if not 0<=offset<=len(buf)-8:raise ValueError('IAT slot outside .rdata')
  struct.pack_into('<Q',buf,offset,marker+patched*16);patched+=1
for i,(event,ctx) in enumerate(zip(events,contexts)):
 off=int(event['data'],16)-start;n=event['length']
 if not (0<n<=16*1024*1024 and 0<=off<=len(buf)-n):raise ValueError(f'out-of-range call {i}')
 before=bytes(buf[off:off+n])
 if hashlib.sha256(before).hexdigest()!=event['before_sha256']:raise ValueError(f'input mismatch at call {i}')
 key=bytes.fromhex(ctx['rcx_bytes'])[:16];iv=bytes.fromhex(ctx['rdx_bytes'])[:16];after=AES.new(key,AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(iv,'big')).encrypt(before)
 if hashlib.sha256(after).hexdigest()!=event['after_sha256']:raise ValueError(f'output mismatch at call {i}')
 if i==a.capture_index:
  capture={'index':i,'length':n,'key':key.hex(),'counter':iv.hex(),'input':before.hex(),'expected_sha256':event['after_sha256'],'data_rva':hex(off+section.VirtualAddress)}
  with a.capture_file.open('x',encoding='utf-8') as out:json.dump(capture,out)
 buf[off:off+n]=after
expected=a.expected_image.read_bytes();digest=hashlib.sha256(buf).hexdigest();print(json.dumps({'events_verified':len(events),'bytes_processed':sum(e['length'] for e in events),'synthetic_iat_slots':patched,'replay_sha256':digest,'image_sha256':hashlib.sha256(expected).hexdigest(),'byte_identical':bytes(buf)==expected}))
if bytes(buf)!=expected:raise SystemExit(1)
