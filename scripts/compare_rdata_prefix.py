"""Replay a captured synthetic AES prefix and compare the worker's rdata digest."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import pefile
from Crypto.Cipher import AES

p=argparse.ArgumentParser()
p.add_argument('pe',type=Path)
p.add_argument('prior_trace',type=Path)
p.add_argument('worker_trace',type=Path)
a=p.parse_args()
with a.pe.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
old=json.loads(a.prior_trace.read_text(encoding='utf-8-sig'))
new=json.loads(a.worker_trace.read_text(encoding='utf-8-sig'))
if new['stop']['kind']!='aes_checkpoint':raise ValueError('worker did not reach an AES checkpoint')
count=new['stop']['completed']
if count!=new['aes_completed'] or count>len(old['fast_transform_events']):raise ValueError('invalid event count')
pe=pefile.PE(str(a.pe),fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
section=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.rdata')
base=pe.OPTIONAL_HEADER.ImageBase
start=base+section.VirtualAddress
with a.pe.open('rb') as f:f.seek(section.PointerToRawData);buf=bytearray(f.read(section.SizeOfRawData))
marker=0x720000000000
patched=0
for desc in pe.DIRECTORY_ENTRY_IMPORT:
    for item in desc.imports:
        off=item.address-start
        if not 0<=off<=len(buf)-8:raise ValueError('IAT slot out of range')
        struct.pack_into('<Q',buf,off,marker+patched*16);patched+=1
for i,(event,ctx) in enumerate(zip(old['fast_transform_events'][:count],old['transform_entries'][:count])):
    off=int(event['data'],16)-start;n=event['length']
    if not 0<=off<=len(buf)-n:raise ValueError('invalid output range')
    before=bytes(buf[off:off+n])
    if hashlib.sha256(before).hexdigest()!=event['before_sha256']:raise ValueError(f'input mismatch {i}')
    output=AES.new(bytes.fromhex(ctx['rcx_bytes'])[:16],AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(ctx['rdx_bytes'])[:16],'big')).encrypt(before)
    if hashlib.sha256(output).hexdigest()!=event['after_sha256']:raise ValueError(f'output mismatch {i}')
    buf[off:off+n]=output
digest=hashlib.sha256(buf).hexdigest()
print(json.dumps({'events_replayed':count,'prior_prefix_rdata_sha256':digest,
                  'worker_rdata_sha256':new['worker_rdata_sha256'],
                  'matches':digest==new['worker_rdata_sha256'],
                  'warning':'Both images are synthetic models with modeled loader/API state.'},indent=2))
