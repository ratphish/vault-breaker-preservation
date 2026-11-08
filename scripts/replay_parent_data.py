"""Independently replay synthetic callback writes and modeled parent data transforms."""
import argparse
import hashlib
import json
from pathlib import Path
from Crypto.Cipher import AES
import pefile

p=argparse.ArgumentParser()
p.add_argument('pe',type=Path)
p.add_argument('callback_trace',type=Path)
p.add_argument('parent_trace',type=Path)
p.add_argument('expected_image',type=Path)
a=p.parse_args()
with a.pe.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='d5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':raise ValueError('wrong PE')
callbacks=json.loads(a.callback_trace.read_text(encoding='utf-8-sig'))
parent=json.loads(a.parent_trace.read_text(encoding='utf-8-sig'))
pe=pefile.PE(str(a.pe),fast_load=True)
sec=next(s for s in pe.sections if s.Name.rstrip(b'\0')==b'.data')
start=pe.OPTIONAL_HEADER.ImageBase+sec.VirtualAddress
with a.pe.open('rb') as f:f.seek(sec.PointerToRawData);buf=bytearray(f.read(sec.SizeOfRawData))
expected=a.expected_image.read_bytes()
if len(expected) not in (sec.SizeOfRawData,sec.Misc_VirtualSize):raise ValueError('unexpected expected image size')
if len(expected)>len(buf):buf.extend(bytes(len(expected)-len(buf)))
writes=0
for row in callbacks['image_write_samples']:
    off=int(row['address'],16)-start;n=row['size']
    if 0<=off and off+n<=len(buf):
        value=int(row['value'],16)&((1<<(n*8))-1)
        buf[off:off+n]=value.to_bytes(n,'little');writes+=1
events=parent.get('parent_data_events',[])
if not events:raise ValueError('no recorded parent data events')
for i,event in enumerate(events):
    off=int(event['data'],16)-start;n=event['length']
    if not 0<=off<=len(buf)-n:raise ValueError(f'event outside data {i}')
    before=bytes(buf[off:off+n])
    if hashlib.sha256(before).hexdigest()!=event['before_sha256']:raise ValueError(f'input mismatch at event {i}')
    output=AES.new(bytes.fromhex(event['key']),AES.MODE_CTR,nonce=b'',initial_value=int.from_bytes(bytes.fromhex(event['counter']),'big')).encrypt(before)
    if hashlib.sha256(output).hexdigest()!=event['after_sha256']:raise ValueError(f'output mismatch at event {i}')
    buf[off:off+n]=output
digest=hashlib.sha256(buf).hexdigest()
print(json.dumps({'callback_writes_replayed':writes,'events_replayed':len(events),'bytes_processed':sum(e['length'] for e in events),
                  'replay_sha256':digest,'image_sha256':hashlib.sha256(expected).hexdigest(),
                  'byte_identical':bytes(buf)==expected,
                  'warning':'Replay checks model consistency, not real loader state or unmodeled writes.'},indent=2))
