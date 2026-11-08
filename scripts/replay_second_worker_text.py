"""Replay recorded second-worker writes against the prior private modeled text image."""
import argparse
import hashlib
import json
import mmap
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('prior_text',type=Path)
p.add_argument('trace',type=Path)
p.add_argument('expected_text',type=Path)
a=p.parse_args()
x=json.loads(a.trace.read_text(encoding='utf-8-sig'))
if x['stop'].get('kind')!='synthetic_return' or x.get('second_image_write_truncated'):raise ValueError('incomplete second-worker trace')
events=x['second_image_write_events'];base=0x140001000;size=851977728
if a.prior_text.stat().st_size!=size or a.expected_text.stat().st_size!=size:raise ValueError('unexpected text length')
with a.prior_text.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca':raise ValueError('wrong prior image')
    f.seek(0)
    with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_COPY) as image:
        writes=0;write_bytes=0;changed=set()
        for i,e in enumerate(events):
            off=int(e['address'],16)-base;n=e['size']
            if not 0<=off<=size-n:continue
            if n<=0 or n>8:raise ValueError(f'unsupported write size {n} at {i}')
            before=bytes.fromhex(e['before'])
            if image[off:off+n]!=before:raise ValueError(f'pre-write mismatch at event {i}')
            after=int(e['value'],16).to_bytes(n,'little')
            for j,(u,v) in enumerate(zip(before,after)):
                if u!=v:changed.add(off+j)
            image[off:off+n]=after;writes+=1;write_bytes+=n
        digest=hashlib.sha256();expected_digest=hashlib.sha256();identical=True;chunk=8*1024*1024
        with a.expected_text.open('rb') as f2:
            for off in range(0,size,chunk):
                z=bytes(image[off:min(size,off+chunk)]);expected=f2.read(len(z));digest.update(z);expected_digest.update(expected)
                if z!=expected:identical=False
print(json.dumps({'all_image_events':len(events),'text_write_events':writes,'text_bytes_written':write_bytes,
                  'distinct_text_positions_changed_during_replay':len(changed),'replay_sha256':digest.hexdigest(),
                  'export_sha256':expected_digest.hexdigest(),'byte_identical':identical,
                  'warning':'Synthetic event replay; changed positions count any intermediate changes, not necessarily final differences.'},indent=2))
