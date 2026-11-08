"""Compare synthetic shortcut events and final rdata with an earlier replay."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('worker',type=Path)
p.add_argument('prior_trace',type=Path)
p.add_argument('prior_image',type=Path)
a=p.parse_args()
new=json.loads(a.worker.read_text(encoding='utf-8-sig'))
old=json.loads(a.prior_trace.read_text(encoding='utf-8-sig'))
events=old['fast_transform_events'];fast=new.get('fast_aes_events',[]);differences=[]
for row in fast:
    i=row['index']
    if not 0<=i<len(events):raise ValueError('event index out of range')
    prior=events[i]
    bad=[key for key in ('data','length','before_sha256','after_sha256') if row[key]!=prior[key]]
    if bad:differences.append({'index':i,'fields':bad})
with a.prior_image.open('rb') as f:digest=hashlib.file_digest(f,'sha256').hexdigest()
worker_digest=new.get('worker_rdata_sha256') or new.get('fake_worker_outcome',{}).get('rdata_sha256')
print(json.dumps({'shortcut_events_compared':len(fast),'shortcut_event_differences':differences,
                  'worker_completed':new.get('aes_completed'),'worker_stop':new['stop'],
                  'worker_rdata_sha256':worker_digest,'prior_rdata_sha256':digest,
                  'rdata_matches':worker_digest==digest,
                  'warning':'Synthetic outputs only; independently executed periodic calls and callback models do not prove a real Windows runtime.'},indent=2))
