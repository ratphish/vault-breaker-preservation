"""Summarize a private synthetic loader trace without copying transform keys."""
import argparse
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('trace',type=Path)
a=p.parse_args()
x=json.loads(a.trace.read_text(encoding='utf-8-sig'))
expected_text='e003a16dc5e495ee9b0b1b3824a46c9553e0bcbd038b432eddb3a55d7d450dca'
expected_rdata='e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42'
print(json.dumps({'stop':x['stop'],'callback_stops':[v['stop'] for v in x.get('loader_sequence',[])],
                  'modeled_faults':len(x.get('modeled_faults',[])),
                  'fake_worker':x.get('fake_worker'), 'fake_worker_outcome':x.get('fake_worker_outcome'),
                  'fake_virtualprotect':x.get('fake_virtualprotect',[]),
                  'parent_aes_completed':x.get('parent_aes_completed',0),
                  'parent_aes_bytes':x.get('parent_aes_bytes',0),
                  'parent_data_events':len(x.get('parent_data_events',[])),
                  'parent_data_bytes':x.get('parent_data_bytes',0),
                  'parent_data_sha256':x.get('parent_data_sha256'),
                  'parent_text_sha256':x.get('parent_text_sha256'),
                  'matches_prior_text':x.get('parent_text_sha256')==expected_text,
                  'matches_prior_rdata':x.get('fake_worker_outcome',{}).get('rdata_sha256')==expected_rdata,
                  'elapsed_seconds':x['elapsed_seconds'],
                  'warning':'Synthetic loader, fake APIs, invented scheduling and shortcut transforms; not a Windows runtime trace.'},indent=2))
