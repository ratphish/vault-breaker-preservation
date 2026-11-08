"""Compare private synthetic AES call inputs without exposing captured key material."""
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('worker',type=Path)
p.add_argument('prior',type=Path)
a = p.parse_args()
new=json.loads(a.worker.read_text(encoding='utf-8-sig'))
old=json.loads(a.prior.read_text(encoding='utf-8-sig'))
entries=new.get('aes_entries',[]);events=old['fast_transform_events'];contexts=old['transform_entries']
if not entries or len(entries)>len(events) or len(events)!=len(contexts):raise ValueError('unexpected trace lengths')
differences=[]
for i,(current,event,context) in enumerate(zip(entries,events,contexts)):
    fields={'data':(int(current['data'],16),int(event['data'],16)),
            'length':(current['length'],event['length']),
            'key':(current['key'],context['rcx_bytes'][:32]),
            'counter':(current['counter'],context['rdx_bytes'][:32])}
    bad=[name for name,(x,y) in fields.items() if x!=y]
    if bad:differences.append({'index':i,'fields':bad})
print(json.dumps({'compared_calls':len(entries),'differences':differences,
                  'matches':not differences,'worker_stop':new['stop'],
                  'warning':'Both sides are synthetic models; agreeing inputs do not prove real loader state or subsequent output.'},indent=2))
