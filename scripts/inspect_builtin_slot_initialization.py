"""Check synthetic aggregator path initializes the three shared slot globals."""
import argparse,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('probe',type=Path);p.add_argument('types',type=Path);a=p.parse_args()
d=json.loads(a.probe.read_text(encoding='utf-8-sig'));types=json.loads(a.types.read_text(encoding='utf-8-sig'))['selected']
if d['start']!='0x1714e2875' or d['stop']!={'kind':'target_reached','address':'0x16f8d4c40'}:raise ValueError('unexpected probe')
rows=[]
for t in types:
 if not t.get('registry_candidates'):continue
 ptr=t['registry_candidates'][0]['pointer'];hits=[w for w in d['image_write_samples'] if w['address']==ptr and w['rip']=='0x16fc07380' and w['value']=='0xffffffff' and w['size']==4]
 if len(hits)!=1:raise ValueError('expected one initialization for '+t['tag'])
 rows.append({'tag':t['tag'],'global':ptr,'initialized_first_word':'ffffffff'})
if len(rows)!=3:raise ValueError('missing types')
print(json.dumps({'call_site':d['start'],'registration_target':d['stop']['address'],'descriptor':d['registers_at_stop']['rcx'],'descriptor_count':d['registers_at_stop']['rdx'],'records':rows,'warning':'Artificial-state execution of modeled bytes, not proof of actual runtime reachability or method binding.'},indent=2))
