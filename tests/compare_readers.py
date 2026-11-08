import json
from pathlib import Path
m={x['tag']:x for x in map(json.loads,Path('research/probe-evidence.txt').read_text(encoding='utf-8-sig').splitlines())}
a={x['tag']:x for x in map(json.loads,Path('research/audio-codex-validation.jsonl').read_text(encoding='utf-8-sig').splitlines())}
assert set(a)==set(m), (set(a)-set(m),set(m)-set(a))
for tag in sorted(a):
 assert (a[tag]['sha256'],a[tag]['length'],a[tag]['reference'])==(m[tag]['sha256'],m[tag]['size'],m[tag]['reference']),tag
print('PASS: six tag digests, lengths, and reference identifiers agree')
expected={'80B3808C':('80B38C23',2204),'80B38C23':('80B38BEC',24),'80B38BEC':('80B38569',188),'80B38569':('80B38567',32)}
for tag,(target,offset) in expected.items():
 assert any(r['target']==target and offset in r['offsets'] for r in a[tag]['references']), (tag,target,offset)
assert a['80B38567']['pathOffset']==0x3c0
print('PASS: four raw reference values and pedestal path match the selected offsets')
activity_records={}
for file in ['research/audio-activity-chain-019c.jsonl','research/audio-activity-chain-019b.jsonl']:
 for line in Path(file).read_text(encoding='utf-8-sig').splitlines():
  row=json.loads(line);activity_records[row['tag']]=row
for tag,target,offset in [('80B38BEC','80B37FEE',0x40),('80B37FEE','80B37FED',0x20)]:
 assert any(r['target']==target and offset in r['offsets'] for r in activity_records[tag]['references'])
assert activity_records['80B37FED']['activityPathOffset']==9377
print('PASS: raw activity component references and script filename match')

pedestal={x['tag']:x for x in map(json.loads,Path('research/pedestal-class-audio-verification.jsonl').read_text(encoding='utf-8-sig').splitlines())}
definition=json.loads(Path('research/pedestal-definition-instance-members.json').read_text(encoding='utf-8-sig'))
instance=json.loads(Path('research/pedestal-ordered-slot-names.json').read_text(encoding='utf-8-sig'))
assert pedestal['80B38555']['sha256'].lower()==definition['definition_sha256']
assert pedestal['80B38561']['sha256'].lower()==instance['sha256']
assert pedestal['80B38555']['reference']==pedestal['80B38561']['reference']=='80800000'
print('PASS: pedestal definition and instance metadata match independently decoded package bytes')
