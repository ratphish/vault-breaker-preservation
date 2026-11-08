import json
from pathlib import Path
names=['research/cryo-script-paths.jsonl','research/data-script-paths.jsonl']
sets=[{(x['tag'],x['needle'],x['offset']) for x in map(json.loads,Path(n).read_text(encoding='utf-8-sig').splitlines())} for n in names]
assert sets[0]==sets[1] and len(sets[0])==17
print('PASS: broader type-8/16 scan has the same 17 tag/needle/offset matches as the Cryo scan')
