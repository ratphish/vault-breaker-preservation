import json
from pathlib import Path
p=Path(r'D:\Marathon-preservation\analysis\entrypoint-flow.jsonl')
rows=[json.loads(s) for s in p.read_text(encoding='utf-8-sig').splitlines()];by={x['va']:x for x in rows if 'va'in x}
assert by['0x15a14e2c2']['bytes']=='66bbeb27'
assert any(e['kind']=='call' and e['va']=='0x15a14e2c4' for e in by['0x15a14e2cc']['edges'])
assert by['0x15a14e2c4']['bytes']=='eb27' and by['0x15a14e2c4']['edges'][0]['va']=='0x15a14e2ed'
assert rows[-1]['visited']==100 and rows[-1]['remaining_queue']>0
print('PASS: bounded graph preserves overlapping decode and records truncation')
