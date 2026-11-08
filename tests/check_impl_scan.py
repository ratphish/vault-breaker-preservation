import json
from pathlib import Path
rows=[json.loads(s) for s in Path('research/implementation-name-matches.jsonl').read_text(encoding='utf-8-sig').splitlines()]
assert {(x['tag'],x['needle'],x['offset']) for x in rows}=={('80B37C7E','sc_vault_1_objectives_d_execute_impl',23879),('80B37C7E','spawn_initial_keys',21895)}
print('PASS: selected implementation names match only the recorded activity metadata entries')
