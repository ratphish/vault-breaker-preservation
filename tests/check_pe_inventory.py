import json
from pathlib import Path
rows=[json.loads(s) for s in Path('research/pe-inventory.jsonl').read_text(encoding='utf-8-sig').splitlines()]
assert len(rows)==33 and not any('error' in r for r in rows)
assert {r['path'] for r in rows if r['cli_directory_present']}=={'miniTicketDbg.exe','SharpDX.dll','SharpDX.DXGI.dll'}
print('PASS: 33 PE headers parsed; three managed-directory candidates match REA checks')
