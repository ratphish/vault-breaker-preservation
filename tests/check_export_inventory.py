import json
from pathlib import Path
rows=[json.loads(s) for s in Path('research/script-related-exports.jsonl').read_text(encoding='utf-8-sig').splitlines()]
a=next(r for r in rows if r['name'].startswith('?_setup_script_workflow_tag_suite@@'))
b=next(r for r in rows if r['name'].startswith('?run_script_workflow_tag_unit_tests__function@@'))
assert (a['rva'],a['file_offset'])==('0x2f7a2690','0x2f7a1c90')
assert (b['rva'],b['file_offset'])==('0x2ef22710','0x2ef21d10')
assert not Path('research/vault-encounter-exports.jsonl').read_text(encoding='utf-8-sig').strip()
print('PASS: two previously recorded export mappings agree; bounded name search is empty')
