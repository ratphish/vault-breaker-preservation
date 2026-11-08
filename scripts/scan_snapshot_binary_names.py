"""Search loose snapshot binaries for a bounded set of script identifiers."""
import argparse
import json
import mmap
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('snapshot', type=Path)
a = p.parse_args()
names = ['spawn_initial_keys', 'sc_vault_1_objectives_d_execute_impl',
         'activity_vault_breaker', 'pf_vault_breaker_key_pedestal', 'bungiescript']
files, matches = [], []
for path in sorted(a.snapshot.rglob('*')):
    if not path.is_file() or path.suffix.lower() not in ('.dll', '.exe', '.dat', '.bin'):
        continue
    if path.stat().st_size == 0:
        continue
    rel = str(path.relative_to(a.snapshot))
    files.append(rel)
    with path.open('rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as image:
        for name in names:
            for encoding in ('ascii', 'utf-16le'):
                pos = image.find(name.encode(encoding))
                if pos >= 0:
                    matches.append({'file': rel, 'name': name, 'encoding': encoding, 'offset': hex(pos)})
print(json.dumps({'files_count': len(files), 'files': files, 'matches': matches,
                  'warning': 'Exact cleartext names only; encrypted, transformed and differently named code is not excluded.'}, indent=2))
