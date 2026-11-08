"""Correlate observed TLS continuation stores with the next synthetic dispatcher."""
import argparse
import bisect
import collections
import json
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

p = argparse.ArgumentParser()
p.add_argument('trace', type=Path)
a = p.parse_args()
x = json.loads(a.trace.read_text())
events = x['range_events']
dispatch = x['dispatch_events']
indices = [d['instruction'] for d in dispatch]
c = Cs(CS_ARCH_X86, CS_MODE_64)
stores = []
for e in events:
    ins = next(c.disasm(bytes.fromhex(e['bytes']), int(e['pc'], 16)), None)
    if ins is None or ins.mnemonic != 'mov' or ins.op_str != 'qword ptr [rax + 0x18], rbx':
        continue
    i = bisect.bisect_right(indices, e['instruction'])
    d = dispatch[i] if i < len(dispatch) else None
    stores.append({'instruction': e['instruction'], 'site': e['pc'],
                   'address': e['regs']['rax'], 'value': e['regs']['rbx'],
                   'next_dispatch_instruction': d['instruction'] if d else None,
                   'next_dispatch_continuation': d['continuation'] if d else None,
                   'matches_next_dispatch': int(e['regs']['rbx'], 16) == int(d['continuation'], 16) if d else None})
last_stores = []
store_indices = [s['instruction'] for s in stores]
for d in dispatch:
    i = bisect.bisect_left(store_indices, d['instruction']) - 1
    if i >= 0:
        last_stores.append(int(stores[i]['value'], 16) == int(d['continuation'], 16))
print(json.dumps({'stores': len(stores), 'distinct_sites': len(set(s['site'] for s in stores)),
                  'destinations': dict(collections.Counter(s['address'] for s in stores)),
                  'matches': dict(collections.Counter(str(s['matches_next_dispatch']) for s in stores)),
                  'last_observed_store_before_dispatch_matches': dict(collections.Counter(map(str, last_stores))),
                  'examples': stores[:12],
                  'warning': 'Synthetic trace only; matching stores are not necessarily all setters, and another store may precede the next dispatcher.'}, indent=2))
