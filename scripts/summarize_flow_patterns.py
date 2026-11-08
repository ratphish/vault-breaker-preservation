"""Count syntactic patterns in an overapproximate graph, without rewriting code."""
import argparse,json,collections
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('graph',type=Path);a=p.parse_args()
rows=[json.loads(s) for s in a.graph.read_text(encoding='utf-8-sig').splitlines()];nodes={int(r['va'],16):r for r in rows if 'mnemonic'in r};pairs=[];next_jumps=[]
for va,r in nodes.items():
 if r['mnemonic']=='xchg':
  q=nodes.get(va+r['size'])
  if q and q['mnemonic']=='xchg' and q['operands']==r['operands']:pairs.append((va,va+r['size']))
 if r['mnemonic']=='jmp' and any(e['kind']=='branch' and int(e['va'],16)==va+r['size'] for e in r['edges']):next_jumps.append(va)
print('sampled_nodes',len(nodes),'adjacent_identical_xchg_pairs',len(pairs),'direct_jumps_to_next_instruction',len(next_jumps))
print('pair_examples',[(hex(x),hex(y)) for x,y in pairs[:5]])
print('jump_examples',[hex(x) for x in next_jumps[:5]])
