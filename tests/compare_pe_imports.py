import sys,json
from pathlib import Path
sys.path.insert(0,r'D:\Marathon-preservation\tools\python')
import pefile
p=pefile.PE(r'D:\Marathon-preservation\build-26136895-20261031\Marathon.exe',fast_load=True);p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
a={x.dll.decode('ascii').lower():[('#'+str(y.ordinal) if y.import_by_ordinal else y.name.decode('ascii')) for y in x.imports] for x in p.DIRECTORY_ENTRY_IMPORT}
b={x['dll'].lower():[(v['name'] if 'name'in v else '#'+str(v['ordinal'])) for v in x['functions']] for x in json.loads(Path('research/main-standard-imports.json').read_text(encoding='utf-8-sig'))['imports']}

for key in sorted(set(a)|set(b)):
 if a.get(key)!=b.get(key):
  print(key,[(i,x,y) for i,(x,y) in enumerate(zip(a.get(key,[]),b.get(key,[]))) if x!=y][:8])
assert a==b
print('PASS: pefile and streaming parser agree on',len(a),'DLLs and',sum(map(len,a.values())),'ordered import names/ordinals')
