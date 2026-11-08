"""Prepare private Ghidra windows for the modeled second-worker patched blocks."""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('text',type=Path)
p.add_argument('analysis',type=Path)
p.add_argument('output',type=Path)
a=p.parse_args();root=a.output.resolve()
if root.exists() or root.is_relative_to(Path(__file__).resolve().parents[1]):raise ValueError('new private output directory required')
with a.text.open('rb') as f:
    if hashlib.file_digest(f,'sha256').hexdigest()!='1c8f2a6e3cc77ad5b373afb368959968c78e571706974db051a32fabd0af459e':raise ValueError('wrong synthetic text')
x=json.loads(a.analysis.read_text(encoding='utf-8-sig'))
if x['ranges']!=129:raise ValueError('unexpected patch count')
windows=[('entry',0x171290000,0x171320000,[(0x171295af0,0x1712b0000)]),
         ('fragments',0x171290000,0x171320000,[]),('other',0x16f9fc000,0x16f9fd000,[])]
for row in x['patch_ranges']:
    begin=int(row['start'],16);end=int(row['end_exclusive'],16)
    w=windows[1] if windows[1][1]<=begin<end<=windows[1][2] else windows[2]
    if not w[1]<=begin<end<=w[2]:raise ValueError('patch outside windows')
    w[3].append((begin,end))
root.mkdir();manifest=[]
with a.text.open('rb') as src:
    for name,lo,hi,spans in windows:
        if not spans:raise ValueError('empty window')
        d=root/name;d.mkdir();src.seek(lo-0x140001000);payload=src.read(hi-lo)
        if len(payload)!=hi-lo:raise ValueError('short image window')
        (d/'range.bin').write_bytes(payload)
        (d/'ranges.txt').write_text(''.join(f'0x{begin:x} 0x{end-1:x}\n' for begin,end in spans))
        manifest.append({'window':name,'base':hex(lo),'bytes':len(payload),'ranges':len(spans),'sha256':hashlib.sha256(payload).hexdigest()})
(root/'manifest.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps({'windows':manifest,'warning':'Patched synthetic bytes; fragment ranges and Ghidra outputs are not verified functions.'},indent=2))
