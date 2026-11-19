"""Decode the opt-in native receiver observer's bounded register/stack files."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

REGISTER_ORDER='r15 r14 r13 r12 rdi rsi rbp rbx r11 r10 r9 r8 rdx rcx rax flags caller'.split()


def decode(path, image_base=None):
    match=re.fullmatch(r'(\d+)-(\d+)-slot(\d+)-(\d+)\.bin',path.name)
    if not match: raise ValueError('unexpected capture filename')
    raw=path.read_bytes()
    if not 144<=len(raw)<=136+16384 or len(raw)%8: raise ValueError('invalid capture length')
    values=struct.unpack_from('<17Q',raw)
    if raw[128:136]!=raw[136:144]: raise ValueError('saved caller differs from stack return address')
    pid,tid,slot,sample=map(int,match.groups())
    regs=dict(zip(REGISTER_ORDER,values))
    if slot>=11 and image_base is None: raise ValueError('table candidates require --image-base')
    base=image_base if image_base is not None else regs['rcx']-0x367a5b48
    def value(v):
        row={'address':hex(v)}
        if base<=v<base+0x39d3e000: row['image_rva']=hex(v-base)
        return row
    return dict(file=str(path),sha256=hashlib.sha256(raw).hexdigest(),pid=pid,tid=tid,
                slot=slot,sample=sample,image_base=hex(base),
                registers={k:value(v) for k,v in regs.items()},
                stack=[dict(offset=hex(off),**value(struct.unpack_from('<Q',raw,136+off)[0]))
                       for off in range(0,len(raw)-136-7,8)],
                limitation='Observed entry arguments and stack bytes; stack values are not automatically descriptors or result pointers.')


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('captures',nargs='+',type=Path)
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--image-base',type=lambda v:int(v,0))
    args=ap.parse_args()
    with args.output.open('x') as stream:
        json.dump([decode(p,args.image_base) for p in args.captures],stream,indent=2)
