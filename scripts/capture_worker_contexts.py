"""Capture Windows PSS CPU contexts plus bounded, subsequent stack reads.

PSS captures thread contexts through Windows; no debugger, injected code,
register writes, or completion writes. Stack bytes are later live copies.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import struct
from capture_http_state import Process


class ThreadEntry(C.Structure):
    _fields_ = [('exit', W.DWORD), ('teb', C.c_void_p), ('pid', W.DWORD),
        ('tid', W.DWORD), ('affinity', C.c_size_t), ('priority', C.c_int),
        ('base_priority', C.c_int), ('syscall_arg', C.c_void_p),
        ('syscall', W.WORD), ('create', W.FILETIME), ('end', W.FILETIME),
        ('kernel', W.FILETIME), ('user', W.FILETIME), ('start', C.c_void_p),
        ('capture', W.FILETIME), ('flags', W.DWORD), ('suspend', W.WORD),
        ('context_size', W.WORD), ('context', C.c_void_p)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', required=True, type=int)
    ap.add_argument('--expected-exe', required=True, type=Path)
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    args.output.mkdir(exist_ok=False)
    p = Process(args.pid)
    snap, marker = W.HANDLE(), W.HANDLE()
    k = p.k
    sigs = {
        'PssCaptureSnapshot': [W.HANDLE,W.DWORD,W.DWORD,C.POINTER(W.HANDLE)],
        'PssWalkMarkerCreate': [C.c_void_p,C.POINTER(W.HANDLE)],
        'PssWalkSnapshot': [W.HANDLE,W.DWORD,W.HANDLE,C.c_void_p,W.DWORD],
        'PssWalkMarkerFree': [W.HANDLE],
        'PssFreeSnapshot': [W.HANDLE,W.HANDLE],
    }
    for name, sig in sigs.items():
        fn = getattr(k,name); fn.argtypes=sig; fn.restype=W.DWORD
    def checked(status):
        if status: raise C.WinError(status)
    try:
        mods = p.modules()
        if Path(mods[0]['path']).resolve() != args.expected_exe.resolve():
            raise ValueError('wrong executable')
        checked(k.PssCaptureSnapshot(p.handle,0x180,0x100003,C.byref(snap)))
        checked(k.PssWalkMarkerCreate(None,C.byref(marker)))
        rows=[]
        while True:
            e=ThreadEntry()
            status=k.PssWalkSnapshot(snap,3,marker,C.byref(e),C.sizeof(e))
            if status==259: break
            checked(status)
            row=dict(tid=e.tid,start=hex(e.start or 0),teb=hex(e.teb or 0))
            if e.context and e.context_size>=256:
                raw=C.string_at(e.context,e.context_size)
                names='rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15 rip'.split()
                regs=dict(zip(names,struct.unpack_from('<17Q',raw,120)))
                row['registers']={name:hex(value) for name,value in regs.items()}
                try:
                    stack_base=struct.unpack('<Q',p.read(e.teb+8,8))[0]
                    n=min(65536,stack_base-regs['rsp'])
                    if not 0<n<=65536: raise ValueError('invalid stack bounds')
                    data=p.read(regs['rsp'],n)
                    row.update(stack_address=hex(regs['rsp']),stack_hex=data.hex(),
                               stack_sha256=hashlib.sha256(data).hexdigest())
                except (OSError,ValueError) as error: row['stack_error']=str(error)
            rows.append(row)
        output=dict(pid=args.pid,modules=mods,threads=rows,
                    limitation='CPU contexts are PSS observations. Stack reads follow capture and are not unwound frames.')
        (args.output/'contexts.json').write_text(json.dumps(output,indent=2))
        print(json.dumps(dict(pid=args.pid,threads=len(rows),output=str(args.output/'contexts.json'))))
    finally:
        if marker.value: checked(k.PssWalkMarkerFree(marker))
        if snap.value: checked(k.PssFreeSnapshot(C.c_void_p(-1),snap))
        p.close()


if __name__=='__main__': main()
