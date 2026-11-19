"""Bounded read-only owner search for the identified native HTTP wrapper.

Pointer occurrences are candidates, never proof of execution or typed ownership.
Raw windows remain in the caller-selected private evidence directory.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import struct
from capture_http_state import Process


class Region(C.Structure):
    _fields_ = [('base', C.c_void_p), ('allocation', C.c_void_p),
                ('allocation_protect', W.DWORD), ('partition', W.WORD),
                ('size', C.c_size_t), ('state', W.DWORD),
                ('protect', W.DWORD), ('kind', W.DWORD)]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--pid', type=int, required=True)
    ap.add_argument('--expected-exe', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--max-mib', type=int, default=512)
    args = ap.parse_args()
    args.output.mkdir(exist_ok=False)
    p = Process(args.pid)
    try:
        mods = p.modules()
        if Path(mods[0]['path']).resolve() != args.expected_exe.resolve():
            raise ValueError('wrong executable')
        base = int(mods[0]['base'], 16)
        wrapper = base + 0x367a5b48
        body = p.read(wrapper, 0x510)
        if struct.unpack_from('<Q', body)[0] != base + 0x32d27620:
            raise ValueError('identified HTTP vtable does not match')
        needles = {'wrapper': struct.pack('<Q', wrapper)}
        # Only established object identity is assumed; descriptor layouts are not.
        result = dict(pid=args.pid, image_base=hex(base), wrapper=hex(wrapper),
                      modules=mods, wrapper_hex=body.hex(), hits=[], errors=[],
                      limitation='Sequential pointer search; occurrences do not prove active frames or SOS ownership.')
        query = p.k.VirtualQueryEx
        query.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(Region), C.c_size_t]
        query.restype = C.c_size_t
        regions = []
        addr = 0
        while addr < 0x800000000000:
            r = Region()
            if not query(p.handle, addr, C.byref(r), C.sizeof(r)): break
            if r.state == 0x1000 and r.protect & 0xcc and not r.protect & 0x100:
                if r.kind == 0x1000000 or r.size <= 16 * 1024 * 1024:
                    regions.append((r.base, r.size, r.kind))
            addr = (r.base or 0) + r.size
        regions.sort(key=lambda r: (not base <= r[0] < base + mods[0]['size'], r[1]))
        read = 0
        for start, size, kind in regions:
            if read + size > args.max_mib * 1024 * 1024: continue
            for offset in range(0, size, 1024 * 1024):
                n = min(size-offset, 1024*1024)
                try: data = p.read(start+offset, n)
                except OSError as e:
                    result['errors'].append(dict(address=hex(start+offset),error=str(e)))
                    continue
                read += n
                for name, needle in needles.items():
                    pos = data.find(needle)
                    while pos >= 0:
                        lo, hi = max(0,pos-128), min(n,pos+512)
                        raw = data[lo:hi]
                        result['hits'].append(dict(needle=name,address=hex(start+offset+pos),
                            region_kind=hex(kind),window_address=hex(start+offset+lo),
                            hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest()))
                        pos = data.find(needle,pos+1)
            if len(result['hits']) > 4096: raise ValueError('hit budget exceeded')
        result['bytes_read'] = read
        (args.output/'owners.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(dict(pid=args.pid,bytes_read=read,hits=len(result['hits']),
                              output=str(args.output/'owners.json'))))
    finally: p.close()


if __name__ == '__main__': main()
