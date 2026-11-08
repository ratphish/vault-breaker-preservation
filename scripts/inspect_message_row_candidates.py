"""Inspect candidate Marathon message rows using two published Destiny 2 IDs.

The comparison is a lead, not proof that Marathon uses the same dispatcher.
Prints aggregate evidence and a few addresses; does not extract game bytes.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

import pefile

parser = argparse.ArgumentParser()
parser.add_argument('exe', type=Path)
parser.add_argument('rdata', type=Path)
args = parser.parse_args()
expected_exe = 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'
expected_data = 'e440e65ec21b63abf6edfd87868ab25d89946b54f8e53216a954eb62b7f10e42'
with args.exe.open('rb') as f:
    if hashlib.file_digest(f, 'sha256').hexdigest() != expected_exe:
        raise ValueError('unexpected original executable')
data = args.rdata.read_bytes()
if hashlib.sha256(data).hexdigest() != expected_data:
    raise ValueError('unexpected modeled rdata')
pe = pefile.PE(str(args.exe), fast_load=True)
section = next(s for s in pe.sections if s.Name.rstrip(b'\0') == b'.rdata')
if section.VirtualAddress != 0x32c84000:
    raise ValueError('unexpected rdata RVA')
counts = Counter()
examples = []
with args.exe.open('rb') as original:
    for off in range(0, min(len(data), section.SizeOfRawData) - 15, 16):
        handler, message, argc, flags = struct.unpack_from('<QIHH', data, off)
        if message not in (0x67774671, 0x3088896a):
            continue
        original.seek(section.PointerToRawData + off)
        unchanged = original.read(16) == data[off:off + 16]
        kind = 'code-range' if 0x140001000 <= handler < 0x172c84000 else 'null' if not handler else 'other'
        counts[(f'{message:08x}', kind, unchanged)] += 1
        if len(examples) < 8:
            examples.append({'rdata_offset': hex(off), 'row_va': hex(0x172c84000 + off),
                             'handler': hex(handler), 'id': hex(message), 'argc': argc,
                             'flags': flags, 'original_row_equal': unchanged})
print(json.dumps({'exe_sha256': expected_exe, 'rdata_sha256': expected_data,
                  'counts': [{'id': k[0], 'handler_kind': k[1], 'original_row_equal': k[2], 'count': v}
                             for k, v in sorted(counts.items())], 'examples': examples,
                  'scope': '16-byte aligned rows within file-backed rdata only; IDs from Destiny 2 are hypotheses; handler reachability, semantics and table boundaries unverified'}, indent=2))
