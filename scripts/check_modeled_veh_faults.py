"""Independently check observed protected VEH continuations against their inputs."""
import argparse
import json
import struct
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('trace', type=Path)
a = p.parse_args()
x = json.loads(a.trace.read_text(encoding='utf-8-sig'))
results = []
for fault in x['modeled_faults']:
    before, after = fault['before'], fault['after']
    rbx, rbp, rsp = (int(before[k], 16) for k in ('rbx','rbp','rsp'))
    signature = rbx ^ rbp ^ 0xd5e1740f6aceb1bb
    if signature & 0xffffffff != 0x4b8155a3 or signature != int(fault['signature'],16):
        raise ValueError('handler signature mismatch')
    if int(fault['table_address'],16) != 0x173534010 + (signature >> 32) * 16:
        raise ValueError('handler table index mismatch')
    table0, table1 = struct.unpack('<QQ',bytes.fromhex(fault['table_before']))
    stack0, stack1 = struct.unpack('<QQ',bytes.fromhex(fault['stack_before']))
    target_delta = struct.unpack('<i',struct.pack('<I',(table0 ^ rbx) & 0xffffffff))[0]
    expected = {'rbx': stack0, 'rbp': stack1, 'rsp': rsp+16, 'rip': 0x140000000+target_delta}
    actual = {k:int(after[k],16) for k in expected}
    if actual != expected or fault['handler_result'] != '0xffffffff':
        raise ValueError(f'handler result mismatch: {fault["fault_rip"]}')
    results.append({'fault_rip':fault['fault_rip'],'fault_address':fault['fault_address'],
                    'table_address':fault['table_address'],'resume_rip':hex(expected['rip'])})
print(json.dumps({'verified_faults':len(results),'results':results,
                  'warning':'Checks the handler arithmetic in a synthetic exception context; not evidence of Windows loader execution.'},indent=2))
