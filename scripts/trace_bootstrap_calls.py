"""Trace captured call stubs offline. Never opens or launches a process.

Fresh capture bytes are hash checked. Optional synthetic .text supplies missing
code only, and is explicitly identified as model evidence. Initial registers
and the stack are invented: stop before a conditional branch, data read outside
the fake stack, or any write outside that stack. This is not a runtime trace.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM
from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_MEM_READ,
                     UC_HOOK_MEM_WRITE, UC_HOOK_MEM_FETCH_UNMAPPED,
                     UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UcError)
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP


class CapturedCode:
    def __init__(self, directory, synthetic_text=None):
        self.manifest = json.loads((directory / 'capture-manifest.json').read_text())
        if self.manifest['status'] != 'complete':
            raise ValueError('incomplete capture')
        self.base = int(self.manifest['image_base'], 16)
        self.size = int(self.manifest['image_size'], 16)
        self.ranges = []
        for row in self.manifest['ranges']:
            data = (directory / row['file']).read_bytes()
            if len(data) != row['bytes'] or hashlib.sha256(data).hexdigest() != row['sha256']:
                raise ValueError('capture hash mismatch: ' + row['file'])
            self.ranges.append((int(row['rva'], 16), data, row['file']))
        self.synthetic = synthetic_text

    def read(self, rva, length):
        for start, data, name in self.ranges:
            if start <= rva and rva + length <= start + len(data):
                return data[rva-start:rva-start+length], 'capture:' + name
        if self.synthetic is not None and 0x1000 <= rva and rva + length <= self.size:
            with self.synthetic.open('rb') as stream:
                stream.seek(rva - 0x1000)
                data = stream.read(length)
            if len(data) == length:
                return data, 'synthetic-text'
        raise ValueError(f'code unavailable at RVA {rva:#x}')

    def page(self, rva):
        # Fill only code pages, overlay every captured byte at its true RVA.
        page = bytearray(b'\xcc' * 4096)
        if self.synthetic is not None and 0x1000 <= rva < self.size:
            with self.synthetic.open('rb') as stream:
                stream.seek(rva - 0x1000)
                data = stream.read(4096)
            page[:len(data)] = data
        for start, data, name in self.ranges:
            low, high = max(rva, start), min(rva + 4096, start + len(data))
            if low < high:
                page[low-rva:high-rva] = data[low-start:high-start]
        return bytes(page)


def trace(code, call_rva, limit=300):
    instruction, origin = code.read(call_rva, 5)
    if instruction[0] != 0xe8:
        raise ValueError('expected E8 rel32 at the selected captured call site')
    target = call_rva + 5 + struct.unpack('<i', instruction[1:])[0]
    result = {'call_rva': hex(call_rva), 'initial_target_rva': hex(target),
              'call_source': origin,
              'authority': 'offline-model', 'runtime_observed': False,
              'initial_conditions': 'emulator-default registers/flags; synthetic stack and caller return',
              'instructions': [], 'returns': []}
    if not 0 <= target < code.size:
        result['stop'] = {'kind': 'target_outside_image', 'rva': hex(target)}
        return result
    cpu = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, stack_size = 0x10000000000, 0x10000
    cpu.mem_map(stack, stack_size)
    rsp = stack + 0x8000
    cpu.mem_write(rsp, struct.pack('<Q', code.base + call_rva + 5))
    cpu.reg_write(UC_X86_REG_RSP, rsp)
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    mapped = set()

    def stop(kind, **fields):
        if 'stop' not in result:
            result['stop'] = {'kind': kind, **fields}
        cpu.emu_stop()

    def fetch(machine, access, address, size, value, context):
        rva = address - code.base
        try:
            code.read(rva, 1)
        except ValueError:
            stop('code_unavailable', rva=hex(rva))
            return False
        page = address & ~4095
        if page not in mapped:
            machine.mem_map(page, 4096)
            machine.mem_write(page, code.page(page - code.base))
            mapped.add(page)
        return True

    def before(machine, address, size, context):
        rva = address - code.base
        try:
            data, source = code.read(rva, size)
        except ValueError:
            stop('code_unavailable', rva=hex(rva))
            return
        op = next(decoder.disasm(data, address, count=1), None)
        if op is None:
            stop('undecodable', rva=hex(rva))
            return
        row = {'rva': hex(rva), 'source': source, 'instruction': op.mnemonic + ' ' + op.op_str,
               'bytes': data.hex()}
        result['instructions'].append(row)
        if len(result['instructions']) >= limit:
            stop('instruction_budget', rva=hex(rva))
        elif (op.group(CS_GRP_JUMP) and op.mnemonic != 'jmp' and not
              (len(op.operands) == 1 and op.operands[0].type == X86_OP_IMM and
               op.operands[0].imm == address + size)):
            # Flags may depend on invented incoming state. Do not choose a branch.
            # A jump to its own fallthrough has the same successor either way.
            stop('conditional_requires_context', rva=hex(rva))
        elif (op.mnemonic.startswith('cmov') and
              (len(op.operands) != 2 or op.operands[0].type != op.operands[1].type
               or op.operands[0].reg != op.operands[1].reg)):
            stop('conditional_requires_context', rva=hex(rva))
        elif op.mnemonic in ('int3', 'int1', 'ud2', 'syscall', 'sysenter', 'rdtsc', 'rdtscp'):
            stop('unmodeled_instruction', rva=hex(rva), instruction=op.mnemonic)
        elif op.mnemonic.startswith('ret'):
            current_rsp = machine.reg_read(UC_X86_REG_RSP)
            if stack <= current_rsp <= stack + stack_size - 8:
                destination = struct.unpack('<Q', machine.mem_read(current_rsp, 8))[0]
                result['returns'].append({'site_rva': hex(rva), 'target_rva': hex(destination - code.base)})

    def memory(machine, access, address, size, value, context):
        if not stack <= address <= stack + stack_size - size:
            stop('non_stack_memory_access', address=hex(address), bytes=size,
                 instruction_rva=hex(machine.reg_read(UC_X86_REG_RIP) - code.base))
        return False  # Never satisfy an unmapped read or write with invented data.

    cpu.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, fetch)
    cpu.hook_add(UC_HOOK_CODE, before)
    cpu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, memory)
    cpu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, memory)
    try:
        cpu.emu_start(code.base + target, 0, count=limit + 1)
    except UcError as error:
        if 'stop' not in result:
            result['stop'] = {'kind': 'emulator_error', 'message': str(error),
                              'rva': hex(cpu.reg_read(UC_X86_REG_RIP) - code.base)}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--synthetic-text', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--call-rva', type=lambda value: int(value, 0), action='append')
    args = parser.parse_args()
    code = CapturedCode(args.capture, args.synthetic_text)
    report = {'capture': str(args.capture.resolve()), 'image_base': hex(code.base),
              'capture_hashes_checked': True, 'traces': [trace(code, site) for site in
                  (args.call_rva or [0x2ef4c7e0, 0x30291247, 0x3029124c, 0x30291255, 0x3029126b])]}
    if args.synthetic_text:
        with args.synthetic_text.open('rb') as stream:
            sha = hashlib.file_digest(stream, 'sha256').hexdigest()
        report['synthetic_text'] = {'path': str(args.synthetic_text.resolve()), 'sha256': sha,
                                     'authority': 'prior model, not an authenticated runtime snapshot'}
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    for row in report['traces']:
        print(json.dumps({key: row.get(key) for key in ['call_rva', 'returns', 'stop']}))


if __name__ == '__main__':
    main()
