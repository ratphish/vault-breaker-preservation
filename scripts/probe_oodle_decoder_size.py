"""Execute one preserved Oodle export in Unicorn without host DLL calls."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
import pefile
from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_HOOK_CODE, UC_HOOK_INSN
from unicorn.x86_const import UC_X86_INS_SYSCALL, UC_X86_INS_SYSENTER, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSP

parser = argparse.ArgumentParser()
parser.add_argument('dll', type=Path)
args = parser.parse_args()
raw = args.dll.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if digest != '24f182bb2127c007df04cc56063ceec5999a7dd714c133920310caa47295572a':
    raise ValueError('unexpected preserved Oodle DLL')
pe = pefile.PE(data=raw)
base = pe.OPTIONAL_HEADER.ImageBase
size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xfff) & ~0xfff
symbol = next(s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b'OodleLZDecoder_MemorySizeNeeded')
if symbol.forwarder:
    raise ValueError('unexpected forwarded export')


def probe(length):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(base, size)
    image = pe.get_memory_mapped_image()
    uc.mem_write(base, image)
    stack, ret = 0x700000000000, 0x730000000000
    uc.mem_map(stack, 0x10000)
    uc.mem_map(ret, 0x1000)
    uc.mem_write(ret, b'\x90')
    sp = stack + 0xffc8
    uc.mem_write(sp, struct.pack('<Q', ret))
    uc.reg_write(UC_X86_REG_RSP, sp)
    uc.reg_write(UC_X86_REG_RCX, 8)
    uc.reg_write(UC_X86_REG_RDX, length & 0xffffffffffffffff)
    observed = {'instructions': 0, 'return': False}

    def trace(machine, address, instruction_size, user):
        observed['instructions'] += 1
        if address == ret:
            observed['return'] = True
            machine.emu_stop()
        elif not base <= address < base + size:
            raise ValueError(f'execution outside Oodle image: {address:#x}')

    def no_host(machine, user):
        raise ValueError(f'host instruction attempted at {machine.reg_read(UC_X86_REG_RIP):#x}')

    uc.hook_add(UC_HOOK_CODE, trace)
    uc.hook_add(UC_HOOK_INSN, no_host, None, 1, 0, UC_X86_INS_SYSCALL)
    uc.hook_add(UC_HOOK_INSN, no_host, None, 1, 0, UC_X86_INS_SYSENTER)
    try:
        uc.emu_start(base + symbol.address, 0, count=10000)
    except UcError as exc:
        raise ValueError(f'Unicorn stopped at {uc.reg_read(UC_X86_REG_RIP):#x}: {exc}') from exc
    if not observed['return']:
        raise ValueError('export did not return')
    observed.update(compressor=8, length=length, result=uc.reg_read(UC_X86_REG_RAX) & 0xffffffff)
    return observed


rows = [probe(n) for n in (-1, 1, 65536, 131072, 200000)]
for row in rows:
    n = row['length']
    block = n if 0 < n < 0x20000 else 0x20000
    expected = 3 * block + 0xd0d8
    if row['result'] != expected:
        raise ValueError(f"formula mismatch: {row}")
print(json.dumps({'dll_sha256': digest, 'export': 'OodleLZDecoder_MemorySizeNeeded',
                  'export_address': hex(base + symbol.address), 'results': rows,
                  'scope': 'compressor 8, five lengths; emulated DLL code, no host calls'}, indent=2))
