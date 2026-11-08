"""Compare VEX scalar arithmetic with equivalent legacy SSE instructions.

Run with the same Unicorn installation used by emulate_tls_callback.py. No game
code or host APIs are executed. The values are deliberately exactly representable.
"""
import json
import struct

import unicorn
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM6


def bits(value, width):
    return int.from_bytes(struct.pack('<f' if width == 32 else '<d', value), 'little')


def run(code, numerator, denominator, destination, width):
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_write(0x1000, code)
    for reg, value in ((UC_X86_REG_XMM0, denominator),
                       (UC_X86_REG_XMM1, numerator),
                       (UC_X86_REG_XMM6, destination)):
        uc.reg_write(reg, bits(value, width))
    uc.emu_start(0x1000, 0x1000 + len(code))
    return uc.reg_read(UC_X86_REG_XMM6) & ((1 << width) - 1)


def main():
    rows = []
    for width, vex_prefix, sse_prefix in ((32, 0xf2, 0xf3), (64, 0xf3, 0xf2)):
        for name, opcode in (('add', 0x58), ('sub', 0x5c), ('mul', 0x59),
                             ('div', 0x5e), ('min', 0x5d), ('max', 0x5f)):
            # SSE uses the destination as source 1, so seed it with 20.
            reference = run(bytes((sse_prefix, 0x0f, opcode, 0xf0)), 20., 4., 20., width)
            for old_destination in (0., 20.):
                actual = run(bytes((0xc5, vex_prefix, opcode, 0xf0)), 20., 4., old_destination, width)
                rows.append({'instruction': f'v{name}s{"s" if width == 32 else "d"} xmm6,xmm1,xmm0',
                             'old_destination': old_destination, 'actual_bits': hex(actual),
                             'sse_reference_bits': hex(reference), 'matches': actual == reference})
    print(json.dumps({'unicorn_version': unicorn.__version__, 'source1': 20., 'source2': 4.,
                      'scope': 'register operands and exact finite test values only', 'rows': rows}, indent=2))


if __name__ == '__main__':
    main()
