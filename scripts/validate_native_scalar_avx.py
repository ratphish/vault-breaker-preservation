"""Compare a generated scalar division on this Windows CPU with Unicorn.

Executes only the 13 bytes defined below, not game code. Requires Windows x64,
NumPy's AVX feature detection and an AVX-capable CPU/OS. Does not access a
game process or the network.
"""
import ctypes
import json
import platform
import struct

import numpy as np
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2


def float_bits(value):
    return struct.unpack('<I', struct.pack('<f', value))[0]


def main():
    if platform.system() != 'Windows' or platform.machine().lower() not in ('amd64', 'x86_64'):
        raise SystemExit('requires Windows x64')
    if not np._core._multiarray_umath.__cpu_features__.get('AVX', False):
        raise SystemExit('AVX unavailable to this process')
    # vxorps xmm2,xmm2,xmm2; vdivss xmm2,xmm0,xmm1;
    # vmovaps xmm0,xmm2; ret. Windows x64 passes the two floats in xmm0/1.
    code = bytes.fromhex('c5e857d2c5fa5ed1c5f828c2c3')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong)
    kernel.VirtualAlloc.restype = ctypes.c_void_p
    kernel.VirtualFree.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong)
    kernel.VirtualFree.restype = ctypes.c_int
    address = kernel.VirtualAlloc(None, len(code), 0x3000, 0x40)
    if not address:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        ctypes.memmove(address, code, len(code))
        fn = ctypes.CFUNCTYPE(ctypes.c_float, ctypes.c_float, ctypes.c_float)(address)
        native = float_bits(fn(1920., 1080.))
    finally:
        if not kernel.VirtualFree(address, 0, 0x8000):
            raise ctypes.WinError(ctypes.get_last_error())
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0x1000, 0x1000)
    uc.mem_write(0x1000, code)
    uc.reg_write(UC_X86_REG_XMM0, float_bits(1920.))
    uc.reg_write(UC_X86_REG_XMM1, float_bits(1080.))
    uc.emu_start(0x1000, 0x100c)
    emulated = uc.reg_read(UC_X86_REG_XMM2) & 0xffffffff
    print(json.dumps({'native_bits': hex(native), 'unicorn_bits': hex(emulated),
                      'expected_bounded_hook_bits': '0x3fe38e39',
                      'native_matches_bounded_hook': native == 0x3fe38e39,
                      'host_code_scope': 'generated arithmetic test only; no Marathon bytes'}, indent=2))
    if native != 0x3fe38e39:
        raise SystemExit('native result differs from bounded hook')


if __name__ == '__main__':
    main()
