"""One explicitly armed, build-pinned offline test: one DWORD 1->2 write.

No DLL replacement, injection, debugger, native decoder invocation, protection
changes, or retries of the write. The owning launcher always ends its client;
rollback discards the process instead of writing over subsequent native state.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys
import time

from capture_http_state import Process

EXE = Path(r'D:\Marathon-live\Marathon.exe')
DLL = Path(r'D:\Marathon-live\steam_api64.dll')
EXE_HASH = 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'
DLL_HASHES = {
    'ba01f2fbf4175815883768e2efd7ff07e7c5c5d065b108b79c97eb7f928fefbf',  # baseline
    'bbe619358ce87d1708345776988e42cb8c15551d5c18b8fc238d2a8768b484c8',  # native initialization passthrough
    'af614d9edd226bdfa99b5d4518052704ed94cc9b2cffc5fb6b45a95d6251d8a9',  # transport routing (port 7505 BAP enabled)
    '8b39afe884fabe17bd2660e7840e04bbefddc6226f2d310f08a318d35774f486',  # bootflow hook (state 8 table slot advance)
}
REFERENCE = 0x3658D650
sys.path.insert(0, r'D:\Marathon-preservation\tools\python')


class MemoryInfo(C.Structure):
    _fields_ = [('base', C.c_void_p), ('allocation_base', C.c_void_p),
                ('allocation_protect', W.DWORD), ('partition', W.WORD),
                ('size', C.c_size_t), ('state', W.DWORD),
                ('protect', W.DWORD), ('type', W.DWORD)]


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def decode_reference(read, base, image_size, reference):
    """Decode captured bytes privately; CPU execution never enters the client."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_UNMAPPED, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX, UC_X86_REG_RIP
    encoded, = struct.unpack_from('<Q', reference)
    codec, = struct.unpack_from('<I', reference, 20)
    if not encoded or not 0x1000 <= codec < 0x32C84000:
        raise ValueError('reference is not initialized')
    cpu = Uc(UC_ARCH_X86, UC_MODE_64)
    stack, marker = 0x700000000000, 0x710000000000
    cpu.mem_map(stack, 0x10000)
    cpu.mem_map(marker, 4096)
    cpu.mem_write(stack + 0xEFF8, struct.pack('<Q', marker))
    cpu.reg_write(UC_X86_REG_RSP, stack + 0xEFF8)
    cpu.reg_write(UC_X86_REG_RCX, encoded)
    cpu.reg_write(UC_X86_REG_RDX, base + REFERENCE)
    pages, violations = {}, []

    def missing(uc, access, address, size, value, context):
        page = address & ~4095
        if page in pages or len(pages) >= 16 or not base <= page < page + 4096 <= base + image_size:
            return False
        raw = read(page, 4096)
        cpu.mem_map(page, 4096)
        cpu.mem_write(page, raw)
        pages[page] = raw
        return True

    def writes(uc, access, address, size, value, context):
        if not stack <= address < address + size <= stack + 0x10000:
            violations.append(hex(address))
            uc.emu_stop()

    cpu.hook_add(UC_HOOK_MEM_UNMAPPED, missing)
    cpu.hook_add(UC_HOOK_MEM_WRITE, writes)
    cpu.emu_start(base + codec, marker, count=20000, timeout=1000000)
    if violations or cpu.reg_read(UC_X86_REG_RIP) != marker:
        raise ValueError('private decoder did not return safely')
    obj = encoded ^ cpu.reg_read(UC_X86_REG_RAX)
    if not 0x10000 <= obj < 0x800000000000 - 0xC0 or obj & 15:
        raise ValueError('decoded object is not canonical/aligned')
    return obj, {'codec_rva': hex(codec), 'pages': {
        hex(address): hashlib.sha256(raw).hexdigest() for address, raw in pages.items()}}


def snapshot(process, base, obj, reference):
    if process.read(base + REFERENCE, 24) != reference:
        raise ValueError('encoded reference changed')
    head = process.read(obj, 0xC0)
    task, result = struct.unpack('<II', process.read(base + 0x3683E9A0, 8))
    http_state, http_status = struct.unpack('<II', process.read(base + 0x367A5F98, 8))
    received, = struct.unpack('<Q', process.read(base + 0x367A5FB0, 8))
    return {'utc': datetime.now(timezone.utc).isoformat(), 'monotonic': time.monotonic(), 'object': hex(obj),
            'header': struct.unpack_from('<I', head)[0],
            'state': struct.unpack_from('<I', head, 12)[0],
            'flag': struct.unpack_from('<I', head, 188)[0],
            'appid': struct.unpack_from('<I', head, 120)[0],
            'signon_task': task, 'signon_result': result,
            'http_state': http_state, 'http_status': http_status, 'received_bytes': received,
            'other_readiness_value': struct.unpack('<I', process.read(base + 0x365C013C, 4))[0]}


def stalled(value):
    return (value['header'], value['state'], value['flag'], value['appid'],
            value['signon_task'], value['signon_result'], value['http_state'], value['http_status']) == (
                20, 1, 2, 3065800, 4, 20, 2, 200) and 0 < value['received_bytes'] <= 0xA000


def signon_stall_signature(process, base):
    task, result = struct.unpack('<II', process.read(base + 0x3683E9A0, 8))
    http_state, http_status = struct.unpack('<II', process.read(base + 0x367A5F98, 8))
    received, = struct.unpack('<Q', process.read(base + 0x367A5FB0, 8))
    return (task, result, http_state, http_status) == (4, 20, 2, 200) and 0 < received <= 0xA000


def kernel_signatures(k):
    k.VirtualQueryEx.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MemoryInfo), C.c_size_t]
    k.VirtualQueryEx.restype = C.c_size_t
    k.WriteProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
    k.WriteProcessMemory.restype = W.BOOL
    k.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
    k.GetProcessTimes.restype = W.BOOL
    k.CheckRemoteDebuggerPresent.argtypes = [W.HANDLE, C.POINTER(W.BOOL)]
    k.CheckRemoteDebuggerPresent.restype = W.BOOL


def creation_time(k, handle):
    values = [W.FILETIME() for _ in range(4)]
    Process.check(k.GetProcessTimes(handle, *(C.byref(value) for value in values)))
    return (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime


def write_dword_two(k, handle, address):
    """Exactly one API call, four bytes; caller owns all identity/prestate checks."""
    value = W.DWORD(2)
    written = C.c_size_t()
    ok = k.WriteProcessMemory(handle, address, C.byref(value), 4, C.byref(written))
    if not ok or written.value != 4:
        raise RuntimeError(f'write failed/short: completed_bytes={written.value}, winerror={C.get_last_error()}; no retry')


def force_once(process, pid, base, obj, reference, evidence):
    k = process.k
    kernel_signatures(k)
    before = snapshot(process, base, obj, reference)
    if not stalled(before):
        raise ValueError('stall signature changed; no write')
    info = MemoryInfo()
    Process.check(k.VirtualQueryEx(process.handle, obj, C.byref(info), C.sizeof(info)))
    if info.state != 0x1000 or info.type != 0x20000 or info.protect & 0x101 or not info.protect & 0xCC:
        raise ValueError('object is not committed private writable memory')
    if obj + 0xC0 > info.base + info.size:
        raise ValueError('object crosses its memory region')
    if process.read(base + 0x0D4F706F, 3) != b'\x8b\x43\x0c' or process.read(base + 0x0D4F7078, 3) != b'\x83\xf8\x02':
        raise ValueError('readiness instruction identity differs')
    handle = k.OpenProcess(0x1028, False, pid)  # QUERY_LIMITED_INFORMATION | VM_OPERATION | VM_WRITE
    Process.check(handle)
    try:
        if creation_time(k, handle) != creation_time(k, process.handle):
            raise ValueError('process creation identity differs')
        debugger = W.BOOL()
        Process.check(k.CheckRemoteDebuggerPresent(process.handle, C.byref(debugger)))
        if debugger.value:
            raise ValueError('debugger detected; no write')
        with (evidence / 'write-attempt.json').open('x') as stream:
            json.dump({'pid': pid, 'creation_time': creation_time(k, handle), 'base': hex(base),
                       'reference': reference.hex(), 'address': hex(obj + 12), 'before': before,
                       'original_bytes': '01000000', 'requested_bytes': '02000000', 'writes_allowed': 1,
                       'limitation': 'Pre-read and write are separate operations; native threads are not suspended.'}, stream, indent=2)
        if process.read(base + REFERENCE, 24) != reference or process.read(obj + 12, 4) != b'\x01\0\0\0':
            raise ValueError('last pre-write guard changed; no write')
        try:
            write_dword_two(k, handle, obj + 12)
        except Exception as error:
            (evidence / 'write-error.json').write_text(json.dumps({'write_calls': 1, 'error': str(error)}, indent=2))
            raise
        outcome = {'before': before, 'write_calls': 1, 'write_completed': True,
                   'write_completed_utc': datetime.now(timezone.utc).isoformat()}
        (evidence / 'write-result.json').write_text(json.dumps(outcome, indent=2))
        try:
            after = snapshot(process, base, obj, reference)
            outcome['after'] = after
        except Exception as error:
            after = None
            outcome['readback_error'] = str(error)
        (evidence / 'write-result.json').write_text(json.dumps(outcome, indent=2))
        print(json.dumps({'status': 'forced_once', 'pid': pid, 'address': hex(obj + 12),
                          'before': 1, 'requested': 2, 'readback': after['state'] if after else None}), flush=True)
        return after
    finally:
        k.CloseHandle(handle)


def run(args):
    evidence = args.evidence_dir
    arm = json.loads((evidence / 'ARM_FORCE_STATE2.json').read_text(encoding='utf-8-sig'))
    if arm != {'mode': 'force-state2-v1', 'pid': args.pid}:
        raise ValueError('missing matching one-test arm record')
    if (evidence / 'write-attempt.json').exists():
        raise ValueError('this evidence directory already consumed its write attempt')
    if digest(EXE) != EXE_HASH or digest(DLL) not in DLL_HASHES:
        raise ValueError('pinned installation differs')
    process = Process(args.pid)
    try:
        path = C.create_unicode_buffer(32768)
        length = W.DWORD(len(path))
        Process.check(process.k.QueryFullProcessImageNameW(process.handle, 0, path, C.byref(length)))
        if Path(path.value).resolve() != EXE.resolve():
            raise ValueError('process is not the preserved executable')
        modules = process.modules()
        main = next(row for row in modules if Path(row['path']).resolve() == EXE.resolve())
        base, image_size = int(main['base'], 16), main['size']
        start = time.monotonic()
        obj = None
        reference = None
        stable_since = None
        post_deadline = None
        with (evidence / 'samples.jsonl').open('x') as samples:
            while True:
                if post_deadline is None and time.monotonic() - start >= 180:
                    raise TimeoutError('expected stable stall was not reached; no write')
                exit_code = W.DWORD()
                Process.check(process.k.GetExitCodeProcess(process.handle, C.byref(exit_code)))
                if exit_code.value != 259:
                    raise RuntimeError(f'client exited with code {exit_code.value}')
                if obj is None:
                    # Do not interpret pre-initialization/protected .data as a
                    # pointer. Decode only after the known post-SignOn signature.
                    if not signon_stall_signature(process, base):
                        time.sleep(0.1)
                        continue
                    candidate = process.read(base + REFERENCE, 24)
                    if not int.from_bytes(candidate[:8], 'little'):
                        time.sleep(0.1)
                        continue
                    obj, decoding = decode_reference(process.read, base, image_size, candidate)
                    reference = candidate
                    (evidence / 'object-binding.json').write_text(json.dumps(
                        {'base': hex(base), 'object': hex(obj), 'reference': reference.hex(), **decoding}, indent=2))
                value = snapshot(process, base, obj, reference)
                samples.write(json.dumps(value) + '\n')
                samples.flush()
                if post_deadline is not None:
                    if time.monotonic() >= post_deadline:
                        return
                elif stalled(value):
                    if stable_since is None:
                        stable_since = time.monotonic()
                    if time.monotonic() - stable_since >= 0.2:
                        loaded = process.modules()
                        if not any(Path(row['path']).resolve() == DLL.resolve() for row in loaded) or digest(DLL) not in DLL_HASHES:
                            raise ValueError('baseline proxy identity differs')
                        force_once(process, args.pid, base, obj, reference, evidence)
                        post_deadline = time.monotonic() + 20
                else:
                    stable_since = None
                time.sleep(0.1)
    finally:
        process.close()


def main():
    if sys.argv[1:] == ['--preflight']:
        import unicorn
        if sys.version_info < (3, 11) or struct.calcsize('P') != 8:
            raise RuntimeError('requires 64-bit Python3.11 or newer')
        print(json.dumps({'status': 'preflight_ok', 'unicorn': unicorn.__version__}))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    result = {'status': 'finished', 'rollback': 'owning launcher closes the test process'}
    try:
        run(args)
    except BaseException as error:
        result = {'status': 'aborted', 'error': str(error), 'type': type(error).__name__}
    finally:
        (args.evidence_dir / 'helper-ended.json').write_text(json.dumps(result, indent=2))
        print(json.dumps(result), flush=True)
    if result['status'] != 'finished':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
