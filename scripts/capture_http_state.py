"""Read-only Windows HTTP import/TLS snapshot of an existing process.

No launch, injection, memory write, debugger attach, thread suspension, or UI.
Run with the access required by the target (an elevated game normally needs an
elevated terminal). Output stays local and must be a new filename.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct


class PEImports:
    """Bounded PE32+ import reader; never executes an image or reads it wholesale."""
    def __init__(self, path):
        self.stream = Path(path).open('rb')
        self.length = os.fstat(self.stream.fileno()).st_size
        try:
            if self.at(0, 2) != b'MZ': raise ValueError('missing MZ')
            header = struct.unpack('<I', self.at(0x3c, 4))[0]
            if self.at(header, 4) != b'PE\0\0': raise ValueError('missing PE signature')
            count = struct.unpack('<H', self.at(header + 6, 2))[0]
            optional_size = struct.unpack('<H', self.at(header + 20, 2))[0]
            if not 1 <= count <= 96 or optional_size < 128: raise ValueError('invalid PE headers')
            optional = self.at(header + 24, optional_size)
            if optional[:2] != b'\x0b\x02': raise ValueError('expected PE32+')
            self.import_rva, self.import_size = struct.unpack_from('<II', optional, 120)
            self.sections = []
            for index in range(count):
                row = self.at(header + 24 + optional_size + index * 40, 40)
                virtual, raw_size, raw = struct.unpack_from('<III', row, 12)
                self.sections.append((virtual, raw_size, raw))
        except Exception:
            self.stream.close()
            raise

    def close(self): self.stream.close()

    def at(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.length: raise ValueError('PE range outside file')
        self.stream.seek(offset)
        data = self.stream.read(length)
        if len(data) != length: raise ValueError('short PE read')
        return data

    def rva(self, address, length):
        for start, size, raw in self.sections:
            if start <= address and address + length <= start + size:
                return self.at(raw + address - start, length)
        raise ValueError(f'unmapped file RVA {address:#x}')

    def string(self, address):
        out = bytearray()
        for index in range(512):
            byte = self.rva(address + index, 1)
            if byte == b'\0': return out.decode('ascii', 'strict')
            out += byte
        raise ValueError('unterminated PE import name')

    def rows(self):
        if not self.import_rva: return
        for index in range(min(self.import_size // 20, 256)):
            descriptor = self.rva(self.import_rva + index * 20, 20)
            if descriptor == bytes(20): return
            original, _, _, name, first = struct.unpack('<IIIII', descriptor)
            dll = self.string(name)
            for slot in range(4096):
                thunk = struct.unpack('<Q', self.rva((original or first) + slot * 8, 8))[0]
                if thunk == 0: break
                symbol = '#' + str(thunk & 65535) if thunk >> 63 else self.string(thunk + 2)
                yield {'dll': dll, 'symbol': symbol, 'iat_rva': first + slot * 8}
            else: raise ValueError('import thunk budget exhausted')
        raise ValueError('import descriptor budget exhausted')


class Process:
    def __init__(self, pid):
        if os.name != 'nt' or struct.calcsize('P') != 8: raise RuntimeError('requires 64-bit Windows Python')
        self.k = C.WinDLL('kernel32', use_last_error=True)
        signatures = {
            'OpenProcess': ([W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
            'CloseHandle': ([W.HANDLE], W.BOOL),
            'ReadProcessMemory': ([W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)], W.BOOL),
            'K32EnumProcessModules': ([W.HANDLE, C.POINTER(W.HMODULE), W.DWORD, C.POINTER(W.DWORD)], W.BOOL),
            'K32GetModuleFileNameExW': ([W.HANDLE, W.HMODULE, W.LPWSTR, W.DWORD], W.DWORD),
            'QueryFullProcessImageNameW': ([W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)], W.BOOL),
            'GetExitCodeProcess': ([W.HANDLE, C.POINTER(W.DWORD)], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.k, name); function.argtypes = args; function.restype = result
        self.handle = self.k.OpenProcess(0x410, False, pid)  # QUERY_INFORMATION | VM_READ
        self.check(self.handle)

    @staticmethod
    def check(value):
        if not value: raise C.WinError(C.get_last_error())

    def close(self): self.k.CloseHandle(self.handle)

    def read(self, address, length):
        buffer = C.create_string_buffer(length); count = C.c_size_t()
        self.check(self.k.ReadProcessMemory(self.handle, address, buffer, length, C.byref(count)))
        if count.value != length: raise ValueError('short process read')
        return buffer.raw

    def modules(self):
        class Info(C.Structure):
            _fields_ = [('base', C.c_void_p), ('size', W.DWORD), ('entry', C.c_void_p)]
        function = self.k.K32GetModuleInformation
        function.argtypes = [W.HANDLE, W.HMODULE, C.POINTER(Info), W.DWORD]; function.restype = W.BOOL
        handles = (W.HMODULE * 2048)(); needed = W.DWORD()
        self.check(self.k.K32EnumProcessModules(self.handle, handles, C.sizeof(handles), C.byref(needed)))
        if needed.value > C.sizeof(handles): raise ValueError('module inventory truncated')
        result = []
        for handle in handles[:needed.value // C.sizeof(W.HMODULE)]:
            path = C.create_unicode_buffer(32768); info = Info()
            self.check(self.k.K32GetModuleFileNameExW(self.handle, handle, path, len(path)))
            self.check(function(self.handle, handle, C.byref(info), C.sizeof(info)))
            result.append({'path': path.value, 'base': hex(info.base), 'size': info.size})
        return result


def thread_contexts(process, pid, base):
    """Read the build-pinned protected dispatcher TLS record, NOT a call stack."""
    class Entry(C.Structure):
        _fields_ = [('size', W.DWORD), ('usage', W.DWORD), ('tid', W.DWORD), ('pid', W.DWORD),
                    ('priority', W.LONG), ('delta', W.LONG), ('flags', W.DWORD)]
    class Basic(C.Structure):
        _fields_ = [('exit', W.LONG), ('teb', C.c_void_p), ('client_pid', C.c_void_p),
                    ('client_tid', C.c_void_p), ('affinity', C.c_size_t), ('priority', W.LONG), ('base_priority', W.LONG)]
    k = process.k
    k.CreateToolhelp32Snapshot.argtypes = [W.DWORD, W.DWORD]; k.CreateToolhelp32Snapshot.restype = W.HANDLE
    for name in ['Thread32First', 'Thread32Next']:
        fn = getattr(k, name); fn.argtypes = [W.HANDLE, C.POINTER(Entry)]; fn.restype = W.BOOL
    k.OpenThread.argtypes = [W.DWORD, W.BOOL, W.DWORD]; k.OpenThread.restype = W.HANDLE
    query = C.WinDLL('ntdll').NtQueryInformationThread
    query.argtypes = [W.HANDLE, W.LONG, C.c_void_p, W.ULONG, C.POINTER(W.ULONG)]; query.restype = W.LONG
    index = struct.unpack('<I', process.read(base + 0x38f7ca68, 4))[0]
    if index > 4095: raise ValueError('unexpected native TLS index')
    snapshot = k.CreateToolhelp32Snapshot(4, 0)
    if snapshot == C.c_void_p(-1).value: raise C.WinError(C.get_last_error())
    rows = []
    try:
        entry = Entry(); entry.size = C.sizeof(entry)
        more = k.Thread32First(snapshot, C.byref(entry))
        while more:
            if entry.pid == pid:
                row = {'tid': entry.tid}; handle = None
                try:
                    handle = k.OpenThread(0x40, False, entry.tid)  # Query only; never suspend or set context.
                    process.check(handle)
                    basic = Basic(); returned = W.ULONG()
                    status = query(handle, 0, C.byref(basic), C.sizeof(basic), C.byref(returned))
                    if status < 0: raise RuntimeError(f'NtQueryInformationThread status {status & 0xffffffff:#x}')
                    row['teb'] = hex(basic.teb)
                    vector = struct.unpack('<Q', process.read(basic.teb + 0x58, 8))[0]
                    block = struct.unpack('<Q', process.read(vector + index * 8, 8))[0]
                    row['tls_block'] = hex(block)
                    body = process.read(block + 0x11f8, 64)
                    row['record_address'] = hex(block + 0x11f8)
                    row['record_hex'] = body.hex()
                    row['qwords'] = [hex(x) for x in struct.unpack('<8Q', body)]
                except Exception as error: row['error'] = str(error)
                finally:
                    if handle: k.CloseHandle(handle)
                rows.append(row)
            more = k.Thread32Next(snapshot, C.byref(entry))
    finally: k.CloseHandle(snapshot)
    return {'tls_index': index, 'record_offset': '0x11f8', 'threads': rows,
            'limitation': 'Sequential data snapshots, not CPU contexts, active frames, or a call stack.'}


HTTP_CODE_RANGES = (
    # Executed WinHttpSendRequest return RVA 0x311dd699 was recorded by the
    # observer. Capture its native wrapper neighborhood, not guessed stages.
    ('winhttp_wrappers', 0x311c0000, 0x30000),
    ('winhttp_function_table', 0x3530a800, 0x100),
    # The captured table maps the following candidate call sites to native
    # receive/read/header/callback APIs. Their bytes must be captured before
    # using the older synthetic image to infer native completion behavior.
    ('winhttp_receive_worker', 0x3115c000, 0x6000),
    ('winhttp_initialize', 0x3016e000, 0x4000),
    ('winhttp_response', 0x314c8000, 0x4000),
    ('winhttp_read', 0x2facd000, 0x4000),
    ('winhttp_available_thunk', 0x31be2000, 0x2000),
)


CALLBACK_CODE_RANGES = (('winhttp_native_callback', 0x30618000, 0x6000),)
CALLBACK_STUB_PAGES = (
    0x06464000, 0x067de000, 0x079ea000, 0x0db21000, 0x0dc3c000,
    0x0f6fd000, 0x0fb8f000, 0x128f4000, 0x12ea6000, 0x131d1000,
    0x14a74000, 0x17889000, 0x17f50000, 0x1918b000, 0x19e18000,
    0x1eb0e000, 0x1f5ec000, 0x213a0000, 0x21c1c000, 0x30887000, 0x31a11000,
)


def capture(pid, expected, protected, http_code=False, callback_code=False, callback_stubs=False, code_pages=()):
    report = {'pid': pid, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'status': 'incomplete', 'imports': [], 'errors': [],
              'limitations': ['Sequential reads are not atomic.', 'Import target identity does not prove a call executed.']}
    process = Process(pid)
    try:
        path = C.create_unicode_buffer(32768); length = W.DWORD(len(path))
        process.check(process.k.QueryFullProcessImageNameW(process.handle, 0, path, C.byref(length)))
        if Path(path.value).resolve() != expected.resolve(): raise ValueError('PID executable differs from expected path')
        modules = process.modules(); report['modules'] = modules
        main = next(m for m in modules if Path(m['path']).resolve() == expected.resolve())
        report['image_base'] = main['base']
        for module in modules:
            if module != main and Path(module['path']).name.lower() not in ['libcurl.dll', 'partywin.dll', 'winhttp.dll']: continue
            parser = None
            try:
                parser = PEImports(module['path'])
                for row in parser.rows():
                    dll = row['dll'].lower(); name = row['symbol']
                    if dll not in ['ws2_32.dll', 'winhttp.dll', 'libcurl.dll'] and name not in ['GetProcAddress', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW']: continue
                    address = int(module['base'], 16) + row['iat_rva']
                    target = struct.unpack('<Q', process.read(address, 8))[0]
                    provider = next((m for m in modules if int(m['base'], 16) <= target < int(m['base'], 16) + m['size']), None)
                    observed = dict(row, importer=module['path'], slot=hex(address), target=hex(target),
                                    provider=provider['path'] if provider else None,
                                    provider_rva=hex(target-int(provider['base'], 16)) if provider else None)
                    try: observed['target_bytes'] = process.read(target, 16).hex()
                    except Exception as error: observed['target_read_error'] = str(error)
                    report['imports'].append(observed)
            except Exception as error: report['errors'].append({'module': module['path'], 'error': str(error)})
            finally:
                if parser: parser.close()
        if len(code_pages) > 16 or any(rva < 0 or rva % 4096 or rva + 4096 > main['size'] for rva in code_pages):
            raise ValueError('code pages require at most 16 aligned pages inside the pinned image')
        if protected or http_code or callback_code or callback_stubs or code_pages:
            with expected.open('rb') as stream: sha = hashlib.file_digest(stream, 'sha256').hexdigest()
            report['executable_sha256'] = sha
            if sha != 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd':
                raise ValueError('protected context RVAs require the pinned Marathon executable hash')
        if protected:
            try:
                report['protected_context'] = thread_contexts(process, pid, int(main['base'], 16))
                failures = sum('error' in row for row in report['protected_context']['threads'])
                if failures: report['errors'].append({'thread_context_reads_failed': failures})
            except Exception as error: report['errors'].append({'protected_context': str(error)})
        if http_code or callback_code or callback_stubs or code_pages:
            report['http_code'] = []
            ranges = (HTTP_CODE_RANGES if http_code else ()) + (CALLBACK_CODE_RANGES if callback_code else ())
            if callback_stubs:
                ranges += tuple((f'callback_stub_{rva:08x}', rva, 0x1000) for rva in CALLBACK_STUB_PAGES)
            ranges += tuple((f'code_page_{rva:08x}', rva, 0x1000) for rva in code_pages)
            for label, rva, size in ranges:
                try:
                    data = process.read(int(main['base'], 16) + rva, size)
                    report['http_code'].append({'label': label, 'rva': hex(rva),
                                               'bytes': size, 'sha256': hashlib.sha256(data).hexdigest(),
                                               'hex': data.hex()})
                except Exception as error:
                    report['errors'].append({'http_code': label, 'error': str(error)})
        exit_code = W.DWORD()
        process.check(process.k.GetExitCodeProcess(process.handle, C.byref(exit_code)))
        if exit_code.value != 259: raise RuntimeError('target exited during snapshot')
        report['status'] = 'complete_with_errors' if report['errors'] else 'complete'
    except Exception as error:
        report['status'] = 'failed'
        report['errors'].append({'capture': str(error)})
    finally:
        process.close()
    report['ended_utc'] = datetime.now(timezone.utc).isoformat()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-exe', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--protected-context', action='store_true')
    parser.add_argument('--http-code', action='store_true',
                        help='Read pinned code around the observed WinHTTP caller and its API pointer table')
    parser.add_argument('--callback-code', action='store_true',
                        help='Read the 24 KiB window containing the observed native WinHTTP callback')
    parser.add_argument('--callback-stubs', action='store_true',
                        help='Read 84 KiB of protected callback handler code selected by the offline model')
    parser.add_argument('--code-page', type=lambda value: int(value, 0), action='append', default=[],
                        help='Read one aligned 4 KiB page inside the pinned executable; at most 16')
    args = parser.parse_args()
    # Reserve a new output file before collecting; keep failure evidence, too.
    with args.output.open('x', encoding='utf-8') as stream:
        try: report = capture(args.pid, args.expected_exe, args.protected_context, args.http_code, args.callback_code, args.callback_stubs, args.code_page)
        except Exception as error:
            json.dump({'status': 'failed', 'pid': args.pid, 'error': str(error)}, stream, indent=2)
            raise
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'status': report['status'], 'output': str(args.output.resolve()),
                      'modules': len(report.get('modules', [])), 'imports': len(report['imports'])}, indent=2))
    if report['status'] == 'failed': raise SystemExit(1)


if __name__ == '__main__': main()
