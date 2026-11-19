"""Temporary file-based memory reader for one user-authorized existing process.

No network listener, shell commands, target execution, suspension, debugger,
injection or memory-write API. Requests contain only bounded address ranges.
Run in the target's privilege context; Ctrl+C stops it at any time.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import re
import time

from capture_http_state import Process

PINNED_EXE_SHA256 = 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'
MAX_REQUEST_BYTES = 256 * 1024
MAX_RANGE_BYTES = 64 * 1024


def validate_ranges(request, base, image_size, allow_data, remaining):
    ranges = request.get('ranges')
    if not isinstance(ranges, list) or not 1 <= len(ranges) <= 16:
        raise ValueError('expected 1..16 ranges')
    result = []
    for row in ranges:
        if not isinstance(row, dict):
            raise ValueError('range must be an object')
        size = row.get('bytes')
        value = row.get('address')
        if not isinstance(value, str) or not re.fullmatch(r'0x[0-9a-fA-F]{1,16}', value):
            raise ValueError('address must be a hexadecimal string')
        address = int(value, 16)
        if type(size) is not int or not 1 <= size <= MAX_RANGE_BYTES:
            raise ValueError('range must contain 1..65536 bytes')
        if not 0x10000 <= address < address + size <= 0x800000000000:
            raise ValueError('address outside user memory')
        if not allow_data and not base <= address < address + size <= base + image_size:
            raise ValueError('range outside pinned executable image; data reads not authorized')
        result.append((address, size))
    total = sum(size for _, size in result)
    if total > min(MAX_REQUEST_BYTES, remaining):
        raise ValueError('request exceeds per-request or session byte budget')
    return result


def collect(process, ranges):
    rows = []
    for address, size in ranges:
        row = {'address': hex(address), 'bytes_requested': size}
        try:
            data = process.read(address, size)
            if len(data) != size:
                raise ValueError('short memory read')
            row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), hex=data.hex())
        except Exception as error:
            row['error'] = str(error)
        rows.append(row)
    return rows


def serve(args):
    # Reserve a new private session; never reuse old PID/request results.
    args.session_dir.mkdir(parents=False, exist_ok=False)
    process = None
    ending = 'failed'
    remaining = args.max_mib * 1024 * 1024
    try:
        process = Process(args.pid)
        path = C.create_unicode_buffer(32768)
        length = W.DWORD(len(path))
        process.check(process.k.QueryFullProcessImageNameW(process.handle, 0, path, C.byref(length)))
        if Path(path.value).resolve() != args.expected_exe.resolve():
            raise ValueError('target executable differs from expected path')
        with args.expected_exe.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != PINNED_EXE_SHA256:
            raise ValueError('executable differs from pinned Marathon build')
        main = next(m for m in process.modules() if Path(m['path']).resolve() == args.expected_exe.resolve())
        base = int(main['base'], 16)
        metadata = dict(status='serving', pid=args.pid, executable=str(args.expected_exe.resolve()),
                        image_base=hex(base), image_size=main['size'], executable_sha256=digest,
                        allow_data=args.allow_data, max_bytes=remaining, minutes=args.minutes,
                        limitation='Sequential read-only copies; no execution or task-completion proof.')
        (args.session_dir / 'session.json').write_text(json.dumps(metadata, indent=2))
        print(json.dumps(dict(status='serving', session_dir=str(args.session_dir.resolve()),
                              pid=args.pid, image_base=hex(base))), flush=True)
        deadline = time.monotonic() + args.minutes * 60
        seen = set()
        ending = 'expired'
        while time.monotonic() < deadline:
            exit_code = W.DWORD()
            process.check(process.k.GetExitCodeProcess(process.handle, C.byref(exit_code)))
            if exit_code.value != 259:
                ending = 'target_exited'
                break
            if (args.session_dir / 'STOP').exists():
                ending = 'stopped'
                break
            for request_path in sorted(args.session_dir.glob('request-*.json')):
                if not re.fullmatch(r'request-\d{6}\.json', request_path.name) or request_path.name in seen:
                    continue
                seen.add(request_path.name)
                reply = {'pid': args.pid, 'request': request_path.name, 'status': 'failed'}
                try:
                    if request_path.stat().st_size > 16384:
                        raise ValueError('request JSON exceeds 16 KiB')
                    request = json.loads(request_path.read_text())
                    ranges = validate_ranges(request, base, main['size'], args.allow_data, remaining)
                    remaining -= sum(size for _, size in ranges)  # Failed reads consume budget too.
                    reply['ranges'] = collect(process, ranges)
                    reply['status'] = 'complete_with_errors' if any('error' in r for r in reply['ranges']) else 'complete'
                except Exception as error:
                    reply['error'] = str(error)
                reply['remaining_bytes'] = remaining
                output = args.session_dir / request_path.name.replace('request-', 'result-', 1)
                with output.open('x') as stream:
                    json.dump(reply, stream, indent=2)
            if remaining == 0:
                ending = 'byte_budget_exhausted'
                break
            time.sleep(0.25)
    except KeyboardInterrupt:
        ending = 'interrupted'
    finally:
        if process:
            process.close()
        (args.session_dir / 'ended.json').write_text(json.dumps(dict(status=ending, remaining_bytes=remaining)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--expected-exe', type=Path, required=True)
    parser.add_argument('--session-dir', type=Path, required=True)
    parser.add_argument('--allow-data', action='store_true', help='Also permit bounded reads of target-owned memory outside its executable image')
    parser.add_argument('--minutes', type=int, choices=range(1, 61), default=15)
    parser.add_argument('--max-mib', type=int, choices=range(1, 33), default=16)
    serve(parser.parse_args())


if __name__ == '__main__':
    main()
