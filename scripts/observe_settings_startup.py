"""Launch one preserved client and sample its native settings counters read-only."""
import hashlib
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from capture_http_state import Process
from serve_readonly_capture import PINNED_EXE_SHA256
from readonly_reference import decode_reference

sys.path.insert(0, r'D:\Marathon-preservation\tools\python')
from unicorn import UcError


GAME = Path(r'D:\Marathon-live\Marathon.exe')
ANALYSIS = Path(r'D:\Marathon-preservation\analysis')
PASSTHROUGH_SHA256 = 'bbe619358ce87d1708345776988e42cb8c15551d5c18b8fc238d2a8768b484c8'
PREFIX = bytes.fromhex('f0660fc11d02000000eb02')
SUFFIX = bytes.fromhex('6683fb11751f')
# Map formatter call RVA to its two-byte counter RVA in the pinned image.
FORMATTER_COUNTERS = {
    '0x31873fe6': 0x0a75d7df,
    '0x31874308': 0x132fecdd,
    '0x31874596': 0x17edaf49,
}
WRITER_SIGNATURES = {
    'entry': 0x0fb8cb6b,
    'slot0_setup': 0x1b8bf0ea,
    'slot1_setup': 0x1ab2c5f0,
    'slot2_setup': 0x1b0dcbe2,
}
CONFIG_HOLDER = 0x3679c298
OVERLAY_REQUEST = 0x344d8608


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds')


def verify_environment():
    check = r"""
    $ErrorActionPreference = 'Stop'
    $exe = 'D:\Marathon-live\Marathon.exe'
    if (Get-CimInstance Win32_Process -Filter "Name='Marathon.exe'" |
        Where-Object { !$_.ExecutablePath -or $_.ExecutablePath -eq $exe }) {
        throw 'Close the existing preserved client before starting a run.'
    }
    $block = Get-NetFirewallApplicationFilter -Program $exe | Get-NetFirewallRule |
        Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' -and
            $_.Direction -eq 'Outbound' -and $_.Profile -eq 'Any' }
    if (!$block -or (Get-NetFirewallProfile | Where-Object { !$_.Enabled })) {
        throw 'Existing outbound block and firewall profiles must be enabled.'
    }
    """
    subprocess.run(['powershell.exe', '-NoProfile', '-Command', check], check=True)
    for path, expected in [(GAME, PINNED_EXE_SHA256),
                           (GAME.parent / 'steam_api64.dll', PASSTHROUGH_SHA256),
                           (GAME.parent / 'bin/x64/steam_api64.dll', PASSTHROUGH_SHA256)]:
        with path.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                raise RuntimeError(f'Unexpected file hash: {path}')


def counter(proc, address):
    try:
        block = proc.read(address, 19)
    except OSError:
        return None
    if block[:11] == PREFIX and block[13:] == SUFFIX:
        return int.from_bytes(block[11:13], 'little')
    return None


def describe_field(field, urls):
    length = field.find(b'\0')
    if length < 0:
        return {'terminated': False}
    value = field[:length]
    return dict(length=length, http=value.startswith((b'http://', b'https://')),
                matches_signon=[i for i, url in enumerate(urls) if value and value == url],
                sha256=hashlib.sha256(value).hexdigest() if value else None)


class SourceReader:
    def __init__(self):
        self.reference = None
        self.object_address = None

    def fields(self, proc, base, image_size):
        reference = proc.read(base + CONFIG_HOLDER, 24)
        if not any(reference[:8]):
            self.reference = self.object_address = None
            return None, 'uninitialized'
        if self.reference != reference:
            obj, _ = decode_reference(proc.read, base, image_size, reference, CONFIG_HOLDER)
            self.object_address = obj
            self.reference = reference
        start = self.object_address + 0x1f0c + 0x234
        fields = proc.read(start, 3 * 256)
        if proc.read(base + CONFIG_HOLDER, 24) != reference:
            return None, 'holder_changed'
        return fields, 'readable'


def read_overlay(proc, base):
    try:
        request = proc.read(base + OVERLAY_REQUEST, 0x116)
    except OSError:
        return {'status': 'unreadable'}
    if len(request) != 0x116:
        return {'status': 'short_read'}
    name, terminator, _ = request[:0x100].partition(b'\0')
    return dict(status='readable', name=name.decode('ascii', errors='backslashreplace'),
                name_terminated=bool(terminator), expected_hash_raw=request[0x100:0x114].hex(),
                has_expected_hash=request[0x114], required=request[0x115])


def read_settings_owner(proc, base):
    try:
        metadata = proc.read(base + 0x344d85e0, 0x28)
        queue_count = int.from_bytes(metadata[0x18:0x1c], 'little', signed=True)
        index = int.from_bytes(metadata[0x24:0x28], 'little', signed=True)
        result = dict(queue_count=queue_count, owner_index=index, status='uninitialized')
        arena = proc.read(base + 0x3541dd00, 24)
        arena_slot = (base + 0x3541dd00 + int.from_bytes(arena[:8], 'little') +
                      int.from_bytes(metadata[:2], 'little') *
                      int.from_bytes(arena[16:24], 'little'))
        if not 0 <= index < 16:
            return result
        pool = int.from_bytes(proc.read(arena_slot, 8), 'little')
        owner = pool + int.from_bytes(metadata[16:24], 'little') + index * 0x13a8
        body = proc.read(owner, 0x13a8)
        count = int.from_bytes(body[0x60:0x64], 'little', signed=True)
        result.update(status='readable', error=int.from_bytes(body[4:8], 'little'),
                      overlay_count=count, newest_digest=None)
        if 1 <= count <= 16:
            start = 0x64 + (count - 1) * 0x114
            name = body[start:start+0x100].split(b'\0', 1)[0]
            result.update(newest_name=name.decode('ascii', errors='backslashreplace'),
                          newest_digest=body[start+0x100:start+0x114].hex())
        if proc.read(base + 0x344d85e0, 0x28) != metadata:
            return dict(status='metadata_changed', queue_count=queue_count)
        return result
    except OSError:
        return {'status': 'unreadable'}


def sample(proc, base, image_size, source_reader):
    slots = proc.read(base + 0x344ee458, 772)
    raw_urls = [proc.read(base + r, 64) for r in (0x367c01f8, 0x367c01a8, 0x367c0238)]
    urls = [u.split(b'\0', 1)[0] if b'\0' in u else None for u in raw_urls]
    try:
        fields, status = source_reader.fields(proc, base, image_size)
    except (ValueError, OSError, UcError) as exc:
        fields, status = None, f'{type(exc).__name__}: {exc}'
    return dict(settings_owner=read_settings_owner(proc, base),
                overlay=read_overlay(proc, base), check=counter(proc, base + 0x200fb9b9),
                copy=counter(proc, base + 0x130bd52d),
                writer_counts={name: counter(proc, base + rva)
                               for name, rva in WRITER_SIGNATURES.items()},
                enable_byte=proc.read(base + 0x344ee98d, 1)[0],
                writer_source_status=status,
                writer_sources=None if fields is None else
                    [describe_field(fields[i:i+256], urls) for i in (0, 256, 512)],
                destinations=[describe_field(slots[i:i+256], urls) for i in (0, 256, 512)],
                formatter_counts={call: counter(proc, base + rva - len(PREFIX))
                                  for call, rva in FORMATTER_COUNTERS.items()},
                slots_nonempty=[bool(slots[i]) for i in (0, 256, 512)],
                selector=int.from_bytes(slots[-4:], 'little', signed=True),
                source_nonempty=bool(proc.read(base + 0x364c3110, 1)[0]),
                signon_urls_present=[u.startswith(b'http') for u in raw_urls])


def main():
    verify_environment()
    with socket.create_connection(('127.0.0.1', 8080), timeout=2):
        pass
    folder = ANALYSIS / ('settings-startup-' + datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
    folder.mkdir()
    with (folder / 'samples.jsonl').open('x', buffering=1) as out:
        def record(**data):
            print(json.dumps(dict(utc=utc(), **data)), file=out)

        record(event='observer_ready', formatter_counter_rvas={
            call: hex(rva) for call, rva in FORMATTER_COUNTERS.items()},
               writer_counter_rvas={name: hex(rva + len(PREFIX))
                                    for name, rva in WRITER_SIGNATURES.items()})
        game = subprocess.Popen([str(GAME)], cwd=GAME.parent)
        record(event='launched', pid=game.pid)
        print(f'PID {game.pid}. Use normal sign-in. Evidence: {folder}', flush=True)
        proc = None
        base = None
        previous = None
        valid = 0
        verified_samples = dict.fromkeys(FORMATTER_COUNTERS, 0)
        writer_samples = dict.fromkeys(WRITER_SIGNATURES, 0)
        readable_sources = 0
        source_reader = SourceReader()
        deadline = time.monotonic() + 180
        try:
            while game.poll() is None and time.monotonic() < deadline:
                try:
                    if proc is None:
                        proc = Process(game.pid)
                    if base is None:
                        image = next(m for m in proc.modules() if Path(m['path']) == GAME)
                        base = int(image['base'], 16)
                    values = sample(proc, base, image['size'], source_reader)
                    readable_sources += int(values['writer_source_status'] == 'readable')
                    for name, count in values['writer_counts'].items():
                        writer_samples[name] += int(count is not None)
                    valid += int(values['check'] is not None and values['copy'] is not None)
                    for call, count in values['formatter_counts'].items():
                        if count is not None:
                            if verified_samples[call] == 0:
                                print(f'Live formatter signature verified at call {call}; '
                                      f'first counter value {count}.', flush=True)
                            verified_samples[call] += 1
                except (OSError, ValueError, StopIteration) as exc:
                    values = dict(unavailable=type(exc).__name__, detail=str(exc))
                if values != previous:
                    record(event='observation', **values)
                    previous = values
                time.sleep(0.1)
        finally:
            if proc is not None:
                proc.close()
            record(event='finished', valid_counter_samples=valid,
                   writer_verified_samples=writer_samples, readable_source_samples=readable_sources,
                   formatter_verified_samples=verified_samples, exit_code=game.poll())
        print(f'Capture finished. Valid counter samples: {valid}. Evidence: {folder}')
        print(f'Verified formatter samples by call RVA: {verified_samples}')
        print(f'Writer verified samples: {writer_samples}; readable source samples: {readable_sources}')


if __name__ == '__main__':
    main()
