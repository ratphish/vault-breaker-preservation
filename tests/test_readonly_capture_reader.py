import hashlib
import ctypes
import json
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import pytest

import serve_readonly_capture as reader_module
from serve_readonly_capture import validate_ranges, collect


def request(address='0x140001000', size=4096):
    return {'ranges': [{'address': address, 'bytes': size}]}


def test_default_scope_refuses_heap_but_explicit_data_authorization_allows_it():
    with pytest.raises(ValueError, match='outside pinned'):
        validate_ranges(request('0x20000000000'), 0x140000000, 0x100000, False, 65536)
    assert validate_ranges(request('0x20000000000'), 0x140000000, 0x100000, True, 65536) == [(0x20000000000, 4096)]


@pytest.mark.parametrize('payload,budget', [
    (request(size=0), 65536), (request(size=-1), 65536),
    (request(size=True), 65536), (request(size=65537), 100000),
    (request('0xffffffffffffffff'), 65536), (request('0x1'), 65536),
    (request('0x7fffffffffff', 2), 65536), (request('$(bad)'), 65536),
    ({'ranges': []}, 65536), ({'ranges': [{}] * 17}, 65536),
    (request(), 4095),
    ({'ranges': [{'address': '0x140001000', 'bytes': 65536}] * 5}, 1000000),
])
def test_rejects_invalid_ranges_and_budgets(payload, budget):
    with pytest.raises(ValueError):
        validate_ranges(payload, 0x140000000, 0x100000, True, budget)


def test_read_results_are_hashed_and_errors_do_not_fabricate_bytes():
    class Reader:
        def read(self, address, size):
            if address == 0x10000:
                raise OSError('unreadable')
            return b'\x90' * size
    rows = collect(Reader(), [(0x10000, 4), (0x20000, 4)])
    assert rows[0]['error'] == 'unreadable'
    assert 'hex' not in rows[0]
    assert rows[1]['hex'] == '90909090'
    assert rows[1]['sha256'] == hashlib.sha256(b'\x90' * 4).hexdigest()


@pytest.mark.skipif(os.name != 'nt', reason='Windows process-reader integration')
def test_reader_roundtrip_uses_only_own_process_and_stops(monkeypatch, tmp_path):
    executable = Path(sys.executable)
    with executable.open('rb') as stream:
        own_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    # This override exists only in this test process; production CLI pins Marathon.
    monkeypatch.setattr(reader_module, 'PINNED_EXE_SHA256', own_digest)
    buffer = ctypes.create_string_buffer(b'test-readonly')
    session = tmp_path / 'session'
    failures = []

    def client():
        try:
            deadline = time.monotonic() + 5
            while not (session / 'session.json').exists():
                if time.monotonic() > deadline:
                    raise AssertionError('reader did not become ready')
                time.sleep(0.01)
            payload = request(hex(ctypes.addressof(buffer)), len(buffer.raw))
            pending = session / 'pending'
            pending.write_text(json.dumps(payload))
            pending.rename(session / 'request-000001.json')
            result = session / 'result-000001.json'
            while not result.exists():
                if time.monotonic() > deadline:
                    raise AssertionError('reader did not respond')
                time.sleep(0.01)
        except Exception as error:
            failures.append(error)
        finally:
            if session.exists():
                (session / 'STOP').touch()

    worker = threading.Thread(target=client)
    worker.start()
    reader_module.serve(SimpleNamespace(pid=os.getpid(), expected_exe=executable,
                                       session_dir=session, allow_data=True,
                                       minutes=0.1, max_mib=1))
    worker.join(timeout=2)
    assert not worker.is_alive() and not failures
    reply = json.loads((session / 'result-000001.json').read_text())
    assert reply['status'] == 'complete'
    assert bytes.fromhex(reply['ranges'][0]['hex']) == buffer.raw
    assert json.loads((session / 'ended.json').read_text())['status'] == 'stopped'
