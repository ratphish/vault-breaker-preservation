"""Bounded capture controls with fake process reads; never access a game."""
import hashlib
from types import SimpleNamespace

import capture_http_state as snapshot


PINNED = 'd5c2fb538f4020a71060b553127259fcd5d3131beb89a4ec26a7d6ccfa9dfbfd'


def setup_capture(monkeypatch, tmp_path, digest=PINNED, fail_read=False):
    executable = tmp_path / 'Marathon.exe'
    executable.write_bytes(b'fixture')
    reads = []
    closed = []

    class Process:
        def __init__(self, pid):
            self.handle = 1
            self.k = SimpleNamespace(QueryFullProcessImageNameW=self.image_name,
                                     GetExitCodeProcess=self.exit_code)

        def image_name(self, handle, flags, path, length):
            path.value = str(executable)
            return True

        def exit_code(self, handle, code):
            code._obj.value = 259
            return True

        def modules(self):
            return [{'path': str(executable), 'base': '0x140000000', 'size': 0x39d3e000}]

        def read(self, address, length):
            reads.append((address, length))
            if fail_read:
                raise OSError('fixture read failed')
            return b'\x90' * length

        def close(self):
            closed.append(True)

        @staticmethod
        def check(result):
            assert result

    monkeypatch.setattr(snapshot, 'Process', Process)
    monkeypatch.setattr(snapshot, 'PEImports', lambda path: SimpleNamespace(rows=lambda: [], close=lambda: None))
    monkeypatch.setattr(snapshot.hashlib, 'file_digest', lambda stream, algorithm: SimpleNamespace(hexdigest=lambda: digest))
    return executable, reads, closed


def test_http_code_reads_exact_pinned_ranges(monkeypatch, tmp_path):
    executable, reads, closed = setup_capture(monkeypatch, tmp_path)
    report = snapshot.capture(123, executable, False, True)
    assert report['status'] == 'complete'
    assert reads == [(0x140000000 + rva, size) for _, rva, size in snapshot.HTTP_CODE_RANGES]
    assert sum(size for _, size in reads) == 0x44100
    assert 'protected_context' not in report
    for row in report['http_code']:
        data = bytes.fromhex(row['hex'])
        assert len(data) == row['bytes']
        assert hashlib.sha256(data).hexdigest() == row['sha256']
    assert closed == [True]


def test_http_code_refuses_wrong_executable_hash(monkeypatch, tmp_path):
    executable, reads, closed = setup_capture(monkeypatch, tmp_path, digest='0' * 64)
    report = snapshot.capture(123, executable, False, True)
    assert report['status'] == 'failed'
    assert reads == []
    assert 'http_code' not in report
    assert closed == [True]


def test_http_code_preserves_partial_read_errors(monkeypatch, tmp_path):
    executable, reads, closed = setup_capture(monkeypatch, tmp_path, fail_read=True)
    report = snapshot.capture(123, executable, False, True)
    assert report['status'] == 'complete_with_errors'
    assert len(reads) == len(snapshot.HTTP_CODE_RANGES)
    assert len(report['errors']) == len(snapshot.HTTP_CODE_RANGES)
    assert report['http_code'] == []
    assert closed == [True]


def test_callback_capture_reads_only_callback_window(monkeypatch, tmp_path):
    executable, reads, closed = setup_capture(monkeypatch, tmp_path)
    report = snapshot.capture(123, executable, False, False, True)
    assert report['status'] == 'complete'
    assert reads == [(0x140000000 + 0x30618000, 0x6000)]
    assert [row['label'] for row in report['http_code']] == ['winhttp_native_callback']
    assert closed == [True]


def test_callback_stub_capture_is_bounded_and_separate(monkeypatch, tmp_path):
    executable, reads, closed = setup_capture(monkeypatch, tmp_path)
    report = snapshot.capture(123, executable, False, False, False, True)
    assert report['status'] == 'complete'
    assert len(reads) == 21
    assert sum(size for _, size in reads) == 84 * 1024
    assert reads == [(0x140000000 + rva, 4096) for rva in snapshot.CALLBACK_STUB_PAGES]
    assert closed == [True]


def test_explicit_code_page_reads_exact_aligned_page(monkeypatch, tmp_path):
    executable, reads, closed = setup_capture(monkeypatch, tmp_path)
    report = snapshot.capture(123, executable, False, code_pages=[0x1000])
    assert report['status'] == 'complete'
    assert reads == [(0x140001000, 4096)]
    assert closed == [True]


def test_explicit_code_page_rejects_unaligned_or_outside_image(monkeypatch, tmp_path):
    for pages in [[1], [-4096], [0x39d3e000], [0x1000] * 17]:
        executable, reads, closed = setup_capture(monkeypatch, tmp_path)
        report = snapshot.capture(123, executable, False, code_pages=pages)
        assert report['status'] == 'failed'
        assert reads == []
        assert closed == [True]
