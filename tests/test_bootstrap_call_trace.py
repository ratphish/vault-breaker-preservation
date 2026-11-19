"""Offline controls; no game files, process access, or host APIs are executed."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

import pytest

pytest.importorskip('unicorn')
from trace_bootstrap_calls import CapturedCode


def fixture_code(tmp_path, instructions):
    data = bytearray(b'\xcc' * 256)
    data[:5] = b'\xe8' + struct.pack('<i', 0x1010 - 0x1005)
    data[16:16+len(instructions)] = instructions
    (tmp_path / 'code.bin').write_bytes(data)
    (tmp_path / 'capture-manifest.json').write_text(json.dumps({
        'status': 'complete', 'image_base': '0x140000000', 'image_size': '0x3000',
        'ranges': [{'file': 'code.bin', 'rva': '0x1000', 'bytes': len(data),
                    'sha256': hashlib.sha256(data).hexdigest()}]}))
    return CapturedCode(tmp_path)


def run_trace(tmp_path):
    # Keep Unicorn's native exception handling separate from pytest's Windows
    # faulthandler plugin. A native crash is still a nonzero subprocess failure.
    output = tmp_path / 'result.json'
    script = Path(__file__).resolve().parents[1] / 'scripts' / 'trace_bootstrap_calls.py'
    result = subprocess.run([sys.executable, str(script), '--capture', str(tmp_path),
                             '--call-rva', '0x1000', '--output', str(output)],
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(output.read_text())['traces'][0]


def test_push_ret_follows_computed_target(tmp_path):
    # lea rax,[rip+2]; push rax; ret; jmp next; int3
    fixture_code(tmp_path, bytes.fromhex('488d050200000050c3eb00cc'))
    result = run_trace(tmp_path)
    assert result['returns'] == [{'site_rva': '0x1018', 'target_rva': '0x1019'}]
    assert result['stop'] == {'kind': 'unmodeled_instruction', 'rva': '0x101b', 'instruction': 'int3'}
    assert result['runtime_observed'] is False


def test_conditional_to_fallthrough_needs_no_incoming_flags(tmp_path):
    fixture_code(tmp_path, bytes.fromhex('7500cc'))  # jne next; int3
    result = run_trace(tmp_path)
    assert result['stop'] == {'kind': 'unmodeled_instruction', 'rva': '0x1012', 'instruction': 'int3'}
    assert result['runtime_observed'] is False


def test_unknown_data_read_is_not_fabricated(tmp_path):
    fixture_code(tmp_path, b'\x48\xa1' + struct.pack('<Q', 0x5000000000))
    result = run_trace(tmp_path)
    assert result['stop']['kind'] == 'non_stack_memory_access'
    assert result['stop']['address'] == '0x5000000000'
    assert len(result['instructions']) == 1


def test_conditional_branch_requires_real_context(tmp_path):
    fixture_code(tmp_path, b'\x74\x01\xcc\xcc')  # Distinct taken/fallthrough successors.
    result = run_trace(tmp_path)
    assert result['stop']['kind'] == 'conditional_requires_context'
    assert not result['returns']


def test_changed_capture_rejected(tmp_path):
    fixture_code(tmp_path, b'\xcc')
    (tmp_path / 'code.bin').write_bytes(b'corrupted')
    with pytest.raises(ValueError, match='capture hash mismatch'):
        CapturedCode(tmp_path)
