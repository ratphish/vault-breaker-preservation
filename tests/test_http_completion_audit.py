import hashlib
import json
import struct

import pytest

from audit_http_completion import audit, PINNED_EXE_SHA256


BASE = 0x140000000
CONTEXT = BASE + 0x200000
HANDLE = 0x200001000


def row(address, data):
    return {'address': hex(address), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'hex': data.hex()}


def fixture_session(tmp_path, *, wrong_handle=False, wrong_route=False,
                    state=2, missing_eof=False, changing_count=False):
    (tmp_path / 'session.json').write_text(json.dumps({'pid': 7, 'image_base': hex(BASE),
                                                     'executable_sha256': PINNED_EXE_SHA256}))
    code = bytearray(4096)
    if not missing_eof:
        code[0xc1f:0xc29] = bytes.fromhex('c7805004000002000000')
    handle_record = bytearray(1024)
    struct.pack_into('<Q', handle_record, 0x40, CONTEXT)
    identity = struct.pack('<QQQQ', BASE + 4096, 0x200000000, HANDLE + int(wrong_handle), 0)
    body = b'\x08\x00\x12\x00'  # Zero error and empty success message; no secrets.
    fields = bytearray(88)
    struct.pack_into('<I', fields, 8, 527)
    struct.pack_into('<QQ', fields, 0x18, CONTEXT + 0x10490, 40960)
    struct.pack_into('<II', fields, 0x30, state, 200)
    struct.pack_into('<Q', fields, 0x48, len(body))
    repeat = bytearray(fields[0x30:0x54])
    if changing_count:
        struct.pack_into('<Q', repeat, 0x18, len(body) + 1)
    route = b'https://local/Other\0' if wrong_route else b'https://local/SignOn\0'
    records = {
        1: [row(BASE + 0x6333000, code)],
        5: [row(HANDLE, handle_record)],
        7: [row(CONTEXT, identity), row(CONTEXT + 0x420, fields)],
        8: [row(CONTEXT + 0x18, route), row(CONTEXT + 0x10490, body),
            row(CONTEXT, identity[:24]), row(CONTEXT + 0x450, repeat)],
    }
    for number, ranges in records.items():
        (tmp_path / f'result-{number:06d}.json').write_text(json.dumps({'pid': 7, 'status': 'complete', 'ranges': ranges}))


def test_completed_native_wrapper_does_not_claim_engine_acceptance(tmp_path):
    fixture_session(tmp_path)
    result = audit(tmp_path)
    assert result['native_http_completion_verified']
    assert result['received_bytes'] == 4
    assert not result['signon_acceptance_verified']
    assert not result['engine_result_publication_verified']
    assert not result['state8_root_cause_verified']


@pytest.mark.parametrize('variant', ['wrong_handle', 'wrong_route', 'missing_eof', 'changing_count'])
def test_rejects_unbound_or_incomplete_evidence(tmp_path, variant):
    fixture_session(tmp_path, **{variant: True})
    with pytest.raises(ValueError):
        audit(tmp_path)


def test_state_other_than_complete_is_not_accepted(tmp_path):
    fixture_session(tmp_path, state=1)
    with pytest.raises(ValueError, match='completed HTTP'):
        audit(tmp_path)


def test_tampered_saved_bytes_are_rejected(tmp_path):
    fixture_session(tmp_path)
    path = tmp_path / 'result-000008.json'
    data = json.loads(path.read_text())
    data['ranges'][1]['hex'] = '08011200'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='SHA-256'):
        audit(tmp_path)
