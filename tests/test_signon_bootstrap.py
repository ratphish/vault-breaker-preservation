"""Bootstrap wire compatibility; no process access, launches or network."""
import pytest

import marathon_server as module
from marathon_protobuf import ProtobufReader
from signon_bootstrap import encode_bootstrap_entry, load_bootstrap_token


def common_info(payload):
    top = dict((n, value) for n, wire, value in ProtobufReader(payload).parse())
    return dict((n, value) for n, wire, value in ProtobufReader(top[4]).parse())


def test_matches_shipped_dawn_writer_config_key_fixture():
    # Extracted from probe_dawn_signon_writer.run_writer(..., config_key=True)
    # with its synthetic bytes(range(16)); contains no captured native secret.
    expected = bytes.fromhex('563412000f627b0010000102030405060708090a0b0c0d0e0f00000000')
    assert encode_bootstrap_entry(bytes(range(16))) == expected


def test_entry_default_and_explicit_occupies_common_info_field_three(monkeypatch):
    monkeypatch.setattr(module, 'server_log', lambda message: None)
    token = bytes(range(16))
    candidate = module.Path(__file__).resolve().parents[1] / 'config' / 'bootstrap_token.bin'
    default = common_info(module.MarathonServer().handle_signon_request(b'')[1])
    enabled = common_info(module.MarathonServer(bootstrap_token=token).handle_signon_request(b'')[1])
    urls_record = bytes.fromhex('431e4a00') + 3 * (b'\x2fhttp://manifest.goliath.deadorbit.net/GolRetail')
    suffix_record = bytes.fromhex('edd6710047') + (
        b'/direct_settings/manifest/95EA841F43B4E9D27C957EC7427894B5C6BA035F.json'
    )
    def expected_stream(value):
        url = b'http://127.0.0.1/GolRetail/content_manifest/content_manifest.pb'
        manifest_record = bytes.fromhex('64000000') + bytes([len(url)]) + url
        guid_record = bytes.fromhex('6500000024') + b'f5e5c169-9ebc-42c9-b4fb-d6b234c097a0'
        return (bytes.fromhex('563412000f627b0010') + value + urls_record + suffix_record
                + manifest_record + guid_record + bytes(4))
    if candidate.is_file():
        assert default == {1: 1, 2: 1, 3: expected_stream(load_bootstrap_token(candidate))}
    else:
        assert default == {1: 1, 2: 1}
    assert enabled == {1: 1, 2: 1, 3: expected_stream(token)}


def test_entry_omitted_when_default_token_file_absent(monkeypatch):
    monkeypatch.setattr(module, 'server_log', lambda message: None)
    monkeypatch.setattr(module.Path, 'is_file', lambda self: False)
    default = common_info(module.MarathonServer().handle_signon_request(b'')[1])
    assert default == {1: 1, 2: 1}


@pytest.mark.parametrize('token', [b'', bytes(15), bytes(17), '0123456789abcdef'])
def test_rejects_wrong_token_length_or_type(token):
    with pytest.raises(ValueError, match='exactly 16 bytes'):
        module.MarathonServer(bootstrap_token=token)


def test_file_requires_raw_sixteen_bytes(tmp_path):
    path = tmp_path / 'native.bin'
    token = bytes(range(16))
    path.write_bytes(token)
    assert load_bootstrap_token(path) == token
    path.write_text(token.hex())
    with pytest.raises(ValueError, match='16 raw bytes'):
        load_bootstrap_token(path)
