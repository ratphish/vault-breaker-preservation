"""Tests use temporary fixtures and loopback HTTP only; no game required."""
import hashlib
import http.client
from contextlib import contextmanager
from pathlib import Path
import threading

import pytest

from direct_settings import load_settings
from marathon_server import SignOnHTTPHandler, ThreadedHTTPServer
from marathon_server import MarathonServer
from marathon_protobuf import ProtobufReader


@contextmanager
def settings_http(directory):
    server = ThreadedHTTPServer(('127.0.0.1', 0), SignOnHTTPHandler,
                                direct_settings_dir=directory)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def test_explicit_source_and_verbatim_bytes(tmp_path, monkeypatch):
    selected = tmp_path / 'selected'
    selected.mkdir()
    body = b'{ "marker": "selected" }\n'
    (selected / 'global.json').write_bytes(body)
    shadow = tmp_path / 'config' / 'direct_settings'
    shadow.mkdir(parents=True)
    (shadow / 'global.json').write_text('{"marker":"wrong"}')
    monkeypatch.chdir(tmp_path)
    result = load_settings('/cfg_a/direct_settings/global/global.json?test=1', selected)
    assert result.status == 200 and result.body == body
    assert Path(result.source) == selected / 'global.json'
    assert result.sha256 == hashlib.sha256(body).hexdigest()
    assert load_settings('/cfg_a/direct_settings/global/missing.json', selected).status == 404


@pytest.mark.parametrize('body', [b'{', b'{"x":1,"x":2}', b'{"x":NaN}', b'\xff'])
def test_invalid_json_is_not_replaced_by_empty_success(tmp_path, body):
    (tmp_path / 'global.json').write_bytes(body)
    result = load_settings('/cfg_a/direct_settings/global/global.json', tmp_path)
    assert result.status == 500
    assert b'invalid_json' in result.body


@pytest.mark.parametrize('path', ['/cfg_a/../global.json', '/cfg_a/%2e%2e/global.json',
                                  '/cfg_a/a%5cglobal.json', '/cfg_a/a//global.json'])
def test_ambiguous_paths_rejected(tmp_path, path):
    assert load_settings(path, tmp_path).status == 400


def test_query_string_cannot_route_unrelated_endpoint(tmp_path):
    assert load_settings('/unrelated?next=direct_settings/global.json', tmp_path) is None


def test_signon_serves_bootstrap_token_and_settings_urls():
    status, payload = MarathonServer().handle_signon_request(b'')
    assert status == 200
    root = {field: value for field, wire, value in ProtobufReader(payload).parse()}
    common = {field: value for field, wire, value in ProtobufReader(root[4]).parse()}
    candidate = Path(__file__).resolve().parents[1] / 'config' / 'bootstrap_token.bin'
    if candidate.is_file():
        from signon_bootstrap import DIRECT_SETTINGS_MANIFEST_SUFFIX, DIRECT_SETTINGS_URLS, load_bootstrap_token, encode_bootstrap_entry
        assert common.get(3) == encode_bootstrap_entry(
            load_bootstrap_token(candidate), DIRECT_SETTINGS_URLS, DIRECT_SETTINGS_MANIFEST_SUFFIX
        )
    else:
        assert 3 not in common
    success = {field: value for field, wire, value in ProtobufReader(root[2]).parse()}
    assert [success[field] for field in (14, 15, 16)] == [
        b'http://manifest.goliath.deadorbit.net/GolRetail',
        b'http://manifest.goliath.deadorbit.net/GolRetail',
        b'http://manifest.goliath.deadorbit.net/GolRetail']


def test_http_head_matches_get_and_missing_is_404(tmp_path):
    body = b'{"transport_fixture":true}\n'  # A fixture, not a Tiger schema claim.
    (tmp_path / 'global.json').write_bytes(body)
    with settings_http(tmp_path) as port:
        for method in ('GET', 'HEAD'):
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                # Query text must not accidentally select the SDR endpoint.
                conn.request(method, '/cfg_a/direct_settings/global/global.json?GetSDRConfig=1')
                response = conn.getresponse()
                assert response.status == 200
                assert response.getheader('Content-Length') == str(len(body))
                assert response.getheader('X-Direct-Settings-SHA256') == hashlib.sha256(body).hexdigest()
                assert response.read() == (body if method == 'GET' else b'')
            finally:
                conn.close()
        for method in ('GET', 'HEAD'):
            conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
            try:
                conn.request(method, '/cfg_a/direct_settings/global/missing.json')
                response = conn.getresponse()
                assert response.status == 404
                response.read()
            finally:
                conn.close()


@pytest.mark.parametrize('document,name,length,digest', [
    ('manifest', '95EA841F43B4E9D27C957EC7427894B5C6BA035F.json', 3226,
     '98b787e573f90db3edc9510da559a46c75bd041671b160e675fa2e028eeff276'),
    ('global', '756CC4AF0A45C7A02300FCDFDED5A05628D2CA1A.json', 2907,
     '916a92b5028f696833b7e233dda8af756d36d921704f2cbe88d39879ec4fb869'),
])
def test_captured_retail_settings_replay(document, name, length, digest):
    directory = Path(__file__).resolve().parents[1] / 'config' / 'direct_settings'
    with settings_http(directory) as port:
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        try:
            conn.request('GET', f'/GolRetail/direct_settings/{document}/{name}')
            response = conn.getresponse()
            body = response.read()
            assert response.status == 200
            assert response.getheader('Content-Type') == 'application/json'
            assert len(body) == length
            assert hashlib.sha256(body).hexdigest() == digest
        finally:
            conn.close()
