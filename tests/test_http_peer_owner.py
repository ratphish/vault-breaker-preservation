import ipaddress
import os
import socket
import struct

import pytest

import http_peer_owner as owner


PEER = ("127.0.0.2", 51234)
LOCAL = ("127.0.0.1", 8080)


def row4(local=PEER, remote=LOCAL, pid=123, state=5):
    return (struct.pack("<I", state) + socket.inet_aton(local[0])
            + struct.pack("!H", local[1]) + b"\x00\x00" + socket.inet_aton(remote[0])
            + struct.pack("!H", remote[1]) + b"\x00\x00" + struct.pack("<I", pid))


def table(*rows):
    return struct.pack("<I", len(rows)) + b"".join(rows)


def test_reverse_tuple_and_network_port_order():
    snapshot = table(row4(LOCAL, PEER, 999), row4())
    assert owner.owner_from_table(snapshot, socket.AF_INET, PEER, LOCAL) == 123
    assert owner.owner_from_table(snapshot, socket.AF_INET, PEER, (LOCAL[0], 80)) is None


@pytest.mark.parametrize("snapshot", [b"", b"\x00", struct.pack("<I", 1),
                                       struct.pack("<I", 0xFFFFFFFF), table(row4())[:-1]])
def test_malformed_snapshot(snapshot):
    assert owner.owner_from_table(snapshot, socket.AF_INET, PEER, LOCAL) is None


def test_ambiguous_and_unowned_rows():
    assert owner.owner_from_table(table(row4(), row4(pid=456)), socket.AF_INET, PEER, LOCAL) is None
    assert owner.owner_from_table(table(row4(), row4()), socket.AF_INET, PEER, LOCAL) == 123
    for row in [row4(pid=0), row4(state=11), row4(state=2)]:
        assert owner.owner_from_table(table(row), socket.AF_INET, PEER, LOCAL) is None


@pytest.mark.parametrize("address", ["::1", "::ffff:127.0.0.1"])
def test_ipv6(address):
    packed = ipaddress.ip_address(address).packed
    row = (packed + struct.pack("<I", 0) + struct.pack("!H", 51234) + b"\x00\x00"
           + packed + struct.pack("<I", 0) + struct.pack("!H", 8080) + b"\x00\x00"
           + struct.pack("<II", 5, 321))
    peer, local = (address, 51234, 0, 0), (address, 8080, 0, 0)
    assert len(row) == 56
    assert owner.owner_from_table(table(row), socket.AF_INET6, peer, local) == 321
    assert owner.owner_from_table(table(row), socket.AF_INET6, peer, (address, 8080, 0, 1)) is None


def test_non_loopback_does_not_query_table(monkeypatch):
    class Connection:
        family = socket.AF_INET
        def getpeername(self): return ("192.0.2.1", 51234)
        def getsockname(self): return LOCAL
    def unexpected(family):
        pytest.fail("non-loopback must not query the native table")
    monkeypatch.setattr(owner, "_read_table", unexpected)
    assert owner.owner_for_connection(Connection()) is None


def test_socket_error_and_native_permission_failure(monkeypatch):
    class Connection:
        family = socket.AF_INET
        def getpeername(self): return PEER
        def getsockname(self): return LOCAL
    monkeypatch.setattr(owner, "_read_table", lambda family: None)
    assert owner.owner_for_connection(Connection()) is None
    def denied(family): raise PermissionError("unavailable")
    monkeypatch.setattr(owner, "_read_table", denied)
    assert owner.owner_for_connection(Connection()) is None
    monkeypatch.setattr(owner, "_read_table", lambda family: table(row4()))
    assert owner.owner_for_connection(Connection()) == 123
    with socket.socket() as closed:
        closed.close()
        assert owner.owner_for_connection(closed) is None


def test_native_reader_resize_and_failure_bounds(monkeypatch):
    calls = []
    payload = table(row4())
    def native(buffer, size, ordered, family, table_class, reserved):
        calls.append(buffer)
        assert not ordered and family == socket.AF_INET and table_class == 5 and reserved == 0
        if len(calls) == 1:
            size._obj.value = 4
            return 122
        if len(calls) == 2:
            size._obj.value = len(payload)
            return 122
        buffer.raw = payload
        return 0
    monkeypatch.setattr(owner, "_tcp_reader", lambda: native)
    assert owner._read_table(socket.AF_INET) == payload
    assert len(calls) == 3

    def denied(*args): return 5
    monkeypatch.setattr(owner, "_tcp_reader", lambda: denied)
    assert owner._read_table(socket.AF_INET) is None
    monkeypatch.setattr(owner, "_tcp_reader", lambda: None)
    assert owner._read_table(socket.AF_INET) is None

    def oversize(buffer, size, *args):
        size._obj.value = owner._MAX_TABLE_BYTES + 1
        return 122
    monkeypatch.setattr(owner, "_tcp_reader", lambda: oversize)
    assert owner._read_table(socket.AF_INET) is None

    retries = []
    def growing(buffer, size, *args):
        retries.append(1)
        size._obj.value = 4 + len(retries) * 24
        return 122
    monkeypatch.setattr(owner, "_tcp_reader", lambda: growing)
    assert owner._read_table(socket.AF_INET) is None
    assert len(retries) == 4  # Size query, then at most three allocation attempts.


@pytest.mark.skipif(os.name != "nt", reason="Windows TCP ownership API")
@pytest.mark.parametrize("family,host", [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")])
def test_own_process_loopback(family, host):
    # Only this test process opens two sockets; no subprocess or HTTP daemon.
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        try:
            listener.bind((host, 0))
        except OSError:
            if family == socket.AF_INET6:
                pytest.skip("IPv6 loopback unavailable")
            raise
        listener.listen(1)
        listener.settimeout(2)
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            client.connect(listener.getsockname())
            accepted, _ = listener.accept()
            with accepted:
                assert owner.owner_for_connection(accepted) == os.getpid()
