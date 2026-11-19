"""Regression for Tiger's direct uint32-to-sockaddr relay address copy."""
import socket
import struct

import marathon_server
from marathon_protobuf import ProtobufReader


def test_signon_relay_becomes_loopback_sockaddr(monkeypatch):
    monkeypatch.setattr(marathon_server, 'server_log', lambda message: None)
    server = marathon_server.MarathonServer(bap_port=7505)
    status, response = server.handle_signon_request(b'')
    assert status == 200
    top = {tag: value for tag, wire, value in ProtobufReader(response).parse()}
    success = {tag: value for tag, wire, value in ProtobufReader(top[2]).parse()}
    address_bytes = struct.pack('<I', success[6])
    assert address_bytes == socket.inet_aton('127.0.0.1')
    assert socket.inet_ntoa(address_bytes) == '127.0.0.1'
    assert success[7] == 7505
