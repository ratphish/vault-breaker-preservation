"""Offline regression for Marathon's captured 30 -> 31 startup envelope."""
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from marathon_bap import decode_outer_frame, decode_inner_request
from marathon_server import MarathonServer, handle_bap_connection

class Stream:
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.output = bytearray()
        self.closed = False
    def recv(self, size):
        return next(self.chunks, b'')
    def sendall(self, data):
        self.output.extend(data)
    def close(self):
        self.closed = True

def request():
    return struct.pack('>BBIHIH', 1, 2, 136, 30, 0, 0) + b'DESTINY\x01' + bytes(range(120))

def test_fragmented_startup_response(monkeypatch):
    monkeypatch.setattr('marathon_server.server_log', lambda message: None)
    packet = request()
    stream = Stream([packet[:3], packet[3:11], packet[11:]])
    handle_bap_connection(stream, MarathonServer())
    response = bytes(stream.output)
    assert stream.closed
    assert len(response) == 142
    assert response[:14] == struct.pack('>BBIHIH', 1, 2, 136, 31, 0, 200)
    assert response[14:22] == b'DESTINY\x01'
    assert len(response[22:]) == 120

def test_reject_wrong_type_length_or_marker():
    inner, kind, _ = decode_outer_frame(request())
    server = MarathonServer()
    for body, frame_type in [(inner, 0), (inner[:-1], kind), (inner[:8] + bytes(128), kind)]:
        response = server.dispatch_bap_request(decode_inner_request(body, frame_type))
        assert response.status == 400
        assert response.frame_type == 2
        assert response.payload == b''

def test_first_encrypted_request_uses_connection_hello():
    import hmac
    import pytest
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from marathon_server import BapChannel
    from marathon_protobuf import ProtobufWriter

    server = MarathonServer()
    server.handle_signon_request(b"offline-test")
    player = server.players[1001]
    hello = bytes(2) + ProtobufWriter().bytes(1, player.session_token).varint(2, 1).build()
    channel = BapChannel()
    response = server.dispatch_bap_request(decode_inner_request(struct.pack(">HI", 25, 1) + hello, 2),
                                           channel=channel)
    body = response.payload
    assert hmac.compare_digest(body[52:], hmac.digest(player.auth_key, body[:52], "sha256"))
    decrypt = Cipher(algorithms.AES(player.encryption_key), modes.CBC(body[4:20])).decryptor()
    raw = decrypt.update(body[20:52]) + decrypt.finalize()
    nonce = bytearray(raw[:12])
    nonce[-1] ^= 1
    plaintext = struct.pack(">HI", 123, 47) + bytes(47)
    sealed = AESGCM(raw[12:28]).encrypt(bytes(nonce), plaintext, None)
    wire = sealed[-16:] + sealed[:-16]
    assert len(wire) == 69
    opened = channel.open_first_frame(wire)
    assert (opened.service_id, opened.task_id, opened.payload) == (123, 47, bytes(47))
    with pytest.raises(InvalidTag):
        channel.open_first_frame(bytes([wire[0] ^ 1]) + wire[1:])

def test_encrypted_ssc_reply_on_socket_path(tmp_path, monkeypatch):
    import hashlib
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from marathon_protobuf import ProtobufWriter
    from marathon_bap import encode_outer_frame

    monkeypatch.setattr('marathon_server.server_log', lambda message: None)
    server = MarathonServer(ssc_response_dir=tmp_path)
    server.handle_signon_request(b"test")
    token = server.players[1001].session_token
    hello = bytes(2) + ProtobufWriter().bytes(1, token).varint(2, 1).build()
    hello_frame = encode_outer_frame(struct.pack(">HI", 25, 1) + hello, 2)
    material = bytes(range(28))
    monkeypatch.setattr('marathon_server.os.urandom', lambda n: bytes(range(n)))
    aes = AESGCM(material[12:])
    nonce = material[:12]
    request_body = bytes(47)
    sealed = aes.encrypt(nonce[:11] + bytes([nonce[11] ^ 1]),
                         struct.pack(">HI", 304, 2) + request_body, None)
    request_frame = encode_outer_frame(sealed[-16:] + sealed[:-16], 1)
    fixture = tmp_path / (hashlib.sha256(request_body).hexdigest() + '.bin')
    for status, body in [(503, b''), (200, b'test-encoded-body')]:
        if body:
            fixture.write_bytes(body)
        stream = Stream([hello_frame, request_frame])
        handle_bap_connection(stream, server)
        data = bytes(stream.output)
        _, _, pos = decode_outer_frame(data)
        reply, kind, end = decode_outer_frame(data, pos)
        assert kind == 1 and end == len(data)
        assert aes.decrypt(nonce, reply[16:] + reply[:16], None) == struct.pack(">HIH", 305, 2, status) + body
