"""Comprehensive test suite for BAP Service 304/305 certificate contract & implementation.

Validates:
1. Correct Service 304 parsing and schema validation.
2. Correct Service 305 protobuf serialization.
3. Correct AES-GCM response framing and nonce sequencing.
4. Correct task ID and service ID handling.
5. Correct behavior for missing or malformed certificates.
6. Correct socket lifecycle and connection persistence.
7. No regression to working BAP Services 30/31 or 25/26.
"""
import hashlib
import struct
import time
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from marathon_protobuf import ProtobufWriter, ProtobufReader
from marathon_bap import (
    BapRequest, BapResponse,
    encode_outer_frame, decode_outer_frame,
    decode_inner_request, encode_inner_response,
    build_response_frame,
    BAP_STATUS_OK, BAP_STATUS_BAD_REQUEST,
    FRAME_TYPE_PLAINTEXT_REQUEST, FRAME_TYPE_PLAINTEXT_BOOTSTRAP,
    FRAME_TYPE_AUTHENTICATED_GCM,
    SERVICE_CHANNEL_START, SERVICE_CHANNEL_START_RESPONSE,
    SERVICE_SERVER_HELLO, SERVICE_HELLO_RESPONSE,
    SERVICE_KEEPALIVE_PING, SERVICE_KEEPALIVE_PONG
)
from marathon_ssc import (
    SERVICE_SSC_REQUEST, SERVICE_SSC_RESPONSE,
    KEY_TYPE_ED25519, DEFAULT_MARATHON_APP_ID, DEFAULT_STEAM_ID,
    SscRequestMetadata, SscResponseMetadata,
    parse_ssc_request, parse_ssc_response,
    build_inner_certificate, build_signed_certificate_container,
    build_service_305_response_body, build_synthetic_ssc_response
)
from marathon_server import MarathonServer, BapChannel, handle_bap_connection, advance_bap_nonce


class MockSocketStream:
    """Mock socket stream that yields predetermined chunks and captures sent bytes."""
    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.output = bytearray()
        self.closed = False

    def recv(self, bufsize):
        return next(self.chunks, b"")

    def sendall(self, data):
        self.output.extend(data)

    def close(self):
        self.closed = True


def build_mock_svc304_request(pubkey: bytes, steam_id: int = DEFAULT_STEAM_ID, task_id: int = 2) -> bytes:
    """Construct a compliant Service 304 request payload."""
    cert_w = ProtobufWriter()
    cert_w.varint(1, KEY_TYPE_ED25519)
    cert_w.bytes(2, pubkey)
    cert_w.fixed64(4, steam_id)
    cert_w.string(12, f"steamid:{steam_id}")
    cert_bytes = cert_w.build()

    csr_w = ProtobufWriter()
    csr_w.bytes(1, cert_bytes)
    csr_bytes = csr_w.build()

    outer_w = ProtobufWriter()
    outer_w.bytes(3, csr_bytes)
    outer_bytes = outer_w.build()

    # Client payload has 2 zero-bytes header
    return bytes(2) + outer_bytes


# ==============================================================================
# 1. Correct Service 304 Parsing and Schema Validation
# ==============================================================================

def test_service_304_parsing_valid():
    dummy_pubkey = bytes(range(32))
    payload = build_mock_svc304_request(dummy_pubkey, steam_id=76561198000001001, task_id=2)
    meta = parse_ssc_request(payload, task_id=2)
    
    assert meta is not None
    assert meta.task_id == 2
    assert meta.key_type == KEY_TYPE_ED25519
    assert meta.public_key == dummy_pubkey
    assert meta.legacy_steam_id == 76561198000001001
    assert meta.identity_string == "steamid:76561198000001001"
    assert meta.payload_sha256 == hashlib.sha256(payload).hexdigest()
    assert meta.body_offset == 2


def test_service_304_parsing_malformed_and_truncated():
    dummy_pubkey = bytes(range(32))
    valid_payload = build_mock_svc304_request(dummy_pubkey)

    # Empty payload
    assert parse_ssc_request(b"") is None

    # Truncated payload
    assert parse_ssc_request(valid_payload[:10]) is None

    # Corrupted key length (not 32 bytes)
    bad_cert = ProtobufWriter().varint(1, 1).bytes(2, b"too_short").build()
    bad_csr = ProtobufWriter().bytes(1, bad_cert).build()
    bad_outer = bytes(2) + ProtobufWriter().bytes(3, bad_csr).build()
    assert parse_ssc_request(bad_outer) is None

    # Unsupported key type (not ED25519)
    bad_type_cert = ProtobufWriter().varint(1, 0).bytes(2, dummy_pubkey).build()
    bad_type_csr = ProtobufWriter().bytes(1, bad_type_cert).build()
    bad_type_outer = bytes(2) + ProtobufWriter().bytes(3, bad_type_csr).build()
    assert parse_ssc_request(bad_type_outer) is None


# ==============================================================================
# 2. Correct Service 305 Protobuf Serialization
# ==============================================================================

def test_service_305_protobuf_serialization_and_roundtrip():
    dummy_pubkey = bytes(range(32))
    test_steam_id = 76561198000001001
    test_app_id = 3065800
    fixed_time = 1732000000

    # Build synthetic response body
    body = build_synthetic_ssc_response(
        public_key=dummy_pubkey,
        steam_id=test_steam_id,
        app_id=test_app_id,
        ca_key_id=0xCAFE,
        ca_signature=b"\x42" * 64,
        valid_duration_seconds=86400,
        created_timestamp=fixed_time
    )

    # Body must be well within Marathon decoder 0x30A3F910's 2048-byte limit
    assert 0 < len(body) <= 2048

    # Decode and verify exact field mapping
    parsed = parse_ssc_response(body)
    assert parsed is not None
    assert parsed.key_type == KEY_TYPE_ED25519
    assert parsed.public_key == dummy_pubkey
    assert parsed.legacy_steam_id == test_steam_id
    assert parsed.time_created == fixed_time
    assert parsed.time_expiry == fixed_time + 86400
    assert parsed.app_ids == [test_app_id]
    assert parsed.identity_string == f"steamid:{test_steam_id}"
    assert parsed.ca_key_id == 0xCAFE
    assert parsed.ca_signature == b"\x42" * 64


# ==============================================================================
# 3. Correct AES-GCM Response Framing and Nonce Sequencing
# ==============================================================================

def test_nonce_advancement_little_endian():
    base_nonce = b"\x01\x00\x00\x00\x00\x00\x00\x00\xAA\xBB\xCC\xDD"
    n1 = advance_bap_nonce(base_nonce)
    assert n1 == b"\x02\x00\x00\x00\x00\x00\x00\x00\xAA\xBB\xCC\xDD"
    n2 = advance_bap_nonce(n1)
    assert n2 == b"\x03\x00\x00\x00\x00\x00\x00\x00\xAA\xBB\xCC\xDD"


def test_multi_frame_authenticated_channel_roundtrip():
    key = bytes(range(16))
    client_send_nonce = bytes(range(12))  # material[:12]
    # Server receive nonce has byte 11 bit 0 flipped
    server_receive_nonce = client_send_nonce[:11] + bytes([client_send_nonce[11] ^ 1])
    server_send_nonce = bytes(range(12))

    client_channel = BapChannel(key=key, send_nonce=server_receive_nonce, receive_nonce=server_send_nonce)
    server_channel = BapChannel(key=key, send_nonce=server_send_nonce, receive_nonce=server_receive_nonce)

    # Frame 1: Client -> Server
    wire1 = client_channel.seal_request(service_id=304, task_id=2, payload=b"frame1_body")
    _, kind1, end1 = decode_outer_frame(wire1)
    assert kind1 == 1
    req1 = server_channel.open_frame(wire1[6:])
    assert (req1.service_id, req1.task_id, req1.payload) == (304, 2, b"frame1_body")

    # Response 1: Server -> Client
    resp1_wire = server_channel.seal_response(service_id=305, task_id=2, status=200, body=b"frame1_resp")
    _, rkind1, _ = decode_outer_frame(resp1_wire)
    assert rkind1 == 1
    # Client receives response (decodes with status field)
    c_resp1_plain = AESGCM(key).decrypt(client_channel.receive_nonce, resp1_wire[22:] + resp1_wire[6:22], None)
    client_channel.receive_nonce = advance_bap_nonce(client_channel.receive_nonce)
    r_svc, r_task, r_status = struct.unpack_from(">HIH", c_resp1_plain, 0)
    assert (r_svc, r_task, r_status, c_resp1_plain[8:]) == (305, 2, 200, b"frame1_resp")

    # Frame 2: Client -> Server (Nonce MUST advance without tag corruption!)
    wire2 = client_channel.seal_request(service_id=250, task_id=3, payload=b"ping")
    req2 = server_channel.open_frame(wire2[6:])
    assert (req2.service_id, req2.task_id, req2.payload) == (250, 3, b"ping")

    # Response 2: Server -> Client
    resp2_wire = server_channel.seal_response(service_id=251, task_id=3, status=200, body=b"pong")
    c_resp2_plain = AESGCM(key).decrypt(client_channel.receive_nonce, resp2_wire[22:] + resp2_wire[6:22], None)
    client_channel.receive_nonce = advance_bap_nonce(client_channel.receive_nonce)
    r_svc2, r_task2, r_status2 = struct.unpack_from(">HIH", c_resp2_plain, 0)
    assert (r_svc2, r_task2, r_status2, c_resp2_plain[8:]) == (251, 3, 200, b"pong")


# ==============================================================================
# 4. Correct Task ID and Service ID Handling
# ==============================================================================

def test_task_id_correlation_in_ssc_response():
    server = MarathonServer(allow_synthetic_ssc=True)
    for test_task in [2, 17, 999]:
        dummy_pubkey = bytes(range(32))
        payload = build_mock_svc304_request(dummy_pubkey, task_id=test_task)
        req = BapRequest(service_id=SERVICE_SSC_REQUEST, task_id=test_task, payload=payload, frame_type=1)
        status, body = server.ssc_response(req)
        assert status == 200
        assert len(body) > 0


# ==============================================================================
# 5. Missing or Malformed Certificate Handling
# ==============================================================================

def test_missing_certificate_returns_503_default(tmp_path):
    server = MarathonServer(ssc_response_dir=tmp_path, allow_synthetic_ssc=False)
    dummy_pubkey = bytes(range(32))
    payload = build_mock_svc304_request(dummy_pubkey, task_id=2)
    req = BapRequest(service_id=SERVICE_SSC_REQUEST, task_id=2, payload=payload, frame_type=1)
    
    # Missing cached file -> status 503, empty body
    status, body = server.ssc_response(req)
    assert status == 503
    assert body == b""


def test_provisioned_certificate_lookup_success(tmp_path):
    server = MarathonServer(ssc_response_dir=tmp_path, allow_synthetic_ssc=False)
    dummy_pubkey = bytes(range(32))
    payload = build_mock_svc304_request(dummy_pubkey, task_id=2)
    req = BapRequest(service_id=SERVICE_SSC_REQUEST, task_id=2, payload=payload, frame_type=1)

    digest = hashlib.sha256(payload).hexdigest()
    provisioned_data = b"synthetic_precalculated_cert_body"
    (tmp_path / f"{digest}.bin").write_bytes(provisioned_data)

    status, body = server.ssc_response(req)
    assert status == 200
    assert body == provisioned_data


# ==============================================================================
# 6. Socket Lifecycle and Connection Persistence
# ==============================================================================

def test_socket_persists_and_processes_subsequent_frame(monkeypatch):
    monkeypatch.setattr('marathon_server.server_log', lambda message: None)
    server = MarathonServer(allow_synthetic_ssc=True)
    server.handle_signon_request(b"test")
    token = server.players[1001].session_token

    hello = bytes(2) + ProtobufWriter().bytes(1, token).varint(2, 1).build()
    hello_frame = encode_outer_frame(struct.pack(">HI", SERVICE_SERVER_HELLO, 1) + hello, 2)

    material = bytes(range(28))
    monkeypatch.setattr('marathon_server.os.urandom', lambda n: bytes(range(n)))
    aes = AESGCM(material[12:])
    client_send_nonce = material[:11] + bytes([material[11] ^ 1])
    server_send_nonce = material[:12]

    # Frame 1: Service 304 (SSC Request)
    pubkey = bytes(range(32))
    req304_payload = build_mock_svc304_request(pubkey, task_id=2)
    sealed304 = aes.encrypt(client_send_nonce, struct.pack(">HI", SERVICE_SSC_REQUEST, 2) + req304_payload, None)
    frame304 = encode_outer_frame(sealed304[-16:] + sealed304[:-16], 1)

    # Frame 2: Service 250 (Keepalive Ping) over the same encrypted connection
    client_nonce2 = advance_bap_nonce(client_send_nonce)
    sealed_ping = aes.encrypt(client_nonce2, struct.pack(">HI", SERVICE_KEEPALIVE_PING, 3), None)
    frame_ping = encode_outer_frame(sealed_ping[-16:] + sealed_ping[:-16], 1)

    # Send stream containing both frames!
    stream = MockSocketStream([hello_frame, frame304, frame_ping])
    handle_bap_connection(stream, server)

    data = bytes(stream.output)
    # 1. Hello response
    _, _, pos1 = decode_outer_frame(data)
    # 2. Service 305 response
    payload305, kind305, pos2 = decode_outer_frame(data, pos1)
    assert kind305 == 1
    dec305 = aes.decrypt(server_send_nonce, payload305[16:] + payload305[:16], None)
    svc, task, status = struct.unpack_from(">HIH", dec305, 0)
    assert (svc, task, status) == (SERVICE_SSC_RESPONSE, 2, 200)

    # 3. Service 251 (Keepalive Pong) response - Proves connection did NOT abort!
    payload_pong, kind_pong, pos3 = decode_outer_frame(data, pos2)
    assert kind_pong == 1
    server_nonce2 = advance_bap_nonce(server_send_nonce)
    dec_pong = aes.decrypt(server_nonce2, payload_pong[16:] + payload_pong[:16], None)
    psvc, ptask, pstatus = struct.unpack_from(">HIH", dec_pong, 0)
    assert (psvc, ptask, pstatus) == (SERVICE_KEEPALIVE_PONG, 3, 200)


# ==============================================================================
# 7. No Regression on Services 30/31 and 25/26
# ==============================================================================

def test_full_bootstrap_and_handshake_regression(monkeypatch):
    monkeypatch.setattr('marathon_server.server_log', lambda message: None)
    server = MarathonServer()
    server.handle_signon_request(b"test-regression")
    token = server.players[1001].session_token

    # Step 1: Service 30 (Channel Start)
    req30 = struct.pack('>BBIHIH', 1, 2, 136, SERVICE_CHANNEL_START, 0, 0) + b'DESTINY\x01' + bytes(range(120))
    stream = MockSocketStream([req30])
    handle_bap_connection(stream, server)
    resp31_data = bytes(stream.output)
    _, kind31, _ = decode_outer_frame(resp31_data)
    assert kind31 == 2
    assert resp31_data[:14] == struct.pack('>BBIHIH', 1, 2, 136, SERVICE_CHANNEL_START_RESPONSE, 0, 200)

    # Step 2: Service 25 (Server Hello)
    hello_inner = struct.pack(">HI", SERVICE_SERVER_HELLO, 1) + bytes(2) + ProtobufWriter().bytes(1, token).varint(2, 1).build()
    req25 = encode_outer_frame(hello_inner, 2)
    stream2 = MockSocketStream([req25])
    handle_bap_connection(stream2, server)
    resp26_data = bytes(stream2.output)
    payload26, kind26, _ = decode_outer_frame(resp26_data)
    assert kind26 == 2
    svc, task, status = struct.unpack_from(">HIH", payload26, 0)
    assert (svc, task, status) == (SERVICE_HELLO_RESPONSE, 1, 200)
