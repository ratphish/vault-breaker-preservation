"""Unit tests for Marathon Server Emulator (Project Dawn Architecture),
Protobuf codec, BAP framing, and Vault Breaker modding system.
"""
import struct
from marathon_protobuf import ProtobufWriter, ProtobufReader, encode_varint, decode_varint
from marathon_bap import (
    BapRequest, BapResponse, BapNotification,
    encode_outer_frame, decode_outer_frame,
    decode_inner_request, encode_inner_response, encode_server_notification,
    build_response_frame, build_notification_frame,
    BAP_STATUS_OK,
    SERVICE_ACTIVITY_SESSION_ALLOCATION, SERVICE_ACTIVITY_SESSION_RESPONSE,
    SERVICE_ACTIVITY_NOTIFICATION,
    SERVICE_ACTIVITY_HOST_ENDPOINT, SERVICE_ACTIVITY_HOST_RESPONSE,
    SERVICE_ACCOUNT_TRANSLATION, SERVICE_ACCOUNT_RESPONSE,
    SERVICE_SERVER_HELLO, SERVICE_HELLO_RESPONSE,
    SERVICE_CHANNEL_START, SERVICE_CHANNEL_START_RESPONSE,
    SERVICE_KEEPALIVE_PING, SERVICE_KEEPALIVE_PONG
)
from marathon_server import (
    MarathonServer, PlayerSession, ActivitySession,
    PB_TAG_ERROR, PB_TAG_SUCCESS, PB_TAG_COMMON_INFO,
    PB_SUB_ENCRYPTION_KEY, PB_SUB_SESSION_TOKEN, PB_COMMON_ID
)
from vault_breaker_mod import VaultBreakerModConfig

def test_protobuf_varint_codec():
    """Verify standard varint encoding and decoding."""
    test_cases = [0, 1, 127, 128, 300, 16384, 0xFFFFFFFF, 0x7FFFFFFFFFFFFFFF]
    for val in test_cases:
        enc = encode_varint(val)
        dec, pos = decode_varint(enc, 0)
        assert dec == val, f"Varint mismatch for {val}: got {dec}"
        assert pos == len(enc)

def test_protobuf_writer_reader_roundtrip():
    """Verify protobuf writer and reader on nested fields."""
    sub = ProtobufWriter()
    sub.varint(1, 42)
    sub.string(2, "CryoArchive")
    
    main = ProtobufWriter()
    main.varint(1, 0)
    main.message(2, sub)
    data = main.build()
    
    reader = ProtobufReader(data)
    fields = reader.parse()
    assert len(fields) == 2
    assert fields[0] == (1, 0, 0)
    assert fields[1][0] == 2
    
    # Parse sub-message
    sub_reader = ProtobufReader(fields[1][2])
    sub_fields = sub_reader.parse()
    assert sub_fields[0] == (1, 0, 42)
    assert sub_fields[1] == (2, 2, b"CryoArchive")

def test_bap_outer_inner_frame_codec():
    """Verify BAP outer frame and inner request/response encoding and decoding."""
    payload = b"\x11\x22\x33\x44"
    frame = build_response_frame(SERVICE_KEEPALIVE_PONG, task_id=105,
                                 status=BAP_STATUS_OK, payload=payload)
    
    # Outer decode
    dec_payload, frame_type, new_pos = decode_outer_frame(frame)
    assert dec_payload is not None
    assert frame_type == 0
    assert new_pos == len(frame)
    
    # Inner decode
    svc, task, status = struct.unpack_from(">HIH", dec_payload, 0)
    assert svc == SERVICE_KEEPALIVE_PONG
    assert task == 105
    assert status == 200
    assert dec_payload[8:] == payload

def test_bap_server_notification_format():
    """Verify that BAP notifications contain NO status field (preventing body shift)."""
    payload = b"event_payload"
    notif_frame = build_notification_frame(SERVICE_ACTIVITY_NOTIFICATION, sequence=42, payload=payload)
    
    dec_payload, frame_type, _ = decode_outer_frame(notif_frame)
    assert dec_payload is not None
    svc, seq = struct.unpack_from(">HI", dec_payload, 0)
    assert svc == SERVICE_ACTIVITY_NOTIFICATION
    assert seq == 42
    # Verify payload starts immediately at offset 6 (no status field!)
    assert dec_payload[6:] == payload

def test_signon_endpoint_and_protobuf_response():
    """Verify SignOn request handling produces valid Protobuf response with keys and tokens."""
    server = MarathonServer()
    status, payload = server.handle_signon_request(b"fake_steam_ticket_bytes")
    assert status == 200
    
    # Parse protobuf response
    reader = ProtobufReader(payload)
    fields = {f[0]: f[2] for f in reader.parse()}
    
    # On success, error tag is omitted to avoid triggering Tiger Engine error.signon_denied
    assert PB_TAG_ERROR not in fields or fields[PB_TAG_ERROR] == 0
    assert PB_TAG_SUCCESS in fields
    assert PB_TAG_COMMON_INFO in fields
    
    # Inspect success submessage
    success_reader = ProtobufReader(fields[PB_TAG_SUCCESS])
    success_fields = {f[0]: f[2] for f in success_reader.parse()}
    
    # In Project Dawn schema: 16-byte session key and 32-byte session token
    assert PB_SUB_ENCRYPTION_KEY in success_fields
    assert len(success_fields[PB_SUB_ENCRYPTION_KEY]) == 16
    assert PB_SUB_SESSION_TOKEN in success_fields
    assert len(success_fields[PB_SUB_SESSION_TOKEN]) == 32
    
    # Inspect common info submessage (membership ID)
    common_reader = ProtobufReader(fields[PB_TAG_COMMON_INFO])
    common_fields = {f[0]: f[2] for f in common_reader.parse()}
    assert PB_COMMON_ID in common_fields
    assert common_fields[PB_COMMON_ID] in (1, 1001, 76561198000001001)

def test_bap_service_dispatcher_flow():
    """Verify BAP service router responds accurately to core startup services."""
    server = MarathonServer()
    _, _ = server.handle_signon_request(b"ticket")
    player = server.players[1001]
    
    # 1. Service 25: Server Hello
    hello = bytes(2) + ProtobufWriter().bytes(1, player.session_token).varint(2, 1).build()
    assert len(hello) == 38
    req_hello = BapRequest(SERVICE_SERVER_HELLO, 1, hello, 2)
    resp_hello = server.dispatch_bap_request(req_hello, player)
    assert resp_hello.service_id == SERVICE_HELLO_RESPONSE
    assert resp_hello.status == 200
    assert len(resp_hello.payload) == 84
    assert resp_hello.frame_type == 2
    body = resp_hello.payload
    assert body[:4] == struct.pack(">I", 80)
    import hmac
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    assert hmac.compare_digest(body[52:], hmac.digest(player.auth_key, body[:52], "sha256"))
    decrypt = Cipher(algorithms.AES(player.encryption_key), modes.CBC(body[4:20])).decryptor()
    assert (decrypt.update(body[20:52]) + decrypt.finalize())[28:] == bytes([4]) * 4
    unknown = bytes(2) + ProtobufWriter().bytes(1, b"unknown").varint(2, 1).build()
    assert server.dispatch_bap_request(BapRequest(25, 1, unknown, 2)).status == 401
    
    # 2. Service 30: Channel Start
    req_chan = BapRequest(service_id=SERVICE_CHANNEL_START, task_id=2, payload=b"\x00\x00DESTINY\x01" + bytes(120), frame_type=2)
    resp_chan = server.dispatch_bap_request(req_chan, player)
    assert resp_chan.service_id == SERVICE_CHANNEL_START_RESPONSE
    assert resp_chan.frame_type == 2
    assert len(resp_chan.payload) == 128
    assert resp_chan.payload[:8] == b"DESTINY\x01"
    
    # 3. Service 23: Account Translation
    req_acc = BapRequest(service_id=SERVICE_ACCOUNT_TRANSLATION, task_id=3, payload=b"")
    resp_acc = server.dispatch_bap_request(req_acc, player)
    assert resp_acc.service_id == SERVICE_ACCOUNT_RESPONSE
    m_id = struct.unpack_from(">Q", resp_acc.payload, 0)[0]
    assert m_id in (1, 1001, 76561198000001001)
    assert b"Runner#" in resp_acc.payload
    
    # 4. Service 6: Activity Session Allocation
    req_alloc = BapRequest(service_id=SERVICE_ACTIVITY_SESSION_ALLOCATION, task_id=4, payload=b"")
    resp_alloc = server.dispatch_bap_request(req_alloc, player)
    assert resp_alloc.service_id == SERVICE_ACTIVITY_SESSION_RESPONSE
    session_id = struct.unpack_from(">I", resp_alloc.payload, 0)[0]
    assert session_id == 5001
    assert b"marathon_deck_001" in resp_alloc.payload
    
    # 5. Service 16: Activity Host Endpoint Resolution
    req_host = BapRequest(service_id=SERVICE_ACTIVITY_HOST_ENDPOINT, task_id=5, payload=b"")
    resp_host = server.dispatch_bap_request(req_host, player)
    assert resp_host.service_id == SERVICE_ACTIVITY_HOST_RESPONSE
    assert len(resp_host.payload) == 6  # 4 bytes IP + 2 bytes Port

def test_vault_breaker_modding_and_objective_notification():
    """Verify Vault Breaker custom mod configuration and authoritative event 0x28 generation."""
    # Create custom mod config forcing 1 -> 5 -> 4 -> 7 route and custom battery requirements
    mod_cfg = VaultBreakerModConfig(
        forced_route=[1, 5, 4, 7],
        battery_requirements={1: 2, 2: 2, 3: 3, 4: 3, 5: 3, 6: 4, 7: 5},
        hec_antivirus_batteries_required=2
    )
    
    server = MarathonServer(default_mod_config=mod_cfg)
    _, _ = server.handle_signon_request(b"ticket")
    player = server.players[1001]
    
    # Allocate activity
    activity = server.create_activity_session(player, custom_config=mod_cfg)
    assert activity.selected_vaults == [1, 5, 4, 7]
    assert activity.mod_config.hec_antivirus_batteries_required == 2
    
    # Generate Service 9 objective assigned notification
    notif = server.create_objective_assigned_notification(activity)
    assert notif.service_id == SERVICE_ACTIVITY_NOTIFICATION
    assert notif.sequence == 1
    
    # Check payload contents
    payload = notif.payload
    assert payload[0] == 0x28  # Activity Event 0x28 (triggers 8080B8F1 Slot 10 Active Step 3)
    assert payload[1] == 4     # 4 vaults
    assert list(payload[2:6]) == [1, 5, 4, 7]
    assert payload[6] == 2     # Vault 1 capacity: 2
    assert payload[12] == 5    # Vault 7 capacity: 5
    assert payload[13] == 2    # HEC antivirus requirement: 2

def test_multiplayer_coop_session_isolation():
    """Verify that multiple players can sign on concurrently, receive isolated sessions,
    and be joined into the same co-op activity session."""
    server = MarathonServer()
    
    # Player 1 signs on
    _, p1_payload = server.handle_signon_request(b"player_1_ticket")
    p1 = server.players[1001]
    assert p1.bungie_name in ("Runner#1001", "Runner#0001")
    
    # Player 2 signs on
    _, p2_payload = server.handle_signon_request(b"player_2_ticket")
    p2 = server.players[1002]
    assert p2.bungie_name == "Runner#1002"
    
    # Sessions are distinct
    assert p1.session_token != p2.session_token
    assert p1.encryption_key != p2.encryption_key
    
    # Host Activity Session for Player 1
    activity = server.create_activity_session(p1)
    assert len(activity.players) == 1
    
    # Player 2 joins the co-op activity session
    activity.players.append(p2)
    p2.current_activity_session_id = activity.session_id
    
    assert len(activity.players) == 2
    assert activity.players[0].membership_id in (1, 1001, 76561198000001001)
    assert activity.players[1].membership_id == 1002
    assert p1.current_activity_session_id == p2.current_activity_session_id


def test_direct_settings_http_endpoint(tmp_path):
    """Verify that SignOnHTTPHandler serves Direct Settings JSON for /cfg_a/* and *.json."""
    import socket, threading, urllib.request
    from marathon_server import ThreadedHTTPServer, SignOnHTTPHandler

    (tmp_path / 'global.json').write_bytes(b'{}\n')
    server = ThreadedHTTPServer(('127.0.0.1', 0), SignOnHTTPHandler, direct_settings_dir=tmp_path)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        resp = urllib.request.urlopen(f'http://127.0.0.1:{port}/cfg_a/direct_settings/global/global.json')
        assert resp.status == 200
        assert resp.headers.get('Content-Type') == 'application/json'
        body = resp.read()
        assert b"{}" in body
    finally:
        server.shutdown()
        server.server_close()


def test_sdr_config_endpoint():
    """Verify that /ISteamApps/GetSDRConfig/v1 returns the official SDR configuration."""
    import socket, threading, urllib.request, json
    from marathon_server import ThreadedHTTPServer, SignOnHTTPHandler

    server = ThreadedHTTPServer(('127.0.0.1', 0), SignOnHTTPHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        resp = urllib.request.urlopen(f'http://127.0.0.1:{port}/ISteamApps/GetSDRConfig/v1?appid=3065800')
        assert resp.status == 200
        assert resp.headers.get('Content-Type') == 'application/json'
        body = resp.read()
        d = json.loads(body)
        assert d.get('success') is True
        assert 'pops' in d
        assert len(d['pops']) > 0
    finally:
        server.shutdown()


def test_unknown_endpoint_returns_404():
    """Verify that unknown endpoints return 404 Not Found to prevent masking errors."""
    import socket, threading, urllib.request, urllib.error
    from marathon_server import ThreadedHTTPServer, SignOnHTTPHandler

    server = ThreadedHTTPServer(('127.0.0.1', 0), SignOnHTTPHandler)
    port = server.server_port
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    try:
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/unknown/unsupported/endpoint')
            assert False, "Expected HTTP 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        server.shutdown()


def test_make_sdr_ping_reply(monkeypatch):
    import marathon_server
    monkeypatch.setattr(marathon_server.time, "time", lambda: 123456)
    peer = ("127.0.0.1", 63626)
    # Header from a preserved probe. The DWORD at +20 is the SDR revision.
    header = bytes.fromhex("0101736470696e67ee33e67e306e000000000000973fea6a316e007fb7070b00")
    for mode in (1, 2, 0x81, 0x82):
        short = mode >= 0x80
        request = (header[:1] + bytes([mode]) + header[2:]).ljust(100 if short else 1300, b"\0")
        reply = marathon_server.make_sdr_ping_reply(request, peer)
        assert len(reply) == (55 if short else 1300)
        assert reply[:22] == bytes.fromhex("020dee33e67e250100007f5d8af8000045306e000031")
        assert reply[22:30] == marathon_server.make_sdr_ping_reply(request, peer)[22:30]
        assert reply[30:46] == bytes.fromhex(
            "80018000a006800090018000a0068000" if mode & 1 else
            "80018000880180009001800098018000")
        trailer = b"\x2d" + struct.pack("<I", 123456) + b"\x48\x00"
        if short:
            assert reply[46:] == trailer + b"\x60\x03"
        else:
            # Parse fields 99, 2 and 3 independently, including padding boundaries.
            assert reply.endswith(trailer)
            assert ProtobufReader(reply[46:-len(trailer)]).parse() == [
                (99, 2, bytes(1234)), (2, 2, b"aes\0"), (3, 2, b"\0")]
    assert marathon_server.make_sdr_ping_reply(header, peer) is None
    assert marathon_server.make_sdr_ping_reply(bytes(1300), peer) is None
