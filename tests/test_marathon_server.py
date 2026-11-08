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
    
    assert PB_TAG_ERROR in fields and fields[PB_TAG_ERROR] == 0
    assert PB_TAG_SUCCESS in fields
    assert PB_TAG_COMMON_INFO in fields
    
    # Inspect success submessage
    success_reader = ProtobufReader(fields[PB_TAG_SUCCESS])
    success_fields = {f[0]: f[2] for f in success_reader.parse()}
    
    # Must contain 32-byte session key and 16-byte session token
    assert PB_SUB_ENCRYPTION_KEY in success_fields
    assert len(success_fields[PB_SUB_ENCRYPTION_KEY]) == 32
    assert PB_SUB_SESSION_TOKEN in success_fields
    assert len(success_fields[PB_SUB_SESSION_TOKEN]) == 16
    
    # Inspect common info submessage (membership ID)
    common_reader = ProtobufReader(fields[PB_TAG_COMMON_INFO])
    common_fields = {f[0]: f[2] for f in common_reader.parse()}
    assert PB_COMMON_ID in common_fields
    assert common_fields[PB_COMMON_ID] == 1001

def test_bap_service_dispatcher_flow():
    """Verify BAP service router responds accurately to core startup services."""
    server = MarathonServer()
    _, _ = server.handle_signon_request(b"ticket")
    player = server.players[1001]
    
    # 1. Service 25: Server Hello
    req_hello = BapRequest(service_id=SERVICE_SERVER_HELLO, task_id=1, payload=b"")
    resp_hello = server.dispatch_bap_request(req_hello, player)
    assert resp_hello.service_id == SERVICE_HELLO_RESPONSE
    assert resp_hello.status == 200
    assert len(resp_hello.payload) == 84
    
    # 2. Service 30: Channel Start
    req_chan = BapRequest(service_id=SERVICE_CHANNEL_START, task_id=2, payload=b"nonce_bytes_12")
    resp_chan = server.dispatch_bap_request(req_chan, player)
    assert resp_chan.service_id == SERVICE_CHANNEL_START_RESPONSE
    assert resp_chan.payload == b"nonce_bytes_"
    
    # 3. Service 23: Account Translation
    req_acc = BapRequest(service_id=SERVICE_ACCOUNT_TRANSLATION, task_id=3, payload=b"")
    resp_acc = server.dispatch_bap_request(req_acc, player)
    assert resp_acc.service_id == SERVICE_ACCOUNT_RESPONSE
    m_id = struct.unpack_from(">Q", resp_acc.payload, 0)[0]
    assert m_id == 1001
    assert b"Runner#1001" in resp_acc.payload
    
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
    assert p1.bungie_name == "Runner#1001"
    
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
    assert activity.players[0].membership_id == 1001
    assert activity.players[1].membership_id == 1002
    assert p1.current_activity_session_id == p2.current_activity_session_id
