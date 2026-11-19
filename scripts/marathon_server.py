"""Marathon Standalone Offline Server Emulator (Project Dawn Architecture).

Replicates Bungie live services (SignOn Web API, BAP, and Activity Hosting)
to enable standalone offline execution and modding for Marathon (Build 26136895).
Supports single-player offline preservation with multi-player co-op fireteam readiness.
"""
import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hmac
import hashlib
import time
import struct
import random
import socket
import json
from pathlib import Path
from urllib.parse import urlsplit
from ssc_public_capture import save_public_record
from direct_settings import DEFAULT_DIRECTORY, load_settings
from http_peer_owner import owner_for_connection
from signon_bootstrap import (
    CONTENT_MANIFEST_FILE, CONTENT_MANIFEST_URL, DIRECT_SETTINGS_MANIFEST_SUFFIX, DIRECT_SETTINGS_URLS,
    encode_bootstrap_entry, load_bootstrap_token,
)
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from marathon_protobuf import ProtobufWriter, ProtobufReader, encode_varint
from marathon_bap import (
    BapRequest, BapResponse, BapNotification,
    encode_outer_frame, decode_outer_frame,
    decode_inner_request, encode_inner_response, encode_server_notification,
    build_response_frame, build_notification_frame,
    BAP_STATUS_OK, BAP_STATUS_BAD_REQUEST, FRAME_TYPE_PLAINTEXT_BOOTSTRAP,
    SERVICE_ACTIVITY_SESSION_ALLOCATION, SERVICE_ACTIVITY_SESSION_RESPONSE,
    SERVICE_ACTIVITY_MESSAGE, SERVICE_ACTIVITY_NOTIFICATION,
    SERVICE_WEB_SERVICE_ENVELOPE, SERVICE_WEB_SERVICE_RESPONSE,
    SERVICE_ACTIVITY_HOST_ENDPOINT, SERVICE_ACTIVITY_HOST_RESPONSE,
    SERVICE_CLIENT_CONFIGURATION, SERVICE_CLIENT_CONFIG_RESPONSE,
    SERVICE_PURCHASED_OFFERS, SERVICE_OFFERS_RESPONSE,
    SERVICE_ACCOUNT_TRANSLATION, SERVICE_ACCOUNT_RESPONSE,
    SERVICE_SERVER_HELLO, SERVICE_HELLO_RESPONSE,
    SERVICE_CHANNEL_START, SERVICE_CHANNEL_START_RESPONSE,
    SERVICE_SKILL_RECORDS, SERVICE_SKILL_RESPONSE,
    SERVICE_MATCHMAKING_REQUEST, SERVICE_MATCHMAKING_RESPONSE,
    SERVICE_KEEPALIVE_PING, SERVICE_KEEPALIVE_PONG
)
from vault_breaker_mod import VaultBreakerModConfig

# Protobuf Tag Definitions matching Project Dawn response.cpp
PB_TAG_ERROR = 1
PB_TAG_SUCCESS = 2
PB_TAG_COMMON_INFO = 4
PB_TAG_SILO_ID = 5
PB_TAG_BUILD_VERSION = 6
PB_TAG_CAPABILITY_FLAGS = 8
PB_TAG_ENTITLEMENTS = 10
PB_TAG_SERVER_TIME = 12
PB_TAG_ENVIRONMENT = 13
PB_TAG_EXTERNAL_ADDR = 14

# Success Sub-message tags
PB_SUB_RESERVED = 1
PB_SUB_ENCRYPTION_KEY = 2
PB_SUB_AUTH_KEY = 3
PB_SUB_SESSION_TOKEN = 4
PB_SUB_EXPIRY = 5
PB_SUB_RELAY_ADDR = 6
PB_SUB_RELAY_PORT = 7
PB_SUB_CLIENT_CONFIG = 12
PB_SUB_CFG_A = 14
PB_SUB_CFG_B = 15
PB_SUB_CFG_C = 16

# CommonInfo tags
PB_COMMON_ID = 1
PB_COMMON_SILO = 2
PB_COMMON_CONFIG_BLOB = 3

BUILD_VERSION_STRING = "248199.26.10.21.2300.gol_retail.rc"
SIGNON_TOKEN_LIFETIME_SECONDS = 86400

@dataclass
class PlayerSession:
    membership_id: int
    bungie_name: str
    session_token: bytes
    encryption_key: bytes
    auth_key: bytes
    relay_port: int
    fireteam_id: int = 1
    current_activity_session_id: Optional[int] = None
    last_seen: float = field(default_factory=time.time)

@dataclass
class ActivitySession:
    session_id: int
    map_name: str
    activity_name: str
    mod_config: VaultBreakerModConfig
    selected_vaults: List[int]
    players: List[PlayerSession] = field(default_factory=list)
    sequence: int = 0
    current_phase: int = 0
    created_at: float = field(default_factory=time.time)

@dataclass
class BapChannel:
    # Ephemeral state owned only by this TCP connection.
    receive_nonce: bytes = field(default=b"", repr=False)
    key: bytes = field(default=b"", repr=False)

    send_nonce: bytes = field(default=b"", repr=False)

    def seal_first_response(self, service, task, status, body):
        if not self.send_nonce:
            raise ValueError("first-response nonce unavailable")
        plain = encode_inner_response(service, task, status, body)
        sealed = AESGCM(self.key).encrypt(self.send_nonce, plain, None)
        self.send_nonce = b""
        return encode_outer_frame(sealed[-16:] + sealed[:-16], 1)

    def open_first_frame(self, payload):
        if not self.key or len(payload) < 22:
            raise ValueError("missing channel or truncated authenticated frame")
        plaintext = AESGCM(self.key).decrypt(
            self.receive_nonce, bytes(payload[16:]) + bytes(payload[:16]), None)
        return decode_inner_request(plaintext, 1)


class MarathonServer:
    """Core state engine and service dispatcher for Marathon offline emulation."""
    def __init__(self, host: str = "127.0.0.1", http_port: int = 8080, bap_port: int = 7505,
                 default_mod_config: Optional[VaultBreakerModConfig] = None,
                 bootstrap_token: Optional[bytes] = None, ssc_response_dir: Optional[Path] = None,
                 ssc_capture_dir: Optional[Path] = None):
        self.ssc_capture_dir = ssc_capture_dir
        self.ssc_response_dir = ssc_response_dir
        self.host = host
        self.http_port = http_port
        self.bap_port = bap_port
        self.mod_config = default_mod_config or VaultBreakerModConfig()
        if bootstrap_token is None:
            default_candidate = Path(__file__).resolve().parents[1] / "config" / "bootstrap_token.bin"
            if default_candidate.is_file():
                try:
                    bootstrap_token = load_bootstrap_token(default_candidate)
                except (OSError, ValueError):
                    bootstrap_token = None
        self.bootstrap_entry = None if bootstrap_token is None else encode_bootstrap_entry(
            bootstrap_token, DIRECT_SETTINGS_URLS, DIRECT_SETTINGS_MANIFEST_SUFFIX, manifest_file=CONTENT_MANIFEST_FILE
        )
        
        # State tracking
        self.players: Dict[int, PlayerSession] = {}           # membership_id -> PlayerSession
        self.sessions_by_token: Dict[bytes, PlayerSession] = {} # token -> PlayerSession
        self.activity_sessions: Dict[int, ActivitySession] = {} # session_id -> ActivitySession
        
        self.next_membership_id = 1001
        self.next_activity_session_id = 5001

    def handle_signon_request(self, steam_ticket: bytes, platform: str = "pc_x64",
                              build: str = "248199.26.10.21.2300.gol_retail.rc") -> Tuple[int, bytes]:
        """Handles POST /SignOn?platform=%s&build=%s.
        Returns (HTTP status code, Protobuf binary payload) using Project Dawn's proven schema.
        """
        # Dawn's HTTP route passes absolute epoch seconds to success field 5,
        # not a relative lifetime. Use one clock sample for both wire fields.
        server_time = int(time.time())
        token_expiry = server_time + SIGNON_TOKEN_LIFETIME_SECONDS

        # Allocate deterministic session for player
        legacy_id = self.next_membership_id
        self.next_membership_id += 1
        player_id = 1 if legacy_id == 1001 else legacy_id
        membership_id = player_id
        
        # 16 bytes AES key, 16 bytes HMAC key, 32 bytes session token
        session_token = os.urandom(32)   # 32 bytes session token
        encryption_key = os.urandom(16)  # 16 bytes AES session key
        auth_key = os.urandom(16)        # 16 bytes HMAC auth key
        display_name = f"Runner#{legacy_id:04d}"
        
        player = PlayerSession(
            membership_id=membership_id,
            bungie_name=display_name,
            session_token=session_token,
            encryption_key=encryption_key,
            auth_key=auth_key,
            relay_port=self.bap_port
        )
        self.players[membership_id] = player
        self.players[legacy_id] = player
        self.players[76561198000001001] = player
        self.sessions_by_token[session_token] = player
        
        # Tiger stores the decoded uint32 directly into sockaddr_in.sin_addr.
        # On x64, these four memory bytes must be 7f 00 00 01.
        relay_ip_uint32 = int.from_bytes(socket.inet_aton("127.0.0.1"), "little")
        
        # Build Protobuf response matching Project Dawn's Writer
        success_sub = ProtobufWriter()
        success_sub.bytes(PB_SUB_RESERVED, bytes(16))  # 16 zero reserved bytes
        success_sub.bytes(PB_SUB_ENCRYPTION_KEY, encryption_key)
        success_sub.bytes(PB_SUB_AUTH_KEY, auth_key)
        success_sub.bytes(PB_SUB_SESSION_TOKEN, session_token)
        success_sub.varint(PB_SUB_EXPIRY, token_expiry)
        success_sub.varint(PB_SUB_RELAY_ADDR, relay_ip_uint32)
        success_sub.varint(PB_SUB_RELAY_PORT, self.bap_port)
        
        # Subfield 12: client_config (cookie=1, social_matchmaking_id=1, keys)
        client_config_sub = ProtobufWriter()
        client_config_sub.varint(1, 1)  # cookie = 1
        client_config_sub.bytes(3, b"\x11" * 16)
        client_config_sub.bytes(4, b"\x22" * 16)
        success_sub.message(PB_SUB_CLIENT_CONFIG, client_config_sub)
        
        # Direct Settings configuration URLs (port 80)
        for field, url in zip((PB_SUB_CFG_A, PB_SUB_CFG_B, PB_SUB_CFG_C), DIRECT_SETTINGS_URLS):
            success_sub.string(field, url)
        
        common_info_sub = ProtobufWriter()
        common_info_sub.varint(PB_COMMON_ID, membership_id)  # 1
        common_info_sub.varint(PB_COMMON_SILO, 1)
        # Activated Dawn publishes its native content token in Field 4.3.
        # Marathon's token source and required consumer path are still being
        # verified; do not substitute invented bytes for that native value.
        if self.bootstrap_entry is not None:
            common_info_sub.bytes(PB_COMMON_CONFIG_BLOB, self.bootstrap_entry)
        
        # Extract requested entitlements from client request Field 15
        client_entitlements = [3065800, 3760193538, 3760193537]
        try:
            req_idx = 0
            while req_idx < len(steam_ticket):
                tag = 0
                shift = 0
                while req_idx < len(steam_ticket):
                    b = steam_ticket[req_idx]
                    req_idx += 1
                    tag |= (b & 0x7F) << shift
                    if not (b & 0x80): break
                    shift += 7
                fnum = tag >> 3
                wtype = tag & 7
                if wtype == 0:
                    while req_idx < len(steam_ticket) and (steam_ticket[req_idx] & 0x80): req_idx += 1
                    req_idx += 1
                elif wtype == 1:
                    req_idx += 8
                elif wtype == 2:
                    length = 0
                    shift = 0
                    while req_idx < len(steam_ticket):
                        b = steam_ticket[req_idx]
                        req_idx += 1
                        length |= (b & 0x7F) << shift
                        if not (b & 0x80): break
                        shift += 7
                    val_bytes = steam_ticket[req_idx:req_idx+length]
                    req_idx += length
                    if fnum == 15:
                        v_i = 0
                        found_ids = []
                        while v_i < len(val_bytes):
                            v_val = 0
                            v_shift = 0
                            while v_i < len(val_bytes):
                                vb = val_bytes[v_i]
                                v_i += 1
                                v_val |= (vb & 0x7F) << v_shift
                                if not (vb & 0x80): break
                                v_shift += 7
                            found_ids.append(v_val)
                        if found_ids:
                            client_entitlements = found_ids
                elif wtype == 5:
                    req_idx += 4
        except Exception as e:
            server_log(f"[-] Error extracting client entitlements: {e}")

        response = ProtobufWriter()
        response.varint(PB_TAG_ERROR, 0)
        response.message(PB_TAG_SUCCESS, success_sub)
        response.message(PB_TAG_COMMON_INFO, common_info_sub)
        response.varint(PB_TAG_SILO_ID, 1)
        response.string(PB_TAG_BUILD_VERSION, build)
        response.varint(PB_TAG_CAPABILITY_FLAGS, 0)
        
        # Tag 10: length-delimited submessage with repeated varint 1
        ent_sub = ProtobufWriter()
        for ent_id in client_entitlements:
            ent_sub.varint(1, ent_id)
        response.message(PB_TAG_ENTITLEMENTS, ent_sub)
        
        response.varint(PB_TAG_SERVER_TIME, server_time)
        response.string(PB_TAG_ENVIRONMENT, "GOLRETAIL")
        response.varint(PB_TAG_EXTERNAL_ADDR, relay_ip_uint32)
        
        payload = response.build()
        server_log(f"[SignOn] Granted entitlements: {client_entitlements} (payload {len(payload)}B) "
                   f"server_time={server_time} expiry={token_expiry} "
                   f"lifetime_seconds={SIGNON_TOKEN_LIFETIME_SECONDS} expiry_contract=absolute_epoch_seconds")
        return 200, payload

    def determine_vault_route(self, config: Optional[VaultBreakerModConfig] = None) -> List[int]:
        """Resolves the 4-tier vault progression sequence based on mod config or baseline RNG."""
        cfg = config or self.mod_config
        if cfg.forced_route:
            return list(cfg.forced_route)
        
        # Tier 1 {1,2}
        v1 = random.choice(cfg.tier_1_vaults)
        # Tier 2 {3,5}
        v2 = random.choice(cfg.tier_2_vaults)
        # Tier 3 {4,6}
        v3 = random.choice(cfg.tier_3_vaults)
        # Tier 4 {7}
        v4 = cfg.tier_4_vaults[0] if cfg.tier_4_vaults else 7
        return [v1, v2, v3, v4]

    def create_activity_session(self, player: PlayerSession,
                                map_name: str = "marathon_deck_001",
                                activity_name: str = "activity_exp.cryo.vault_breaker_server",
                                custom_config: Optional[VaultBreakerModConfig] = None) -> ActivitySession:
        """Instantiates an authoritative ActivitySession for Vault Breaker."""
        cfg = custom_config or self.mod_config
        session_id = self.next_activity_session_id
        self.next_activity_session_id += 1
        
        selected_route = self.determine_vault_route(cfg)
        activity = ActivitySession(
            session_id=session_id,
            map_name=map_name,
            activity_name=activity_name,
            mod_config=cfg,
            selected_vaults=selected_route,
            players=[player]
        )
        self.activity_sessions[session_id] = activity
        player.current_activity_session_id = session_id
        return activity

    def ssc_response(self, request):
        # Lookup is scoped to the complete authenticated bytes after the task ID.
        # A provisioned file contains the encoded 305 body, without BAP headers.
        digest = hashlib.sha256(request.payload).hexdigest()
        if self.ssc_response_dir is not None:
            try:
                with (self.ssc_response_dir / (digest + ".bin")).open("rb") as stream:
                    body = stream.read(65537)
            except FileNotFoundError:
                pass
            else:
                if 0 < len(body) <= 65536:
                    return BAP_STATUS_OK, body
                raise ValueError("invalid provisioned SSC response size")
        server_log(f"[BAP] SSC response unavailable for request SHA256={digest}")
        return 503, b""

    def dispatch_bap_request(self, request: BapRequest, player: Optional[PlayerSession] = None,
                             *, channel: Optional[BapChannel] = None) -> BapResponse:
        """Processes an incoming BAP request and routes to the appropriate service."""
        svc = request.service_id
        task = request.task_id
        
        # Service 250: Keepalive
        if svc == SERVICE_KEEPALIVE_PING:
            return BapResponse(service_id=SERVICE_KEEPALIVE_PONG, task_id=task,
                               status=BAP_STATUS_OK, payload=b"")
        
        # Service 25: Server Hello
        elif svc == SERVICE_SERVER_HELLO:
            def hello_response(status, body=b""):
                return BapResponse(SERVICE_HELLO_RESPONSE, task, status, body,
                                   FRAME_TYPE_PLAINTEXT_BOOTSTRAP)

            if request.frame_type != FRAME_TYPE_PLAINTEXT_BOOTSTRAP or request.payload[:2] != bytes(2):
                return hello_response(BAP_STATUS_BAD_REQUEST)
            try:
                fields = ProtobufReader(bytes(request.payload[2:])).parse()
            except (ValueError, NotImplementedError, IndexError):
                return hello_response(BAP_STATUS_BAD_REQUEST)
            tokens = [value for number, wire, value in fields if (number, wire) == (1, 2)]
            versions = [value for number, wire, value in fields if (number, wire) == (2, 0)]
            if len(tokens) != 1 or versions != [1]:
                return hello_response(BAP_STATUS_BAD_REQUEST)
            session = self.sessions_by_token.get(tokens[0])
            if session is None:
                return hello_response(401)

            # Local secure-hello candidate using the Dawn envelope layout.
            # Both wrapping keys belong to this client's local SignOn session.
            iv = os.urandom(16)
            material = os.urandom(12 + 16)
            encryptor = Cipher(algorithms.AES(session.encryption_key), modes.CBC(iv)).encryptor()
            ciphertext = encryptor.update(material + bytes([4]) * 4) + encryptor.finalize()
            envelope = struct.pack(">I", 80) + iv + ciphertext
            if channel is not None:
                channel.receive_nonce = material[:11] + bytes([material[11] ^ 1])
                channel.key = material[12:]
                channel.send_nonce = material[:12]
            return hello_response(BAP_STATUS_OK, envelope + hmac.digest(session.auth_key, envelope, "sha256"))

        # Marathon channel start: two reserved bytes precede the 128-byte
        # body in our six-byte inner-request decoder. Retail uses type 2,
        # DESTINY\x01 and 120 fresh bytes, not a truncated nonce echo.
        # Native consumer: 0x30BE4A70 (length), 0x305E7840 (type),
        # 0x304A9CF0 (service/status), 0x30BE4CC2 (marker).
        elif svc == SERVICE_CHANNEL_START:
            valid = (request.frame_type == FRAME_TYPE_PLAINTEXT_BOOTSTRAP
                     and len(request.payload) == 130
                     and request.payload[:10] == b"\x00\x00DESTINY\x01")
            return BapResponse(
                service_id=SERVICE_CHANNEL_START_RESPONSE, task_id=task,
                status=BAP_STATUS_OK if valid else BAP_STATUS_BAD_REQUEST,
                payload=b"DESTINY\x01" + os.urandom(120) if valid else b"",
                frame_type=FRAME_TYPE_PLAINTEXT_BOOTSTRAP)
        
        # Service 18: Client Configuration
        elif svc == SERVICE_CLIENT_CONFIGURATION:
            # Echo configuration acknowledgment
            return BapResponse(service_id=SERVICE_CLIENT_CONFIG_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=b"\x00\x00")
        
        # Service 23: Account Translation
        elif svc == SERVICE_ACCOUNT_TRANSLATION:
            p_name = player.bungie_name if player else "Runner#0001"
            m_id = player.membership_id if player else 1001
            payload = struct.pack(">Q", m_id) + p_name.encode("utf-8")
            return BapResponse(service_id=SERVICE_ACCOUNT_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=payload)
        
        # Service 21: Purchased Offers / Inventory
        elif svc == SERVICE_PURCHASED_OFFERS:
            # Return empty/default inventory
            return BapResponse(service_id=SERVICE_OFFERS_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=b"\x00\x00\x00\x00")
        
        # Service 34: Skill Records
        elif svc == SERVICE_SKILL_RECORDS:
            # Return empty skill list
            return BapResponse(service_id=SERVICE_SKILL_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=b"\x00\x00")
        
        # Service 6: Activity Session Allocation
        elif svc == SERVICE_ACTIVITY_SESSION_ALLOCATION:
            p = player or self.players.get(1001) or PlayerSession(
                membership_id=1001, bungie_name="Runner#0001",
                session_token=bytes(16), encryption_key=bytes(32),
                auth_key=bytes(32), relay_port=self.bap_port
            )
            act = self.create_activity_session(p)
            # Response payload carries uint32 session ID and map name
            payload = struct.pack(">I", act.session_id) + act.map_name.encode("utf-8")
            return BapResponse(service_id=SERVICE_ACTIVITY_SESSION_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=payload)
        
        # Service 16: Activity Host Endpoint Resolution
        elif svc == SERVICE_ACTIVITY_HOST_ENDPOINT:
            # Resolve to local host IP and UDP port
            ip_bytes = socket.inet_aton(self.host)
            port_bytes = struct.pack(">H", self.bap_port)
            payload = ip_bytes + port_bytes
            return BapResponse(service_id=SERVICE_ACTIVITY_HOST_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=payload)
        
        # Service 42: Matchmaking Request
        elif svc == SERVICE_MATCHMAKING_REQUEST:
            # Return 128-byte opaque join descriptor
            join_descriptor = bytes(128)
            return BapResponse(service_id=SERVICE_MATCHMAKING_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=join_descriptor)
        
        # Unknown services receive generic neutral OK response
        return BapResponse(service_id=svc + 1, task_id=task, status=BAP_STATUS_OK, payload=b"")

    def create_objective_assigned_notification(self, activity: ActivitySession) -> BapNotification:
        """Constructs an authoritative Service 9 notification assigning the selected vaults.
        This triggers Marathon client universal objective listener 8080B8F1 Slot 10
        and dispatches transition event 0x28.
        """
        activity.sequence += 1
        # Payload format:
        # [0x28: 1B] (Event 0x28 / 40)
        # [VaultCount: 1B (4)]
        # [SelectedVaults: 4B (e.g. 1, 5, 4, 7)]
        # [BatteriesRequired: 7B (capacities for Vaults 1..7)]
        # [HECAntivirusBatteries: 1B (3)]
        payload = bytearray()
        payload.append(0x28)  # Event 0x28
        payload.append(len(activity.selected_vaults))
        for v in activity.selected_vaults:
            payload.append(v)
        for i in range(1, 8):
            payload.append(activity.mod_config.battery_requirements.get(i, 4))
        payload.append(activity.mod_config.hec_antivirus_batteries_required)
        
        return BapNotification(
            service_id=SERVICE_ACTIVITY_NOTIFICATION,
            sequence=activity.sequence,
            payload=bytes(payload)
        )

# ---------------------------------------------------------------------------
# Standalone CLI Server Runner
# ---------------------------------------------------------------------------
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import ssl

def server_log(msg: str):
    ts = time.strftime("[%Y-%m-%d %H:%M:%S]")
    line = f"{ts} {msg}"
    print(line, flush=True)
    try:
        with open("marathon_server.log", "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

_SDR_REPLY_KEY = os.urandom(32)


def make_sdr_ping_reply(req_packet: bytes, client_addr: tuple) -> Optional[bytes]:
    """Answer the long and short SDR probe shapes observed in retail."""
    if len(req_packet) < 16 or req_packet[0] != 1 or req_packet[2:8] != b"sdping":
        return None
    mode = req_packet[1]
    if mode not in (1, 2, 0x81, 0x82):
        return None
    short_probe = bool(mode & 0x80)
    if len(req_packet) != (100 if short_probe else 1300):
        return None

    ip = int.from_bytes(socket.inet_aton(client_addr[0]), "big")
    port = client_addr[1]
    endpoint = struct.pack("<II", ip, port)
    # Field 6 is opaque in the capture. Use a stable local value for this peer.
    peer_tag = hmac.digest(_SDR_REPLY_KEY, endpoint, "sha256")[:8]
    prefix = (
        b"\x02\x0d" + req_packet[8:12] +
        b"\x25" + struct.pack("<I", ip) +
        b"\x5d" + struct.pack("<I", port) +
        b"\x45" + req_packet[12:16] +
        b"\x31" + peer_tag
    )
    # Retail uses two-byte varints in these slots, including for zero.
    status_fields = (16, 100, 18, 100) if mode & 0x7f == 1 else (16, 17, 18, 19)
    for field in status_fields:
        prefix += encode_varint(field << 3) + b"\x80\x00"

    trailer = b"\x2d" + struct.pack("<I", int(time.time())) + b"\x48\x00"
    if short_probe:
        return prefix + trailer + b"\x60\x03"

    # One local POP ("sea", encoded as a packed little-endian POP ID),
    # with zero intra-POP latency. No external routes are advertised.
    routes = ProtobufWriter().bytes(2, b"aes\x00").bytes(3, b"\x00").build()
    padding_key = encode_varint((99 << 3) | 2)
    # At this probe size the padding length occupies a two-byte varint.
    padding_size = len(req_packet) - len(prefix + padding_key + routes + trailer) - 2
    return prefix + padding_key + encode_varint(padding_size) + bytes(padding_size) + routes + trailer
    return b"\x02\x01sdping" + pb


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler, *, direct_settings_dir=None):
        # Set once per server, including all CLI listeners. No implicit live/CWD fallback.
        self.direct_settings_dir = Path(direct_settings_dir or DEFAULT_DIRECTORY).resolve()
        super().__init__(server_address, handler)

class SignOnHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_instance: MarathonServer = None  # Injected

    def do_POST(self):
        client_ip, client_port = self.client_address
        peer_pid = owner_for_connection(self.connection)
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""
        
        server_log(f"[HTTPS POST] from {client_ip}:{client_port} -> {self.path} ({content_len} bytes) peer_pid={peer_pid if peer_pid is not None else 'unknown'} server_pid={os.getpid()}")
        server_log(f"[HTTPS POST] User-Agent: {self.headers.get('User-Agent', '<none>')}")
        
        # Handle Bungie Frontdoor Anonymous Events / Telemetry
        if "anon/events" in self.path or "analytics" in self.path:
            ts = int(time.time())
            dump_fn = f"telemetry_{ts}_{client_port}.bin"
            try:
                with open(dump_fn, "wb") as f_dump:
                    f_dump.write(body)
                ascii_strings = [s for s in body.decode("latin1", errors="ignore").split("\x00") if len(s) > 4 and any(c.isalnum() for c in s)]
                server_log(f"[Telemetry] Saved {len(body)} bytes to {dump_fn}. Preview: {ascii_strings[:5]}")
            except Exception as e:
                server_log(f"[-] Telemetry dump error: {e}")

            resp = b'{"result":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(resp)
            self.wfile.flush()
            server_log(f"[Telemetry] Dispatched 200 OK to {self.path}")
            return

        if "SignOn" in self.path:
            ts = int(time.time())
            dump_fn = f"signon_req_{ts}_{client_port}.bin"
            try:
                with open(dump_fn, "wb") as f_dump:
                    f_dump.write(body)
                server_log(f"[SignOn] Dumped {len(body)} bytes request body to {dump_fn}")
            except Exception as e:
                server_log(f"[-] SignOn dump error: {e}")

        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        platform = qs.get("platform", ["pc_x64"])[0]
        build = qs.get("build", [BUILD_VERSION_STRING])[0]
        status, payload = self.server_instance.handle_signon_request(body, platform=platform, build=build)
        
        self.send_response(status)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()
        server_log(f"[HTTPS POST] Dispatched SignOn Protobuf response ({len(payload)} bytes) -> Status {status}")

    def do_GET(self):
        self._serve_get(head_only=False)

    def _serve_get(self, head_only=False):
        client_ip, client_port = self.client_address
        peer_pid = owner_for_connection(self.connection)
        server_log(f"[HTTP {self.command}] from {client_ip}:{client_port} -> {self.path}; User-Agent={self.headers.get('User-Agent', '<none>')}; peer_pid={peer_pid if peer_pid is not None else 'unknown'} server_pid={os.getpid()}")
        if self.path == "/shutdown" and not head_only:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"Server shutting down...\n")
            self.wfile.flush()
            threading.Thread(target=lambda: (time.sleep(0.5), os._exit(0))).start()
            return

        # Steam Datagram Relay (SDR) configuration endpoint
        local_content = None
        if urlsplit(self.path).path.rstrip("/") == "/ISteamApps/GetSDRConfig/v1":
            sdr_candidates = [
                os.path.join(os.path.dirname(__file__), "..", "config", "sdr_config.json"),
                r"D:\Marathon-live\config\sdr_config.json",
                os.path.join(os.getcwd(), "config", "sdr_config.json"),
            ]
            for sp in sdr_candidates:
                if os.path.isfile(sp):
                    try:
                        with open(sp, "rb") as sf:
                            local_content = sf.read()
                        server_log(f"[SDRConfig] Serving official SDR config {sp} ({len(local_content)} bytes)")
                        try:
                            sdr_json = json.loads(local_content)
                            server_log(f"[SDRConfig] Outbound payload: revision={sdr_json.get('revision')}, pops={list(sdr_json.get('pops', {}).keys())}")
                        except Exception:
                            pass
                        break
                    except Exception:
                        pass

        settings = load_settings(self.path, self.server.direct_settings_dir) if local_content is None else None
        if settings is not None:
            server_log(f"[DirectSettings] status={settings.status} source={settings.source!r} bytes={len(settings.body)} sha256={settings.sha256 or '<none>'} schema=unverified")
            self.send_response(settings.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(settings.body)))
            self.send_header("Connection", "close")
            if settings.sha256:
                self.send_header("X-Direct-Settings-SHA256", settings.sha256)
            self.end_headers()
            if not head_only:
                self.wfile.write(settings.body)
                self.wfile.flush()
            return

        # Content Manifest (.pb) endpoint (Bungie Tiger Engine package inventory)
        clean_path = urlsplit(self.path).path
        if ("content_manifest" in clean_path or clean_path.endswith(".pb")) and local_content is None and settings is None:
            manifest_candidates = [
                CONTENT_MANIFEST_FILE.with_name("content_manifest.pb"),
                r"D:\Marathon-live\config\content_manifest\content_manifest.pb",
                os.path.join(os.getcwd(), "config", "content_manifest", "content_manifest.pb"),
                r"D:\Marathon-preservation\analysis\retail-http-contract-20261113\objects\248673.26.11.04.2300-0_f5e5c1699ebc42c9.pb%3fd=639299290878459057",
            ]
            preserved_manifest = clean_path == urlsplit(CONTENT_MANIFEST_URL).path
            for mp in ([CONTENT_MANIFEST_FILE] if preserved_manifest else manifest_candidates):
                if os.path.isfile(mp):
                    try:
                        with open(mp, "rb") as mf:
                            manifest_bytes = mf.read()
                        server_log(f"[ContentManifest] Serving content manifest ({len(manifest_bytes)} bytes) from {mp} -> {self.path}")
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Content-Length", str(len(manifest_bytes)))
                        if preserved_manifest:
                            self.send_header("ETag", '"' + hashlib.sha256(manifest_bytes).hexdigest() + '"')
                            self.send_header("Cache-Control", "no-cache")
                        else:
                            self.send_header("ETag", '"57b1262814b494ba43266831e6da6400:1794332288.309982"')
                            self.send_header("Last-Modified", "Thu, 05 Nov 2026 08:15:40 GMT")
                        self.send_header("Server", "AkamaiNetStorage")
                        self.send_header("Connection", "keep-alive")
                        self.end_headers()
                        if not head_only:
                            self.wfile.write(manifest_bytes)
                            self.wfile.flush()
                        return
                    except Exception as e:
                        server_log(f"[-] ContentManifest read error: {e}")

        if local_content is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(local_content)))
            self.send_header("Connection", "close")
            self.end_headers()
            if not head_only:
                self.wfile.write(local_content)
                self.wfile.flush()
        else:
            server_log(f"[-] [HTTP 404 UNKNOWN ENDPOINT] Unhandled request: {self.command} {self.path}")
            err_body = (json.dumps({"error": "not_found", "path": self.path}) + "\n").encode("utf-8")
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if not head_only:
                self.wfile.write(err_body)
                self.wfile.flush()

    def do_HEAD(self):
        self._serve_get(head_only=True)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, HEAD, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):
        # Redirect standard HTTP access logs to server_log
        server_log(f"[HTTP Access] " + (format % args))

def start_bap_listener(server_instance: MarathonServer):
    """TCP listener for BAP frames with dual 7505/7777 binding."""
    ports = [server_instance.bap_port]
    if 7777 not in ports:
        ports.append(7777)
    for p in ports:
        def listen_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((server_instance.host, port))
                sock.listen(5)
                server_log(f"[*] BAP Service Router listening on TCP {server_instance.host}:{port}")
            except Exception as e:
                server_log(f"[-] BAP TCP bind error on port {port}: {e}")
                return
            while True:
                try:
                    client_sock, client_addr = sock.accept()
                    server_log(f"[BAP] Client connected from {client_addr} on port {port}")
                    threading.Thread(target=handle_bap_connection, args=(client_sock, server_instance), daemon=True).start()
                except Exception as e:
                    server_log(f"[-] BAP accept error on port {port}: {e}")
                    break
        threading.Thread(target=listen_port, args=(p,), daemon=True).start()

def handle_bap_connection(client_sock: socket.socket, server_instance: MarathonServer):
    buf = bytearray()
    channel = BapChannel()
    sent_ssc = False
    try:
        while True:
            chunk = client_sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            while True:
                payload, frame_type, new_pos = decode_outer_frame(buf)
                if payload is None:
                    break
                buf = buf[new_pos:]
                
                if sent_ssc:
                    server_log(f"[BAP] Post-305 frame type={frame_type} bytes={len(payload)}")
                    return
                if frame_type == 1:
                    try:
                        opened = channel.open_first_frame(payload)
                    except InvalidTag:
                        server_log(f"[BAP] Type-1 authentication failed ({len(payload)} bytes)")
                        return
                    server_log(f"[BAP] Authenticated type-1 service={opened.service_id} "
                               f"task={opened.task_id} bytes_after_task={len(opened.payload)}")
                    if opened.service_id != 304:
                        return
                    if server_instance.ssc_capture_dir is not None:
                        try:
                            path, result = save_public_record(server_instance.ssc_capture_dir, opened)
                            server_log(f"[BAP] SSC public capture {result}: {path}")
                        except OSError as error:
                            server_log(f"[BAP] SSC public capture failed: {error}")
                    status, body = server_instance.ssc_response(opened)
                    client_sock.sendall(channel.seal_first_response(305, opened.task_id, status, body))
                    server_log(f"[BAP] Encrypted svc 305 task={opened.task_id} status={status} body={len(body)} bytes")
                    if status != BAP_STATUS_OK:
                        return
                    sent_ssc = True
                    continue
                req = decode_inner_request(payload, frame_type)
                server_log(f"[BAP] Svc {req.service_id} (Task {req.task_id}) <- {len(req.payload)} bytes")
                
                resp = server_instance.dispatch_bap_request(req, channel=channel)
                resp_frame = build_response_frame(resp.service_id, resp.task_id, resp.status, resp.payload, resp.frame_type)
                client_sock.sendall(resp_frame)
                server_log(f"[BAP] Svc {resp.service_id} (Task {resp.task_id}) -> Status {resp.status} ({len(resp.payload)} bytes)")
    except Exception as e:
        server_log(f"[BAP] Connection ended: {type(e).__name__}: {e}")
    finally:
        client_sock.close()

def start_plaintext_http(server: MarathonServer, port: int = 8081, *, direct_settings_dir=None):
    httpd = ThreadedHTTPServer(("0.0.0.0", port), SignOnHTTPHandler, direct_settings_dir=direct_settings_dir)
    server_log(f"[*] Plaintext HTTP fallback listening on http://127.0.0.1:{port}")
    httpd.serve_forever()

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Local Marathon preservation services")
    parser.add_argument("--direct-settings-dir", type=Path, default=DEFAULT_DIRECTORY,
                        help="The ONLY directory served for Direct Settings (default: repository config/direct_settings)")
    parser.add_argument("--bootstrap-token-file", type=Path,
                        help="Experimental CommonInfo entry using exactly 16 raw native bytes; State 8 effect unverified")
    parser.add_argument("--bap-port", type=int, default=7505,
                        help="BAP service router port (default: 7505)")
    parser.add_argument("--ssc-response-dir", type=Path,
                        help="Provisioned service-305 wire bodies named <request SHA256>.bin")
    parser.add_argument("--ssc-capture-dir", type=Path, help="Save decoded public service-304 request metadata")
    args = parser.parse_args()
    if args.ssc_response_dir and not args.ssc_response_dir.is_dir():
        parser.error("SSC response directory does not exist")
    settings_dir = args.direct_settings_dir.resolve()
    if not settings_dir.is_dir():
        parser.error(f"Direct Settings directory does not exist: {settings_dir}")
    bootstrap_token = None
    if args.bootstrap_token_file is None:
        default_candidate = Path(__file__).resolve().parents[1] / "config" / "bootstrap_token.bin"
        if default_candidate.is_file():
            args.bootstrap_token_file = default_candidate
    if args.bootstrap_token_file is not None:
        try:
            bootstrap_token = load_bootstrap_token(args.bootstrap_token_file)
        except (OSError, ValueError) as error:
            parser.error(str(error))
    server = MarathonServer(host="0.0.0.0", http_port=8080, bap_port=args.bap_port,
                            bootstrap_token=bootstrap_token, ssc_response_dir=args.ssc_response_dir,
                            ssc_capture_dir=args.ssc_capture_dir)
    SignOnHTTPHandler.server_instance = server
    server_log(f"[*] Direct Settings root: {settings_dir}; JSON syntax checked; Tiger schema unverified")
    server_log(f"[*] SignOn bootstrap entry: {'experimental native value enabled' if bootstrap_token is not None else 'omitted'}; State 8 effect unverified")
    
    print("=" * 65, flush=True)
    print("  MARATHON STANDALONE EMULATION SERVER (Project Dawn Architecture)", flush=True)
    print("  Target Build: 26136895 (Cryo Archive Vault Breaker)", flush=True)
    print("=" * 65, flush=True)
    server_log(f"[*] Configured Mod Route: {server.mod_config.tier_1_vaults} -> {server.mod_config.tier_2_vaults} -> {server.mod_config.tier_3_vaults} -> {server.mod_config.tier_4_vaults}")
    
    start_bap_listener(server)

    def start_bap_udp(server):
        ports = [server.bap_port]
        if 7777 not in ports:
            ports.append(7777)
        for p in ports:
            def udp_listen(port):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind(("0.0.0.0", port))
                    server_log(f"[*] BAP Service Router listening on UDP 0.0.0.0:{port}")
                    while True:
                        data, addr = sock.recvfrom(65535)
                        server_log(f"[UDP {port}] Received {len(data)} bytes from {addr}. Preview: {data[:32].hex()}")
                except Exception as e:
                    server_log(f"[-] UDP {port} bind warning: {e}")
            threading.Thread(target=udp_listen, args=(p,), daemon=True).start()

    bap_udp_thread = threading.Thread(target=start_bap_udp, args=(server,), daemon=True)
    bap_udp_thread.start()

    def start_sdr_udp(server, port: int = 27015):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Disable WSAECONNRESET (10054) on Windows from asynchronous ICMP Port Unreachable
            if hasattr(socket, "SIO_UDP_CONNRESET"):
                try:
                    sock.ioctl(socket.SIO_UDP_CONNRESET, False)
                except Exception as e:
                    server_log(f"[-] SIO_UDP_CONNRESET config warning: {e}")
            sock.bind(("0.0.0.0", port))
            server_log(f"[*] SDR Ping Responder listening on UDP 0.0.0.0:{port}")
        except Exception as e:
            server_log(f"[-] SDR UDP {port} bind error: {e}")
            return

        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except Exception as e:
                server_log(f"[-] SDR UDP {port} recvfrom error: {e}")
                continue

            try:
                server_log(f"[SDR UDP {port}] Received {len(data)} bytes from {addr}. Hex: {data[:32].hex()}")
                reply = make_sdr_ping_reply(data, addr)
                if reply is None:
                    continue
                sock.sendto(reply, addr)
                server_log(f"[SDR UDP {port}] Dispatched RouterPingReply ({len(reply)} bytes) to {addr}")
            except Exception as e:
                server_log(f"[-] SDR UDP {port} sendto error: {e}")

    sdr_udp_thread = threading.Thread(target=start_sdr_udp, args=(server,), daemon=True)
    sdr_udp_thread.start()
    
    def start_http_80(server):
        try:
            httpd_80 = ThreadedHTTPServer(("0.0.0.0", 80), SignOnHTTPHandler, direct_settings_dir=settings_dir)
            server_log("[*] Plaintext HTTP Direct Settings service active on http://127.0.0.1:80")
            httpd_80.serve_forever()
        except Exception as e:
            server_log(f"[-] Port 80 HTTP bind warning: {e}")

    http_80_thread = threading.Thread(target=start_http_80, args=(server,), daemon=True)
    http_80_thread.start()

    plain_thread = threading.Thread(target=start_plaintext_http, args=(server, 8081), kwargs={"direct_settings_dir": settings_dir}, daemon=True)
    plain_thread.start()

    def start_https_443(server, cert_path, key_path):
        try:
            httpd_443 = ThreadedHTTPServer(("0.0.0.0", 443), SignOnHTTPHandler, direct_settings_dir=settings_dir)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            httpd_443.socket = ctx.wrap_socket(httpd_443.socket, server_side=True)
            server_log("[*] HTTPS SignOn service active with TLS on https://127.0.0.1:443 (Port 443)")
            httpd_443.serve_forever()
        except Exception as e:
            server_log(f"[-] Port 443 HTTPS bind warning: {e}")

    def ensure_self_signed_cert(target_dir):
        c = os.path.join(target_dir, "server.crt")
        k = os.path.join(target_dir, "server.key")
        if os.path.exists(c) and os.path.exists(k):
            return os.path.abspath(c), os.path.abspath(k)
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime, ipaddress

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bungie Preservation"),
                x509.NameAttribute(NameOID.COMMON_NAME, "signon.goliath.prod.gravityshavings.net"),
            ])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
                .add_extension(
                    x509.SubjectAlternativeName([
                        x509.DNSName("signon.goliath.prod.gravityshavings.net"),
                        x509.DNSName("localhost"),
                        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    ]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
            with open(k, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            with open(c, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            server_log(f"[*] Generated fresh self-signed certificates at {c}")
            return os.path.abspath(c), os.path.abspath(k)
        except Exception as e:
            server_log(f"[-] Could not auto-generate self-signed cert: {e}")
            return None, None

    cert_path = None
    key_path = None
    for base in [os.path.dirname(__file__), os.path.join(os.path.dirname(__file__), ".."), os.getcwd(), r"D:\vault-breaker-preservation", r"D:\Marathon-live"]:
        c = os.path.join(base, "server.crt")
        k = os.path.join(base, "server.key")
        if os.path.exists(c) and os.path.exists(k):
            cert_path = os.path.abspath(c)
            key_path = os.path.abspath(k)
            break

    if not cert_path or not key_path:
        default_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cert_path, key_path = ensure_self_signed_cert(default_dir)

    httpd = ThreadedHTTPServer(("0.0.0.0", server.http_port), SignOnHTTPHandler, direct_settings_dir=settings_dir)
    if cert_path and key_path:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        server_log(f"[*] HTTPS SignOn service active with TLS on https://127.0.0.1:{server.http_port} (Cert: {cert_path})")
        threading.Thread(target=start_https_443, args=(server, cert_path, key_path), daemon=True).start()
    else:
        server_log(f"[*] HTTP SignOn service listening on http://127.0.0.1:{server.http_port} (plaintext)")

    server_log(f"[*] Waiting for Marathon.exe client connection...\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        server_log("[*] Server shutdown.")

if __name__ == "__main__":
    main()
