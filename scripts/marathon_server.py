"""Marathon Standalone Offline Server Emulator (Project Dawn Architecture).

Replicates Bungie live services (SignOn Web API, BAP, and Activity Hosting)
to enable standalone offline execution and modding for Marathon (Build 26136895).
Supports single-player offline preservation with multi-player co-op fireteam readiness.
"""
import os
import time
import struct
import random
import socket
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from marathon_protobuf import ProtobufWriter, ProtobufReader, encode_varint
from marathon_bap import (
    BapRequest, BapResponse, BapNotification,
    encode_outer_frame, decode_outer_frame,
    decode_inner_request, encode_inner_response, encode_server_notification,
    build_response_frame, build_notification_frame,
    BAP_STATUS_OK,
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

class MarathonServer:
    """Core state engine and service dispatcher for Marathon offline emulation."""
    def __init__(self, host: str = "127.0.0.1", http_port: int = 8080, bap_port: int = 7777,
                 default_mod_config: Optional[VaultBreakerModConfig] = None):
        self.host = host
        self.http_port = http_port
        self.bap_port = bap_port
        self.mod_config = default_mod_config or VaultBreakerModConfig()
        
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
        
        # Big-endian 127.0.0.1 network byte order (2130706433 / 0x7F000001)
        relay_ip_uint32 = 0x7F000001
        
        # Build Protobuf response matching Project Dawn's Writer
        success_sub = ProtobufWriter()
        success_sub.bytes(PB_SUB_RESERVED, bytes(16))  # 16 zero reserved bytes
        success_sub.bytes(PB_SUB_ENCRYPTION_KEY, encryption_key)
        success_sub.bytes(PB_SUB_AUTH_KEY, auth_key)
        success_sub.bytes(PB_SUB_SESSION_TOKEN, session_token)
        success_sub.varint(PB_SUB_EXPIRY, 86400)
        success_sub.varint(PB_SUB_RELAY_ADDR, relay_ip_uint32)
        success_sub.varint(PB_SUB_RELAY_PORT, self.bap_port)
        
        # Subfield 12: client_config (cookie=1, social_matchmaking_id=1, keys)
        client_config_sub = ProtobufWriter()
        client_config_sub.varint(1, 1)  # cookie = 1
        client_config_sub.bytes(3, b"\x11" * 16)
        client_config_sub.bytes(4, b"\x22" * 16)
        success_sub.message(PB_SUB_CLIENT_CONFIG, client_config_sub)
        
        # Direct Settings configuration URLs (port 80)
        success_sub.string(PB_SUB_CFG_A, "http://127.0.0.1/cfg_a/")
        success_sub.string(PB_SUB_CFG_B, "http://127.0.0.1/cfg_b/")
        success_sub.string(PB_SUB_CFG_C, "http://127.0.0.1/cfg_c/")
        
        common_info_sub = ProtobufWriter()
        common_info_sub.varint(PB_COMMON_ID, membership_id)  # 1
        common_info_sub.varint(PB_COMMON_SILO, 1)
        config_blob = struct.pack("<IIB", 0x00123456, 0x007B620F, 0x10) + bytes(range(16)) + bytes(4)
        common_info_sub.bytes(PB_COMMON_CONFIG_BLOB, config_blob)
        
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
        response.string(PB_TAG_BUILD_VERSION, "d2legacy")
        response.varint(PB_TAG_CAPABILITY_FLAGS, 0)
        
        # Tag 10: length-delimited submessage with repeated varint 1
        ent_sub = ProtobufWriter()
        for ent_id in client_entitlements:
            ent_sub.varint(1, ent_id)
        response.message(PB_TAG_ENTITLEMENTS, ent_sub)
        
        response.varint(PB_TAG_SERVER_TIME, int(time.time()))
        response.string(PB_TAG_ENVIRONMENT, "live")
        response.varint(PB_TAG_EXTERNAL_ADDR, relay_ip_uint32)
        
        payload = response.build()
        server_log(f"[SignOn] Granted entitlements: {client_entitlements} (payload {len(payload)}B)")
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

    def dispatch_bap_request(self, request: BapRequest, player: Optional[PlayerSession] = None) -> BapResponse:
        """Processes an incoming BAP request and routes to the appropriate service."""
        svc = request.service_id
        task = request.task_id
        
        # Service 250: Keepalive
        if svc == SERVICE_KEEPALIVE_PING:
            return BapResponse(service_id=SERVICE_KEEPALIVE_PONG, task_id=task,
                               status=BAP_STATUS_OK, payload=b"")
        
        # Service 25: Server Hello
        elif svc == SERVICE_SERVER_HELLO:
            # Return 84-byte hello envelope parameters
            hello_payload = bytearray(84)
            struct.pack_into(">I", hello_payload, 0, 1)  # Version 1
            return BapResponse(service_id=SERVICE_HELLO_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=bytes(hello_payload))
        
        # Service 30: Channel Start & Nonce Echo
        elif svc == SERVICE_CHANNEL_START:
            nonce_echo = request.payload[:12] if len(request.payload) >= 12 else bytes(12)
            return BapResponse(service_id=SERVICE_CHANNEL_START_RESPONSE, task_id=task,
                               status=BAP_STATUS_OK, payload=nonce_echo)
        
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

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class SignOnHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_instance: MarathonServer = None  # Injected

    def do_POST(self):
        client_ip, client_port = self.client_address
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b""
        
        server_log(f"[HTTPS POST] from {client_ip}:{client_port} -> {self.path} ({content_len} bytes)")
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
        client_ip, client_port = self.client_address
        server_log(f"[HTTP GET] from {client_ip}:{client_port} -> {self.path}")
        if "/shutdown" in self.path:
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
        if "GetSDRConfig" in self.path:
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
                        break
                    except Exception:
                        pass

        # Direct Settings / configuration request handling
        from urllib.parse import urlparse
        parsed_path = urlparse(self.path).path
        filename = os.path.basename(parsed_path)

        # Check local files under config/direct_settings/
        if local_content is None:
            candidate_dirs = [
                os.path.join(os.path.dirname(__file__), "..", "config", "direct_settings"),
                r"D:\Marathon-live\config\direct_settings",
                os.path.join(os.getcwd(), "config", "direct_settings")
            ]
            for cdir in candidate_dirs:
                cpath = os.path.join(cdir, filename)
                if os.path.isfile(cpath):
                    try:
                        with open(cpath, "rb") as cf:
                            local_content = cf.read()
                        server_log(f"[DirectSettings] Serving local config {cpath} ({len(local_content)} bytes)")
                        break
                    except Exception:
                        pass

            if local_content is None:
                local_content = b"{}\n"
                server_log(f"[DirectSettings] Serving default JSON ({len(local_content)} bytes) for {self.path}")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(local_content)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(local_content)
        self.wfile.flush()

    def do_HEAD(self):
        client_ip, client_port = self.client_address
        server_log(f"[HTTP HEAD] from {client_ip}:{client_port} -> {self.path}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, HEAD, OPTIONS")
        self.end_headers()

    def log_message(self, format, *args):
        # Redirect standard HTTP access logs to server_log
        server_log(f"[HTTP Access] " + (format % args))

def start_bap_listener(server_instance: MarathonServer):
    """TCP listener for BAP frames."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server_instance.host, server_instance.bap_port))
    sock.listen(5)
    server_log(f"[*] BAP Service Router listening on TCP {server_instance.host}:{server_instance.bap_port}")
    
    while True:
        try:
            client_sock, client_addr = sock.accept()
            server_log(f"[BAP] Client connected from {client_addr}")
            threading.Thread(target=handle_bap_connection, args=(client_sock, server_instance), daemon=True).start()
        except Exception as e:
            server_log(f"[-] BAP accept error: {e}")
            break

def handle_bap_connection(client_sock: socket.socket, server_instance: MarathonServer):
    buf = bytearray()
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
                
                req = decode_inner_request(payload)
                server_log(f"[BAP] Svc {req.service_id} (Task {req.task_id}) <- {len(req.payload)} bytes")
                
                resp = server_instance.dispatch_bap_request(req)
                resp_frame = build_response_frame(resp.service_id, resp.task_id, resp.status, resp.payload)
                client_sock.sendall(resp_frame)
                server_log(f"[BAP] Svc {resp.service_id} (Task {resp.task_id}) -> Status {resp.status} ({len(resp.payload)} bytes)")
    except Exception as e:
        pass
    finally:
        client_sock.close()

def start_plaintext_http(server: MarathonServer, port: int = 8081):
    httpd = ThreadedHTTPServer(("0.0.0.0", port), SignOnHTTPHandler)
    server_log(f"[*] Plaintext HTTP fallback listening on http://127.0.0.1:{port}")
    httpd.serve_forever()

def main():
    server = MarathonServer(host="0.0.0.0", http_port=8080, bap_port=7777)
    SignOnHTTPHandler.server_instance = server
    
    print("=" * 65, flush=True)
    print("  MARATHON STANDALONE EMULATION SERVER (Project Dawn Architecture)", flush=True)
    print("  Target Build: 26136895 (Cryo Archive Vault Breaker)", flush=True)
    print("=" * 65, flush=True)
    server_log(f"[*] Configured Mod Route: {server.mod_config.tier_1_vaults} -> {server.mod_config.tier_2_vaults} -> {server.mod_config.tier_3_vaults} -> {server.mod_config.tier_4_vaults}")
    
    bap_thread = threading.Thread(target=start_bap_listener, args=(server,), daemon=True)
    bap_thread.start()

    def start_bap_udp(server):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", server.bap_port))
            server_log(f"[*] BAP Service Router listening on UDP 0.0.0.0:{server.bap_port}")
            while True:
                data, addr = sock.recvfrom(65535)
                server_log(f"[UDP 7777] Received {len(data)} bytes from {addr}. Preview: {data[:32].hex()}")
        except Exception as e:
            server_log(f"[-] UDP 7777 bind warning: {e}")

    bap_udp_thread = threading.Thread(target=start_bap_udp, args=(server,), daemon=True)
    bap_udp_thread.start()
    
    def start_http_80(server):
        try:
            httpd_80 = ThreadedHTTPServer(("0.0.0.0", 80), SignOnHTTPHandler)
            server_log("[*] Plaintext HTTP Direct Settings service active on http://127.0.0.1:80")
            httpd_80.serve_forever()
        except Exception as e:
            server_log(f"[-] Port 80 HTTP bind warning: {e}")

    http_80_thread = threading.Thread(target=start_http_80, args=(server,), daemon=True)
    http_80_thread.start()

    plain_thread = threading.Thread(target=start_plaintext_http, args=(server, 8081), daemon=True)
    plain_thread.start()

    def start_https_443(server, cert_path, key_path):
        try:
            httpd_443 = ThreadedHTTPServer(("0.0.0.0", 443), SignOnHTTPHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            httpd_443.socket = ctx.wrap_socket(httpd_443.socket, server_side=True)
            server_log("[*] HTTPS SignOn service active with TLS on https://127.0.0.1:443 (Port 443)")
            httpd_443.serve_forever()
        except Exception as e:
            server_log(f"[-] Port 443 HTTPS bind warning: {e}")

    cert_path = None
    key_path = None
    for base in [os.path.dirname(__file__), os.path.join(os.path.dirname(__file__), ".."), os.getcwd(), r"D:\vault-breaker-preservation", r"D:\Marathon-live"]:
        c = os.path.join(base, "server.crt")
        k = os.path.join(base, "server.key")
        if os.path.exists(c) and os.path.exists(k):
            cert_path = os.path.abspath(c)
            key_path = os.path.abspath(k)
            break

    httpd = ThreadedHTTPServer(("0.0.0.0", server.http_port), SignOnHTTPHandler)
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
