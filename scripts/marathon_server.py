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

    def handle_signon_request(self, steam_ticket: bytes, platform: str = "steam",
                              build: str = "26136895") -> Tuple[int, bytes]:
        """Handles POST /SignOn?platform=%s&build=%s.
        Returns (HTTP status code, Protobuf binary payload).
        """
        # Allocate deterministic session for player
        player_id = self.next_membership_id
        self.next_membership_id += 1
        
        session_token = bytes([random.randint(0, 255) for _ in range(16)])
        encryption_key = bytes([random.randint(0, 255) for _ in range(32)])
        auth_key = bytes([random.randint(0, 255) for _ in range(32)])
        display_name = f"Runner#{player_id % 10000:04d}"
        
        player = PlayerSession(
            membership_id=player_id,
            bungie_name=display_name,
            session_token=session_token,
            encryption_key=encryption_key,
            auth_key=auth_key,
            relay_port=self.bap_port
        )
        self.players[player_id] = player
        self.sessions_by_token[session_token] = player
        
        # Build Protobuf response matching Project Dawn's Writer
        success_sub = ProtobufWriter()
        success_sub.bytes(PB_SUB_RESERVED, bytes(16))  # 16 zero reserved bytes
        success_sub.bytes(PB_SUB_ENCRYPTION_KEY, encryption_key)
        success_sub.bytes(PB_SUB_AUTH_KEY, auth_key)
        success_sub.bytes(PB_SUB_SESSION_TOKEN, session_token)
        success_sub.varint(PB_SUB_EXPIRY, 86400)
        success_sub.varint(PB_SUB_RELAY_ADDR, struct.unpack("<I", socket.inet_aton(self.host))[0])
        success_sub.varint(PB_SUB_RELAY_PORT, self.bap_port)
        
        common_info_sub = ProtobufWriter()
        common_info_sub.varint(PB_COMMON_ID, player_id)
        common_info_sub.varint(PB_COMMON_SILO, 1)
        common_info_sub.bytes(PB_COMMON_CONFIG_BLOB, b"\x01\x00\x00\x00" + bytes(12))
        
        response = ProtobufWriter()
        response.varint(PB_TAG_ERROR, 0)
        response.message(PB_TAG_SUCCESS, success_sub)
        response.message(PB_TAG_COMMON_INFO, common_info_sub)
        response.varint(PB_TAG_SILO_ID, 1)
        response.string(PB_TAG_BUILD_VERSION, BUILD_VERSION_STRING)
        response.varint(PB_TAG_CAPABILITY_FLAGS, 0)
        response.bytes(PB_TAG_ENTITLEMENTS, b"\x01" * 8)
        response.varint(PB_TAG_SERVER_TIME, int(time.time()))
        response.string(PB_TAG_ENVIRONMENT, "live")
        response.varint(PB_TAG_EXTERNAL_ADDR, struct.unpack("<I", socket.inet_aton(self.host))[0])
        
        return 200, response.build()

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
