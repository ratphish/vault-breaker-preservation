"""Bungie Access Protocol (BAP) wire codec and frame processor.

Grounded in Project Dawn (Destiny 2 Build 86657) and Marathon (Build 26136895)
recovered specifications (isinternets/d2-research Chapter 4).
"""
import struct
from dataclasses import dataclass
from typing import Optional, Tuple, Union

# BAP Frame Types
FRAME_TYPE_PLAINTEXT_REQUEST = 0x00
FRAME_TYPE_AUTHENTICATED_GCM = 0x01
FRAME_TYPE_PLAINTEXT_BOOTSTRAP = 0x02

# BAP Magic byte
BAP_OUTER_MAGIC = 0x01

# Status Codes
BAP_STATUS_OK = 200
BAP_STATUS_BAD_REQUEST = 400
BAP_STATUS_UNAUTHORIZED = 401
BAP_STATUS_NOT_FOUND = 404
BAP_STATUS_INTERNAL_ERROR = 500

# Recognized Service Identifiers from Project Dawn & Marathon
SERVICE_ACTIVITY_SESSION_ALLOCATION = 6      # Request 6 -> Response 7
SERVICE_ACTIVITY_SESSION_RESPONSE = 7
SERVICE_ACTIVITY_MESSAGE = 8                 # Request 8 -> Notification 9
SERVICE_ACTIVITY_NOTIFICATION = 9
SERVICE_WEB_SERVICE_ENVELOPE = 10            # Request 10 -> Response 11
SERVICE_WEB_SERVICE_RESPONSE = 11
SERVICE_ACTIVITY_HOST_ENDPOINT = 16          # Request 16 -> Response 17
SERVICE_ACTIVITY_HOST_RESPONSE = 17
SERVICE_CLIENT_CONFIGURATION = 18            # Request 18 -> Response 19
SERVICE_CLIENT_CONFIG_RESPONSE = 19
SERVICE_PURCHASED_OFFERS = 21                # Request 21 -> Response 22
SERVICE_OFFERS_RESPONSE = 22
SERVICE_ACCOUNT_TRANSLATION = 23             # Request 23 -> Response 24
SERVICE_ACCOUNT_RESPONSE = 24
SERVICE_SERVER_HELLO = 25                    # Request 25 -> Response 26
SERVICE_HELLO_RESPONSE = 26
SERVICE_CHANNEL_START = 30                   # Request 30 -> Response 31
SERVICE_CHANNEL_START_RESPONSE = 31
SERVICE_SKILL_RECORDS = 34                   # Request 34 -> Response 35
SERVICE_SKILL_RESPONSE = 35
SERVICE_MATCHMAKING_REQUEST = 42             # Request 42 -> Response 43
SERVICE_MATCHMAKING_RESPONSE = 43
SERVICE_KEEPALIVE_PING = 250                 # Request 250 -> Response 251
SERVICE_KEEPALIVE_PONG = 251

@dataclass
class BapRequest:
    service_id: int
    task_id: int
    payload: bytes
    frame_type: int = FRAME_TYPE_PLAINTEXT_REQUEST

@dataclass
class BapResponse:
    service_id: int
    task_id: int
    status: int
    payload: bytes
    frame_type: int = FRAME_TYPE_PLAINTEXT_REQUEST

@dataclass
class BapNotification:
    service_id: int
    sequence: int
    payload: bytes
    frame_type: int = FRAME_TYPE_PLAINTEXT_REQUEST

def encode_outer_frame(payload: bytes, frame_type: int = FRAME_TYPE_PLAINTEXT_REQUEST) -> bytes:
    """Encode a raw payload into a 6-byte BAP outer header followed by payload."""
    header = struct.pack(">BBI", BAP_OUTER_MAGIC, frame_type, len(payload))
    return header + payload

def decode_outer_frame(data: bytes, offset: int = 0) -> Tuple[Optional[bytes], int, int]:
    """Decode a BAP outer frame.
    Returns (payload, frame_type, new_offset) if a complete frame is present,
    or (None, -1, offset) if more bytes are needed.
    """
    if len(data) - offset < 6:
        return None, -1, offset
    
    magic, frame_type, length = struct.unpack_from(">BBI", data, offset)
    if magic != BAP_OUTER_MAGIC:
        raise ValueError(f"Invalid BAP outer magic: expected 0x01, got {hex(magic)}")
    
    if len(data) - offset < 6 + length:
        return None, -1, offset  # Partial frame, wait for more data
    
    payload = data[offset + 6 : offset + 6 + length]
    return payload, frame_type, offset + 6 + length

def decode_inner_request(payload: bytes, frame_type: int = FRAME_TYPE_PLAINTEXT_REQUEST) -> BapRequest:
    """Decode an inner BAP request (2B service_id, 4B task_id, payload)."""
    if len(payload) < 6:
        raise ValueError(f"Inner request too short: {len(payload)} < 6")
    service_id, task_id = struct.unpack_from(">HI", payload, 0)
    body = payload[6:]
    return BapRequest(service_id=service_id, task_id=task_id, payload=body, frame_type=frame_type)

def encode_inner_response(service_id: int, task_id: int, status: int = BAP_STATUS_OK, payload: bytes = b"") -> bytes:
    """Encode an inner BAP response (2B service_id, 4B task_id, 2B status, payload)."""
    header = struct.pack(">HIH", service_id, task_id, status)
    return header + payload

def encode_server_notification(service_id: int, sequence: int, payload: bytes = b"") -> bytes:
    """Encode an inner BAP notification (2B service_id, 4B sequence, NO status field!)."""
    header = struct.pack(">HI", service_id, sequence)
    return header + payload

def build_response_frame(service_id: int, task_id: int, status: int = BAP_STATUS_OK,
                         payload: bytes = b"", frame_type: int = FRAME_TYPE_PLAINTEXT_REQUEST) -> bytes:
    """Convenience helper to encode inner response and wrap in outer frame."""
    inner = encode_inner_response(service_id, task_id, status, payload)
    return encode_outer_frame(inner, frame_type)

def build_notification_frame(service_id: int, sequence: int,
                            payload: bytes = b"", frame_type: int = FRAME_TYPE_PLAINTEXT_REQUEST) -> bytes:
    """Convenience helper to encode inner notification and wrap in outer frame."""
    inner = encode_server_notification(service_id, sequence, payload)
    return encode_outer_frame(inner, frame_type)
