"""Public-only diagnostics for locally authenticated BAP service 304."""
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

from marathon_protobuf import decode_varint


def fields(data):
    result = {}
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        number, wire = divmod(tag, 8)
        if number == 0:
            raise ValueError("invalid protobuf tag")
        if wire == 0:
            value, pos = decode_varint(data, pos)
        else:
            if wire == 2:
                size, pos = decode_varint(data, pos)
            elif wire in (1, 5):
                size = 8 if wire == 1 else 4
            else:
                raise ValueError("unsupported protobuf wire type")
            if size > len(data) - pos:
                raise ValueError("truncated protobuf field")
            value = data[pos:pos + size]
            pos += size
        result.setdefault((number, wire), []).append(value)
    return result


def one(message, tag, wire, default=None):
    matches = message.get((tag, wire), [])
    if len(matches) > 1:
        raise ValueError("duplicate singular field")
    return matches[0] if matches else default


def public_record(request):
    payload = bytes(request.payload)
    row = dict(utc=datetime.now(timezone.utc).isoformat(), task=request.task_id,
               request_bytes=len(payload), request_sha256=hashlib.sha256(payload).hexdigest())
    # 304 descriptor field 3 wraps CMsgSteamDatagramCertificateRequest.
    # Test both header boundaries using the nested public-key schema.
    for offset in ([2, 0] if payload.startswith(bytes(2)) else [0]):
        try:
            outer = fields(payload[offset:])
            csr = fields(one(outer, 3, 2, b""))
            cert = fields(one(csr, 1, 2, b""))
            key = one(cert, 2, 2, b"")
            if one(cert, 1, 0) != 1 or len(key) != 32:
                continue
            identity = {}
            name = one(cert, 12, 2)
            if name is not None:
                identity["identity_string"] = name.decode("utf-8")
            steam_id = one(cert, 4, 1)
            if steam_id is not None:
                identity["legacy_steam_id"] = str(int.from_bytes(steam_id, "little"))
            legacy = one(cert, 11, 2)
            if legacy is not None:
                identity["legacy_binary_hex"] = legacy.hex()
            return dict(row, status="decoded", body_offset=offset, key_type="ED25519",
                        public_key_hex=key.hex(), public_key_sha256=hashlib.sha256(key).hexdigest(),
                        identity=identity or None)
        except ValueError:
            continue
    return dict(row, status="unrecognized_request_shape")


def save_public_record(directory, request):
    row = public_record(request)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / ("ssc304-" + uuid4().hex + ".json")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(row, stream, indent=2)
    return path, row["status"]
