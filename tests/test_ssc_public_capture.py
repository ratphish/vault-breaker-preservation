import hashlib
from types import SimpleNamespace

from marathon_protobuf import ProtobufWriter
from ssc_public_capture import public_record, save_public_record


def example(identity=False):
    key = bytes(range(32))
    cert = ProtobufWriter().varint(1, 1).bytes(2, key).build()
    if identity:
        cert += b"\x21" + (12345).to_bytes(8, "little")
    csr = ProtobufWriter().bytes(1, cert).build()
    return SimpleNamespace(payload=b"\0\0" + ProtobufWriter().bytes(3, csr).build(), task_id=2)


def test_key_and_identity_are_separate_from_request_digest():
    plain = public_record(example())
    named = public_record(example(True))
    assert plain["status"] == "decoded" and plain["identity"] is None
    assert named["identity"] == {"legacy_steam_id": "12345"}
    assert plain["public_key_hex"] == bytes(range(32)).hex()
    assert named["public_key_sha256"] == plain["public_key_sha256"]
    assert named["request_sha256"] != plain["request_sha256"]


def test_malformed_is_recorded_without_dumping_payload(tmp_path):
    req = SimpleNamespace(task_id=2, payload=b"unexpected-shape")
    path, status = save_public_record(tmp_path, req)
    assert status == "unrecognized_request_shape"
    data = path.read_text()
    assert hashlib.sha256(req.payload).hexdigest() in data
    assert "unexpected-shape" not in data
