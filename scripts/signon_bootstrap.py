"""Opt-in Dawn bootstrap entry for a controlled Marathon compatibility test.

The wire format matches Dawn's shipped writer; captured Marathon code contains
matching magic/key comparisons. Its effect on the State 8 wait is unverified.
The caller must supply the native value; this module never invents a token.
"""
from pathlib import Path
import struct
from uuid import UUID

from marathon_protobuf import ProtobufReader, encode_varint


TOKEN_BYTES = 16
CONFIG_MAGIC = 0x00123456
CONTENT_TOKEN_KEY = 0x007B620F
SETTINGS_URL_KEY = 0x004A1E43
MANIFEST_SUFFIX_KEY = 0x0071D6ED
CONTENT_MANIFEST_URL = 'http://127.0.0.1/GolRetail/content_manifest/content_manifest.pb'
CONTENT_MANIFEST_FILE = Path(__file__).resolve().parents[1] / 'config' / 'content_manifest' / 'content_manifest.pb'
DIRECT_SETTINGS_URLS = ('http://manifest.goliath.deadorbit.net/GolRetail',) * 3
DIRECT_SETTINGS_MANIFEST_SUFFIX = (
    '/direct_settings/manifest/95EA841F43B4E9D27C957EC7427894B5C6BA035F.json'
)


def manifest_identity(path: Path) -> bytes:
    # The version-1 container has an 8-byte header and 256 bytes before the protobuf.
    body = path.read_bytes()
    if body[:8] != struct.pack('<Q', 1):
        raise ValueError('unsupported content manifest header')
    identities = [value for field, wire, value in ProtobufReader(body[264:]).parse()
                  if field == 5 and wire == 2]
    if len(identities) != 1:
        raise ValueError('expected one content manifest GUID in field 5')
    guid = identities[0].decode('ascii')
    if str(UUID(guid)) != guid.lower():
        raise ValueError('expected a hyphenated content manifest GUID')
    return identities[0]


def encode_bootstrap_entry(token: bytes, settings_urls=None, manifest_suffix=None, *, manifest_file=None) -> bytes:
    if not isinstance(token, bytes) or len(token) != TOKEN_BYTES:
        raise ValueError('bootstrap token must contain exactly 16 bytes')
    stream = bytearray(struct.pack('<II', CONFIG_MAGIC, CONTENT_TOKEN_KEY) + b'\x10' + token)
    if settings_urls is not None:
        if len(settings_urls) != 3:
            raise ValueError('expected three Direct Settings URLs')
        stream.extend(struct.pack('<I', SETTINGS_URL_KEY))
        for url in settings_urls:
            data = url.encode('ascii')
            if not 1 <= len(data) <= 255 or b'\0' in data:
                raise ValueError('URL must fit a 256-byte NUL-terminated slot')
            stream.extend(encode_varint(len(data)))
            stream.extend(data)
    if manifest_suffix is not None:
        data = manifest_suffix.encode('ascii')
        if not 1 <= len(data) <= 255 or b'\0' in data or not data.startswith(b'/'):
            raise ValueError('manifest suffix must start with / and fit a 256-byte NUL-terminated slot')
        stream.extend(struct.pack('<I', MANIFEST_SUFFIX_KEY))
        stream.extend(encode_varint(len(data)))
        stream.extend(data)
    if manifest_file is not None:
        for key, value in ((100, CONTENT_MANIFEST_URL.encode('ascii')), (101, manifest_identity(manifest_file))):
            stream.extend(struct.pack('<I', key))
            stream.extend(encode_varint(len(value)))
            stream.extend(value)
    return bytes(stream) + bytes(4)


def load_bootstrap_token(path: Path) -> bytes:
    # Bound the read and reject larger text/hex files or captures by length.
    with path.open('rb') as stream:
        token = stream.read(TOKEN_BYTES + 1)
    if len(token) != TOKEN_BYTES:
        raise ValueError('bootstrap token file must contain exactly 16 raw bytes')
    return token
