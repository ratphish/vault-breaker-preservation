import zlib

def fnv1_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = (h * 0x01000193) & 0xFFFFFFFF
        h ^= b
    return h

def fnv1a_32(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h

def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF

# Bungie tiger engine string hash (often FNV1a with lowercase or custom seed)
target_hash = 88915786 # 0x054CBF4A
print(f"Target hash: {target_hash} (0x{target_hash:08X})")

candidates = [
    "error.signon_error",
    "error.signon_denied",
    "error.signon_failed",
    "error.signon_cancelled",
    "error.signon_timeout",
    "signon_error",
    "signon_denied",
    "SQUIRREL",
    "squirrel",
    "kSignonErrorDenied",
    "kSignonError",
    "signon",
    "signon_denied_squirrel"
]

for c in candidates:
    for s in [c, c.lower(), c.upper()]:
        b = s.encode('utf-8')
        c32 = crc32(b)
        f1 = fnv1_32(b)
        f1a = fnv1a_32(b)
        if target_hash in (c32, f1, f1a):
            print(f"MATCH FOUND: {s}")
            if target_hash == c32: print("  Hash type: CRC32")
            if target_hash == f1: print("  Hash type: FNV1")
            if target_hash == f1a: print("  Hash type: FNV1a")
