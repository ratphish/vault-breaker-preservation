"""Inspect the preserved startup array using the recovered operation-3 layout."""
import argparse
import hashlib
import json
import struct
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("asset", type=Path)
args = parser.parse_args()
data = args.asset.read_bytes()
digest = hashlib.sha256(data).hexdigest()
expected = "e461e1937fc88f56c6cb84d28c89a89c4d81acbdaf79f288a872dff97b85f446"
if digest != expected:
    raise ValueError("expected the preserved 80A6A052 startup asset")

count = struct.unpack_from("<i", data, 8)[0]
relative = struct.unpack_from("<q", data, 0x10)[0]
# 0x15d063889..0x15d06389b computes base + relative + (3 * index + 5) * 8.
first = relative + 0x28
stride = 24
if count < 0 or first < 0 or first + count * stride > len(data):
    raise ValueError("startup array exceeds the preserved asset")

mask_relative = struct.unpack_from("<q", data, 0x20)[0]
mask_offset = 0x30 + mask_relative
mask_word_count = (count + 31) // 32
if mask_relative == 0 or mask_offset < 0 or mask_offset + mask_word_count * 4 > len(data):
    raise ValueError("startup operation-4 mask exceeds the preserved asset")
mask_words = struct.unpack_from(f"<{mask_word_count}I", data, mask_offset)

entries = []
for index in range(count):
    offset = first + index * stride
    tag, flags, field_08, field_10 = struct.unpack_from("<IIQQ", data, offset)
    entries.append({
        "index": index,
        "file_offset": hex(offset),
        "tag": f"{tag:08X}",
        "flags": hex(flags),
        "field_08": hex(field_08),
        "field_10": hex(field_10),
        "operation_4_bit": bool(mask_words[index // 32] & (1 << (index % 32))),
    })
investment = [entry for entry in entries if entry["tag"] == "80A6A004"]
if len(investment) != 1 or investment[0]["file_offset"] != "0x60":
    raise ValueError("investment reference does not match the independently extracted location")

print(json.dumps({
    "asset": "80A6A052",
    "path": str(args.asset.resolve()),
    "sha256": digest,
    "size": len(data),
    "count": count,
    "relative": hex(relative),
    "first_entry": hex(first),
    "stride": stride,
    "entries_end": hex(first + count * stride),
    "operation_4_mask": {
        "file_offset": hex(mask_offset),
        "word_count": mask_word_count,
        "words": [hex(word) for word in mask_words],
        "writer": "0x14dcf7137",
    },
    "entries": entries,
    "investment_entry": investment[0],
    "authority": "preserved asset bytes interpreted with independently decoded native arithmetic",
    "limitations": [
        "No runtime asset mapping or event invocation is supplied.",
        "field_08 and field_10 names denote offsets, not verified semantic types.",
    ],
}, indent=2))
