import sys
sys.path.append('scripts')
from marathon_protobuf import ProtobufWriter, ProtobufReader, encode_varint
import struct

raw_field15 = bytes.fromhex("c88fbb01828080810e818080810e")
print(f"Raw field 15 bytes ({len(raw_field15)}): {raw_field15.hex()}")

# If packed as bytes:
w = ProtobufWriter()
w.bytes(10, raw_field15)
out = w.build()
print(f"Packed field 10 ({len(out)} bytes): {out.hex()}")

# Parse back:
reader = ProtobufReader(out)
f = reader.parse()
print(f"Parsed: {f}")
