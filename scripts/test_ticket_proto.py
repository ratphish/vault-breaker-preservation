import zlib
import struct
import sys
from pathlib import Path

# Add scripts directory
sys.path.append(r"D:\vault-breaker-preservation\scripts")
from marathon_protobuf import ProtobufWriter, ProtobufReader

raw_bin = Path(r"D:\Marathon-live\pDataToInclude_raw.bin")
if raw_bin.exists():
    user_data = raw_bin.read_bytes()
else:
    user_data = b"\x00" * 24

print("User data length:", len(user_data), "hex:", user_data.hex())

inner_len = 128
inner_ticket = bytearray(inner_len)
inner_ticket[:len(user_data)] = user_data
for i in range(len(user_data), inner_len):
    inner_ticket[i] = (i * 7) & 0xFF

inner_bytes = bytes(inner_ticket)
crc = zlib.crc32(inner_bytes) & 0xFFFFFFFF

writer = ProtobufWriter()
writer.varint(1, 1)                      # ticket_version_no = 1
writer.varint(2, crc)                    # crc_encryptedticket
writer.varint(3, len(user_data))         # cb_encrypteduserdata = 24
writer.varint(4, inner_len - len(user_data)) # cb_encrypted_appownershipticket = 104
writer.bytes(5, inner_bytes)

proto_ticket = writer.build()
print("Protobuf ticket size:", len(proto_ticket))
print("Protobuf ticket hex:", proto_ticket.hex())

reader = ProtobufReader(proto_ticket)
for f_num, w_type, val in reader.parse():
    print(f"Field {f_num} (wire {w_type}): {val if not isinstance(val, bytes) else f'{len(val)} bytes'}")
