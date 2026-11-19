import sys
sys.path.insert(0, 'scripts')
import json
from marathon_protobuf import ProtobufReader
from marathon_server import MarathonServer

server = MarathonServer()
# Synthetic steam ticket of 100 bytes
status, payload = server.handle_signon_request(b"\x00" * 100)

print(f"SignOn response status: {status}, length: {len(payload)} bytes")

def parse_pb(data, path=()):
    res = []
    reader = ProtobufReader(data)
    for fnum, wtype, val in reader.parse():
        curr_path = path + (fnum,)
        val_repr = val
        if wtype == 2:
            # Try parsing as submessage if known or if it parses cleanly
            try:
                sub = parse_pb(val, curr_path)
                if sub and len(sub) > 0:
                    val_repr = {"_submessage": sub}
                else:
                    val_repr = f"hex({val.hex()})"
            except Exception:
                val_repr = f"hex({val.hex()})"
        elif wtype == 0:
            val_repr = f"varint({val})"
        elif wtype == 5:
            val_repr = f"fixed32({val})"
        elif wtype == 1:
            val_repr = f"fixed64({val})"
        res.append({"field": fnum, "wire": wtype, "path": ".".join(map(str, curr_path)), "value": val_repr})
    return res

parsed = parse_pb(payload)
print(json.dumps(parsed, indent=2))
