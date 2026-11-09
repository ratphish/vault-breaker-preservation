import sys
sys.path.append(r"D:\vault-breaker-preservation\scripts")
from marathon_server import MarathonServer
from marathon_protobuf import ProtobufReader

server = MarathonServer()
status, payload = server.handle_signon_request(b"", platform="pc_x64", build="248199.26.10.21.2300.gol_retail.rc")

print(f"Generated payload: {len(payload)} bytes")
print("Hex:", payload.hex())

reader = ProtobufReader(payload)
for tag, wt, val in reader.parse():
    if wt == 0:
        print(f"Tag {tag} (varint): {val} (0x{val:X})")
    elif wt == 2:
        try:
            s = val.decode('utf-8')
            print(f"Tag {tag} (string): '{s}'")
        except:
            print(f"Tag {tag} (submessage/bytes, len={len(val)}):")
            try:
                sub = ProtobufReader(val)
                for stag, swt, sval in sub.parse():
                    if swt == 0:
                        print(f"  SubTag {stag} (varint): {sval} (0x{sval:X})")
                    else:
                        print(f"  SubTag {stag} (len={len(sval)}): {sval.hex()}")
            except Exception as e:
                print(f"  [Parse error]: {e}")
