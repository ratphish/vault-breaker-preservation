import sys
sys.path.append(r"D:\vault-breaker-preservation\scripts")
from marathon_protobuf import ProtobufReader

with open(r"D:\Marathon-live\signon_req_1794250439_56323.bin", "rb") as f:
    data = f.read()

r = ProtobufReader(data)
for fnum, wt, val in r.parse():
    if wt == 2:
        try:
            print(f"Field {fnum}: STR: '{val.decode('utf-8')}'")
        except:
            print(f"Field {fnum}: BYTES ({len(val)}): {val[:20].hex()}...")
    else:
        print(f"Field {fnum}: INT: {val} (0x{val:X})")
