import sys
sys.path.append(r"D:\vault-breaker-preservation\scripts")
from marathon_protobuf import ProtobufReader

with open(r"D:\Marathon-live\signon_req_1794250439_56323.bin", "rb") as f:
    data = f.read()

r = ProtobufReader(data)
fields = dict()
for fnum, wt, val in r.parse():
    fields[fnum] = (wt, val)

f22 = fields[22][1]
print("Field 22 len:", len(f22))
r22 = ProtobufReader(f22)
for fnum, wt, val in r22.parse():
    if wt == 2:
        try:
            print(f"  Field 22.{fnum} (str): '{val.decode('utf-8')}'")
        except:
            print(f"  Field 22.{fnum} (bytes, len={len(val)}): {val.hex()}")
    else:
        print(f"  Field 22.{fnum} (int): {val} (0x{val:X})")
