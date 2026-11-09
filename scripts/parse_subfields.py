import sys
sys.path.append(r'D:\vault-breaker-preservation\scripts')
from marathon_protobuf import ProtobufReader

with open(r'D:\Marathon-live\signon_req_1794249368_58164.bin', 'rb') as f:
    data = f.read()

reader = ProtobufReader(data)
fields = dict()
for fnum, wtype, val in reader.parse():
    fields[fnum] = (wtype, val)

print("=== PARSING FIELD 2 ===")
f2_reader = ProtobufReader(fields[2][1])
for fnum, wtype, val in f2_reader.parse():
    if wtype == 2:
        print(f"  Field 2.{fnum}: (len={len(val)}) hex: {val.hex()}")
    else:
        print(f"  Field 2.{fnum}: INT: {val} (0x{val:X})")

print("\n=== PARSING FIELD 22 ===")
f22_reader = ProtobufReader(fields[22][1])
for fnum, wtype, val in f22_reader.parse():
    if wtype == 2:
        try:
            print(f"  Field 22.{fnum}: STRING: '{val.decode('utf-8')}'")
        except:
            print(f"  Field 22.{fnum}: BYTES (len={len(val)}): {val.hex()}")
    else:
        print(f"  Field 22.{fnum}: INT: {val} (0x{val:X})")
