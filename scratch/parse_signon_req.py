import sys
sys.path.append('scripts')
from marathon_protobuf import ProtobufReader

with open(r'D:\Marathon-live\signon_req_1794256247_49843.bin', 'rb') as f:
    data = f.read()

print(f"Request total size: {len(data)} bytes")
reader = ProtobufReader(data)
fields = reader.parse()
for fnum, wtype, val in fields:
    if wtype == 2:
        print(f"Field {fnum} (Length-delimited, {len(val)} bytes):")
        # Try parse submessage
        try:
            sub = ProtobufReader(val).parse()
            for sfnum, swtype, sval in sub:
                if swtype == 2:
                    try:
                        sub_str = sval.decode('utf-8')
                        print(f"   SubField {sfnum} (string): {sub_str}")
                    except:
                        print(f"   SubField {sfnum} (bytes, len {len(sval)}): {sval[:20].hex()}...")
                else:
                    print(f"   SubField {sfnum} (type {swtype}): {sval}")
        except:
            print(f"   Raw bytes: {val.hex()}")
    else:
        print(f"Field {fnum} (type {wtype}): {val}")
