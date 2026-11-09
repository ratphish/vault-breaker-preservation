import sys
sys.path.append('scripts')
from marathon_server import MarathonServer
from marathon_protobuf import ProtobufReader

server = MarathonServer()
with open(r'D:\Marathon-live\signon_req_1794256247_49843.bin', 'rb') as f:
    ticket = f.read()

status, payload = server.handle_signon_request(ticket)
print(f"Server response status: {status}, size: {len(payload)} bytes")

reader = ProtobufReader(payload)
fields = reader.parse()
for fnum, wtype, val in fields:
    if wtype == 2:
        print(f"Response Field {fnum} (Length-delimited, {len(val)} bytes):")
        try:
            sub = ProtobufReader(val).parse()
            for sfnum, swtype, sval in sub:
                if swtype == 2:
                    try:
                        print(f"   SubField {sfnum} (string): {sval.decode('utf-8')}")
                    except:
                        print(f"   SubField {sfnum} (bytes, len {len(sval)}): {sval[:20].hex()}...")
                else:
                    print(f"   SubField {sfnum} (type {swtype}): {sval}")
        except:
            print(f"   Raw bytes: {val.hex()}")
    else:
        print(f"Response Field {fnum} (type {wtype}): {val}")
