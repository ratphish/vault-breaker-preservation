import sys
sys.path.append(r'D:\vault-breaker-preservation\scripts')
from marathon_protobuf import ProtobufWriter, ProtobufReader

def test_response():
    player_id = 76561198000001001
    session_token = bytes([0xAA] * 32)
    encryption_key = bytes([0xBB] * 32)
    auth_key = bytes([0xCC] * 32)
    
    # Success sub-message
    success_sub = ProtobufWriter()
    success_sub.bytes(1, bytes(16))  # 16 zero reserved bytes
    success_sub.bytes(2, encryption_key)
    success_sub.bytes(3, auth_key)
    success_sub.bytes(4, session_token)
    success_sub.varint(5, 86400)
    success_sub.varint(6, 0x0100007F)  # 127.0.0.1
    success_sub.varint(7, 7777)
    
    # Common info sub-message
    common_info_sub = ProtobufWriter()
    common_info_sub.varint(1, 1) # membership_id
    common_info_sub.varint(2, 1) # silo
    
    # Entitlements sub-message
    entitlements_sub = ProtobufWriter()
    entitlements_sub.varint(1, 3065800)
    
    response = ProtobufWriter()
    response.varint(1, 0) # Error 0
    response.message(2, success_sub)
    response.message(4, common_info_sub)
    response.varint(5, 1)
    response.string(6, "248199.26.10.21.2300.gol_retail.rc")
    response.varint(8, 0)
    response.message(10, entitlements_sub)
    response.varint(12, 1794249368)
    response.string(13, "GOLRETAIL")
    response.varint(14, 0x0100007F)
    
    payload = response.build()
    print(f"Total payload size: {len(payload)} bytes")
    
    reader = ProtobufReader(payload)
    for tag, wtype, val in reader.parse():
        print(f"Field {tag} (type {wtype}): {val if wtype != 2 else f'len={len(val)}'}")

test_response()
