import struct
import sys

def decode_protobuf(data, depth=0):
    idx = 0
    indent = '  ' * depth
    while idx < len(data):
        # varint tag
        tag = 0
        shift = 0
        while idx < len(data):
            b = data[idx]
            idx += 1
            tag |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        field_num = tag >> 3
        wire_type = tag & 7
        if wire_type == 0: # varint
            val = 0
            shift = 0
            while idx < len(data):
                b = data[idx]
                idx += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            print(f'{indent}Field {field_num} (varint): {val} (0x{val:x})')
        elif wire_type == 1: # 64-bit
            val = struct.unpack('<Q', data[idx:idx+8])[0]
            idx += 8
            print(f'{indent}Field {field_num} (64-bit): {val} (0x{val:x})')
        elif wire_type == 2: # length-delimited
            length = 0
            shift = 0
            while idx < len(data):
                b = data[idx]
                idx += 1
                length |= (b & 0x7F) << shift
                if not (b & 0x80): break
                shift += 7
            content = data[idx:idx+length]
            idx += length
            # Try to decode as UTF-8 or submessage
            try:
                s = content.decode('utf-8')
                if all(c.isprintable() or c in '\r\n\t' for c in s) and len(s) > 0:
                    print(f'{indent}Field {field_num} (string, len={length}): "{s}"')
                    continue
            except:
                pass
            print(f'{indent}Field {field_num} (bytes, len={length}): {content[:32].hex()}...')
            # Try recursive protobuf if looks plausible
            if length > 2:
                try:
                    decode_protobuf(content, depth + 1)
                except Exception:
                    pass
        elif wire_type == 5: # 32-bit
            val = struct.unpack('<I', data[idx:idx+4])[0]
            idx += 4
            print(f'{indent}Field {field_num} (32-bit): {val} (0x{val:x})')
        else:
            print(f'{indent}Unknown wire type {wire_type} at {idx}')
            break

path = sys.argv[1] if len(sys.argv) > 1 else 'D:/Marathon-live/signon_req_1794251023_59812.bin'
with open(path, 'rb') as f:
    d = f.read()
print(f'File: {path} ({len(d)} bytes)')
decode_protobuf(d)
