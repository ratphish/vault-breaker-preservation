path = r'D:\vault-breaker-preservation\scripts\marathon_server.py'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

target = 'common_info_sub.varint(PB_COMMON_SILO, 1)'
if target in text:
    replacement = 'common_info_sub.varint(PB_COMMON_SILO, 1)\n        config_blob = struct.pack("<IIB", 0x00123456, 0x007B620F, 20) + bytes(20)\n        common_info_sub.bytes(PB_COMMON_CONFIG_BLOB, config_blob)'
    text = text.replace(target, replacement, 1)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    print("SUCCESS: Added PB_COMMON_CONFIG_BLOB to marathon_server.py!")
else:
    print("ERROR: Target not found in marathon_server.py")
