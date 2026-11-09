path = r'D:\vault-breaker-preservation\scripts\marathon_server.py'
with open(path, 'r', encoding='utf-8') as f:
    code = f.read()

old_block = """        # Entitlements submessage granting all requested & required entitlements
        entitlements_sub = ProtobufWriter()
        for ent_id in client_entitlements:
            entitlements_sub.varint(1, ent_id)
        server_log(f"[SignOn] Granted entitlements: {client_entitlements}")
        
        build_str = build or BUILD_VERSION_STRING
        
        response = ProtobufWriter()
        # NOTE: Do NOT emit PB_TAG_ERROR on success! In Tiger Engine Protobuf, Tag 1 is an error enum.
        # Emitting Tag 1 with value 0 sets error = kSignonErrorDenied (0x054CBF4A / 88915786), causing SQUIRREL.
        response.message(PB_TAG_SUCCESS, success_sub)
        response.message(PB_TAG_COMMON_INFO, common_info_sub)
        response.varint(PB_TAG_SILO_ID, 1)
        response.string(PB_TAG_BUILD_VERSION, build_str)
        response.varint(PB_TAG_CAPABILITY_FLAGS, 0)
        response.message(PB_TAG_ENTITLEMENTS, entitlements_sub)"""

new_block = """        # Encode granted entitlements as packed varints (wire type 2), exactly matching
        # the wire format expected by Tiger Engine repeated uint64 owned_entitlements = 10.
        # DO NOT encode as a submessage with tag 1; that injects 0x08 before each ID,
        # corrupting the list and causing error.signon_error (SQUIRREL)!
        if raw_field15_bytes:
            packed_entitlements = raw_field15_bytes
        else:
            packed_buf = bytearray()
            for ent_id in client_entitlements:
                packed_buf.extend(encode_varint(ent_id))
            packed_entitlements = bytes(packed_buf)
        server_log(f"[SignOn] Granted entitlements (packed {len(packed_entitlements)}B): {client_entitlements}")
        
        build_str = build or BUILD_VERSION_STRING
        
        response = ProtobufWriter()
        # NOTE: Do NOT emit PB_TAG_ERROR on success! In Tiger Engine Protobuf, Tag 1 is an error enum.
        # Emitting Tag 1 with value 0 sets error = kSignonErrorDenied (0x054CBF4A / 88915786), causing SQUIRREL.
        response.message(PB_TAG_SUCCESS, success_sub)
        response.message(PB_TAG_COMMON_INFO, common_info_sub)
        response.varint(PB_TAG_SILO_ID, 1)
        response.string(PB_TAG_BUILD_VERSION, build_str)
        response.varint(PB_TAG_CAPABILITY_FLAGS, 0)
        response.bytes(PB_TAG_ENTITLEMENTS, packed_entitlements)"""

# Also ensure raw_field15_bytes is defined and captured
old_f15 = """                    if fnum == 15:
                        v_i = 0"""

new_f15 = """                    if fnum == 15:
                        raw_field15_bytes = val_bytes
                        v_i = 0"""

old_init = """        # Extract requested entitlements from client request Field 15
        client_entitlements = [3065800, 3760193537, 3760193538]"""

new_init = """        # Extract requested entitlements from client request Field 15
        client_entitlements = [3065800, 3760193537, 3760193538]
        raw_field15_bytes = None"""

# Normalize \r\n to \n for matching
code_norm = code.replace('\r\n', '\n')
old_block_norm = old_block.replace('\r\n', '\n')
new_block_norm = new_block.replace('\r\n', '\n')
old_f15_norm = old_f15.replace('\r\n', '\n')
new_f15_norm = new_f15.replace('\r\n', '\n')
old_init_norm = old_init.replace('\r\n', '\n')
new_init_norm = new_init.replace('\r\n', '\n')

assert old_init_norm in code_norm, "old_init not found"
code_norm = code_norm.replace(old_init_norm, new_init_norm, 1)

assert old_f15_norm in code_norm, "old_f15 not found"
code_norm = code_norm.replace(old_f15_norm, new_f15_norm, 1)

assert old_block_norm in code_norm, "old_block not found"
code_norm = code_norm.replace(old_block_norm, new_block_norm, 1)

with open(path, 'w', encoding='utf-8') as f:
    f.write(code_norm)

print("SUCCESS: Patched packed entitlements into scripts/marathon_server.py!")
