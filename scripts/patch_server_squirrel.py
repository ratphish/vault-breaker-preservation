"""Patches scripts/marathon_server.py to resolve SQUIRREL account mismatch and environment errors.
"""
server_path = 'scripts/marathon_server.py'
with open(server_path, 'r', encoding='utf-8') as f:
    code = f.read()

# Update player_id
code = code.replace(
    'player_id = self.next_membership_id\n        self.next_membership_id += 1',
    'player_id = 76561198000001001  # Hardcoded Steam ID to prevent SQUIRREL account mismatch'
)

# Update relay_addr and external_addr to 0x7F000001
code = code.replace(
    'success_sub.varint(PB_SUB_RELAY_ADDR, struct.unpack("<I", socket.inet_aton(relay_host))[0])',
    'success_sub.varint(PB_SUB_RELAY_ADDR, 0x7F000001)  # 127.0.0.1 in network byte order'
)
code = code.replace(
    'response.varint(PB_TAG_EXTERNAL_ADDR, struct.unpack("<I", socket.inet_aton(relay_host))[0])',
    'response.varint(PB_TAG_EXTERNAL_ADDR, 0x7F000001)  # 127.0.0.1 in network byte order'
)

# Update environment to GOLRETAIL
code = code.replace(
    'response.string(PB_TAG_ENVIRONMENT, "live")',
    'response.string(PB_TAG_ENVIRONMENT, "GOLRETAIL")'
)

# Update entitlements to all 1s
code = code.replace(
    'response.bytes(PB_TAG_ENTITLEMENTS, b"\\x01" * 8)',
    'response.bytes(PB_TAG_ENTITLEMENTS, b"\\xFF" * 16)'
)

# Add dump for SignOn in do_POST
old_post_handler = '''        status, payload = self.server_instance.handle_signon_request(body)'''
new_post_handler = '''        if "SignOn" in self.path:
            ts = int(time.time())
            dump_fn = f"signon_req_{ts}_{client_port}.bin"
            try:
                with open(dump_fn, "wb") as f_dump:
                    f_dump.write(body)
                server_log(f"[SignOn] Dumped {len(body)} bytes request body to {dump_fn}")
            except Exception as e:
                server_log(f"[-] SignOn dump error: {e}")

        status, payload = self.server_instance.handle_signon_request(body)'''

code = code.replace(old_post_handler, new_post_handler)

with open(server_path, 'w', encoding='utf-8') as f:
    f.write(code)

print('[+] Successfully patched scripts/marathon_server.py!')
