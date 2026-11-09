import re

path = r'D:\vault-breaker-preservation\scripts\marathon_server.py'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

new_handle_signon = '''    def handle_signon_request(self, steam_ticket: bytes, platform: str = "pc_x64",
                              build: str = "248199.26.10.21.2300.gol_retail.rc") -> Tuple[int, bytes]:
        """Handles POST /SignOn?platform=%s&build=%s.
        Returns (HTTP status code, Protobuf binary payload).
        """
        # Allocate deterministic session for player
        player_id = 76561198000001001  # Steam ID
        membership_id = 1             # Bungie membership ID matching Project Dawn
        
        session_token = os.urandom(32)   # 32 bytes (Tiger Engine cs_signon_token)
        encryption_key = os.urandom(32)  # 32 bytes AES session key
        auth_key = os.urandom(32)        # 32 bytes HMAC auth key
        display_name = "Runner#0001"
        
        player = PlayerSession(
            membership_id=membership_id,
            bungie_name=display_name,
            session_token=session_token,
            encryption_key=encryption_key,
            auth_key=auth_key,
            relay_port=self.bap_port
        )
        self.players[membership_id] = player
        self.players[player_id] = player
        self.sessions_by_token[session_token] = player
        
        # Resolve host IP in native host byte order uint32 (0x0100007F for 127.0.0.1)
        relay_host = "127.0.0.1" if self.host in ("0.0.0.0", "") else self.host
        relay_ip_uint32 = struct.unpack("=I", socket.inet_aton(relay_host))[0]
        
        # Build Protobuf response matching Project Dawn's Writer
        success_sub = ProtobufWriter()
        success_sub.bytes(PB_SUB_RESERVED, bytes(16))  # 16 zero reserved bytes
        success_sub.bytes(PB_SUB_ENCRYPTION_KEY, encryption_key)
        success_sub.bytes(PB_SUB_AUTH_KEY, auth_key)
        success_sub.bytes(PB_SUB_SESSION_TOKEN, session_token)
        success_sub.varint(PB_SUB_EXPIRY, 86400)
        success_sub.varint(PB_SUB_RELAY_ADDR, relay_ip_uint32)  # 127.0.0.1 (0x0100007F)
        success_sub.varint(PB_SUB_RELAY_PORT, self.bap_port)
        
        common_info_sub = ProtobufWriter()
        common_info_sub.varint(PB_COMMON_ID, membership_id)
        common_info_sub.varint(PB_COMMON_SILO, 1)
        
        # Entitlements submessage (eliminates invalid wire type 7 corruption!)
        entitlements_sub = ProtobufWriter()
        entitlements_sub.varint(1, 3065800)  # Marathon AppID
        
        build_str = build or BUILD_VERSION_STRING
        
        response = ProtobufWriter()
        response.varint(PB_TAG_ERROR, 0)
        response.message(PB_TAG_SUCCESS, success_sub)
        response.message(PB_TAG_COMMON_INFO, common_info_sub)
        response.varint(PB_TAG_SILO_ID, 1)
        response.string(PB_TAG_BUILD_VERSION, build_str)
        response.varint(PB_TAG_CAPABILITY_FLAGS, 0)
        response.message(PB_TAG_ENTITLEMENTS, entitlements_sub)
        response.varint(PB_TAG_SERVER_TIME, int(time.time()))
        response.string(PB_TAG_ENVIRONMENT, "GOLRETAIL")
        response.varint(PB_TAG_EXTERNAL_ADDR, relay_ip_uint32)
        
        return 200, response.build()

'''

# Replace handle_signon_request
pattern = re.compile(r'    def handle_signon_request\(.*?\n    def determine_vault_route', re.DOTALL)
replacement = new_handle_signon + '    def determine_vault_route'
assert pattern.search(text) is not None, "Pattern for handle_signon_request not matched!"
text = pattern.sub(replacement, text)

# Replace do_POST handling of status, payload = self.server_instance.handle_signon_request(body)
old_post_call = 'status, payload = self.server_instance.handle_signon_request(body)'
new_post_call = '''from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        platform = qs.get("platform", ["pc_x64"])[0]
        build = qs.get("build", [BUILD_VERSION_STRING])[0]
        status, payload = self.server_instance.handle_signon_request(body, platform=platform, build=build)'''

assert old_post_call in text, "old_post_call not found in text!"
text = text.replace(old_post_call, new_post_call)

with open(path, 'w', encoding='utf-8') as f:
    f.write(text)

print("Successfully updated marathon_server.py!")
