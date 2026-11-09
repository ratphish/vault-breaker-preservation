import sys
sys.path.append(r'D:\vault-breaker-preservation\scripts')
from marathon_protobuf import ProtobufReader

# In Dawn:
# Top-level message has:
# Field 1 (varint): 0 (Error code)
# Field 2 (message): success_sub
#   Field 1 (bytes): 16 bytes
#   Field 2 (bytes): 32 bytes (encryption_key)
#   Field 3 (bytes): 32 bytes (auth_key)
#   Field 4 (bytes): 16 bytes / 32 bytes (session_token)
#   Field 5 (varint): expiry
#   Field 6 (varint): relay_addr
#   Field 7 (varint): relay_port
# Field 4 (message): common_info
#   Field 1 (varint): membership_id (1)
#   Field 2 (varint): silo (1)
#   Field 3 (bytes): 29 bytes config blob
# Field 5 (varint): 1 (silo)
# Field 6 (string): build version
# Field 8 (varint): 0 (capabilities)
# Field 10 (bytes): entitlements
# Field 12 (varint): server time
# Field 13 (string): environment ("live" or "GOLRETAIL")
# Field 14 (varint): external addr (127.0.0.1)

print("Checking Dawn fields...")
