# Let's search for where config_blob is processed in the client
# In protobuf: Field 4 (CommonInfo) has subfield 3 (PB_COMMON_CONFIG_BLOB)
# Field 4 tag: (4 << 3) | 2 = 0x22
# Field 3 tag inside Field 4: (3 << 3) | 2 = 0x1A

import glob

print("Scanning for tag 0x1A or config_blob handlers in dumps...")
for fn in glob.glob("D:/Marathon-live/mem_*.bin"):
    data = open(fn, 'rb').read()
    # Check if this dump has references to 0x1D (29)
    if b'\x1d' in data:
        # count occurrences of 0x1D
        pass
