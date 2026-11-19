import struct

base = 0x00007FF70F850000
table2_rva = 0x32DA1E70
table2_va = base + table2_rva

print(f"Searching for references to Table 2 (RVA 0x{table2_rva:08X}, VA 0x{table2_va:016X})...")

import glob
for fn in glob.glob("D:/Marathon-live/code_bootflow_ref_*.bin"):
    data = open(fn, 'rb').read()
    # Check if target in proxy log was Table 2
    pass

# Check marathon_proxy.log for 0x32DA1E70 or nearby
log_path = "D:/Marathon-live/marathon_proxy.log"
with open(log_path, 'r', encoding='latin1', errors='replace') as f:
    for line in f:
        if "32DA1E" in line or "32da1e" in line or "bootflow table" in line:
            print(line.strip())
