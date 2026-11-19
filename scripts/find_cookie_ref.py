import struct

base = 0x00007FF70F850000
target_rva = 0x32DA9DA0
target_va = base + target_rva

print(f"Target VA for 'client_config_cookie': 0x{target_va:016X} (RVA 0x{target_rva:08X})")

# Let's search across all code_bootflow_ref_*.bin
import glob
for fn in glob.glob("D:/Marathon-live/code_bootflow_ref_*.bin"):
    data = open(fn, 'rb').read()
    # Check if target is in the log or in the dump
    pass

log_path = "D:/Marathon-live/marathon_proxy.log"
with open(log_path, 'r', encoding='latin1', errors='replace') as f:
    for line in f:
        if "32DA9D" in line or "32da9d" in line:
            print(line.strip())
