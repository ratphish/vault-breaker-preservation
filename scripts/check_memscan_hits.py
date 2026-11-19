import glob
import re

base = 0x00007FF70F850000

# Let's inspect marathon_proxy.log for "[MemScan] Found ref to"
log_path = "D:/Marathon-live/marathon_proxy.log"
refs = []
if os.path.exists(log_path):
    with open(log_path, 'r', encoding='latin1', errors='replace') as f:
        for line in f:
            if "[MemScan] Found ref to" in line:
                refs.append(line.strip())

print(f"Total MemScan hits in proxy log: {len(refs)}")
for r in refs[:30]:
    print(r)
if len(refs) > 30:
    print(f"... and {len(refs)-30} more")
