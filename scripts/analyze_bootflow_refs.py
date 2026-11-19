import glob
import os
import struct

# Let's inspect marathon_proxy.log for all [MemScan] lines that dumped code
ref_log = {}
with open(r'D:\Marathon-live\marathon_proxy.log', 'r', encoding='latin1') as f:
    for line in f:
        if '[MemScan] Found ref' in line:
            # [MemScan] Found ref to <desc> <target> at Marathon.exe+<rva> ...
            parts = line.strip().split()
            # print first 20
            print(line.strip())
