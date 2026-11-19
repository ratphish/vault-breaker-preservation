import glob
import os

target_rva = 0x32DA2A80
base = 0x00007FF70F850000

log_path = "D:/Marathon-live/marathon_proxy.log"
with open(log_path, 'r', encoding='latin1', errors='replace') as f:
    for line in f:
        if "32DA2A80" in line or "32da2a80" in line:
            print("Found in proxy log:", line.strip())
