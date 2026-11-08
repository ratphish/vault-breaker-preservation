"""Compute candidate FNV-1 hashes; use as search leads only."""
import argparse
p=argparse.ArgumentParser();p.add_argument('names',nargs='+');a=p.parse_args()
for name in a.names:
 value=0x811c9dc5
 for byte in name.encode('utf-8'):value=((value*0x01000193)&0xffffffff)^byte
 print(name,f'{value:08X}')
