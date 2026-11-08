"""Disassemble selected windows; addresses assume this build's .text mapping."""
import argparse
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
p=argparse.ArgumentParser();p.add_argument('pe',type=Path);p.add_argument('offset',nargs='+',type=lambda x:int(x,0));a=p.parse_args()
with a.pe.open('rb') as f:
 for off in a.offset:
  f.seek(off);data=f.read(128);va=0x140000000+off+0xa00
  print('OFFSET',hex(off),'VA',hex(va),'FIRST',data[:16].hex())
  for ins in list(Cs(CS_ARCH_X86,CS_MODE_64).disasm(data,va))[:25]:print(hex(ins.address),ins.mnemonic,ins.op_str)
