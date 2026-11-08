import sys,struct
sys.path.insert(0,r'D:\Marathon-preservation\tools\python')
import pefile
p=pefile.PE(r'D:\Marathon-preservation\build-26136895-20261031\Marathon.exe',fast_load=True)
e=p.OPTIONAL_HEADER.DATA_DIRECTORY[3];off=p.get_offset_from_rva(e.VirtualAddress); triple=struct.unpack('<III',p.get_data(e.VirtualAddress+0xa1004,12))
assert (e.VirtualAddress,e.Size,off,triple)==(0x392a7000,3509556,0x35309200,(0x2f7a2690,0x2f7a2701,0x33345c7c))
print('PASS: pefile confirms exception-directory mapping and selected 12-byte entry')
