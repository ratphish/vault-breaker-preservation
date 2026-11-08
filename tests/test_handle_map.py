import subprocess,sys,tempfile,struct
from pathlib import Path
exe=Path('scripts/inspect_handle_map.py').resolve()
def u24(n):return n.to_bytes(3,'little')
rows=[(0x80800001,2),(0x80B37FED,0xffffff),(0x80B38567,0xffffff)]
data=struct.pack('<II',3,0x12345678)+b''.join(struct.pack('<I',x)+u24(v) for x,v in rows)+b''.join(u24(x) for x in [0xffffff,0,1])
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/'map.bin';p.write_bytes(data)
 good=subprocess.run([sys.executable,str(exe),str(p),'80B37FED'],capture_output=True,text=True);assert good.returncode==0 and '"row_index": 1' in good.stdout,good.stderr
 p.write_bytes(data[:-1]);bad=subprocess.run([sys.executable,str(exe),str(p)],capture_output=True,text=True);assert bad.returncode!=0
print('PASS: synthetic valid map resolves row; truncated map is rejected')
