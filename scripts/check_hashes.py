import hashlib
from pathlib import Path

orig = Path(r"D:\Marathon-preservation\build-26136895-20261031")
live = Path(r"D:\Marathon-live")

for name in ["cache_phr_0000ed4c.dat", "handle_map_win64.bin", "sku_config.txt", "d3dcompiler_47.dll"]:
    f1 = orig / name
    f2 = live / name
    if f1.exists() and f2.exists():
        h1 = hashlib.sha256(f1.read_bytes()).hexdigest()
        h2 = hashlib.sha256(f2.read_bytes()).hexdigest()
        print(f"{name}: {'MATCH' if h1 == h2 else 'MISMATCH'}")
