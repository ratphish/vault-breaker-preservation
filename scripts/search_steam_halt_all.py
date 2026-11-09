from pathlib import Path
import re

p = Path(r"D:\Marathon-live")
for f in p.rglob("*"):
    if f.is_file() and f.suffix in [".dll", ".exe"]:
        try:
            b = f.read_bytes()
            if b"Steam API failed to initialize" in b or b"S\x00t\x00e\x00a\x00m\x00 \x00A\x00P\x00I" in b:
                print(f"MATCH in {f}: size {len(b)}")
        except Exception:
            pass
