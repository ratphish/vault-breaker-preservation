from pathlib import Path
import re

dir_path = Path(r"D:\Marathon-live")
for p in dir_path.rglob("*"):
    if p.is_file() and p.suffix.lower() in [".exe", ".dll", ".bin", ".dat", ".txt"]:
        try:
            data = p.read_bytes()
            if b"steam_api" in data.lower() or b"s\x00t\x00e\x00a\x00m\x00_\x00a\x00p\x00i" in data.lower():
                print(f"Match in {p.relative_to(dir_path)} (size {len(data)})")
        except Exception as e:
            pass
