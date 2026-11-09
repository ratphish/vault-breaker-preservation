import os
import sys
from pathlib import Path

live_packages = Path(r"D:\Marathon-live\packages")
orig_packages = Path(r"D:\Marathon-preservation\build-26136895-20261031\packages")

# 1. Remove junction
if live_packages.is_symlink() or live_packages.is_dir():
    # If junction, os.rmdir removes the reparse point without deleting contents of target
    print("[*] Removing junction...")
    os.rmdir(live_packages)

# 2. Create real directory
print("[*] Creating real packages directory...")
live_packages.mkdir(exist_ok=True)

# 3. Create NTFS hard links for all 627 files
orig_files = list(orig_packages.glob("*.pkg"))
print(f"[*] Found {len(orig_files)} package files to link...")
linked = 0
for f in orig_files:
    dst = live_packages / f.name
    try:
        os.link(str(f), str(dst))
        linked += 1
    except Exception as e:
        print(f"[!] Error linking {f.name}: {e}")
        break

print(f"[+] Successfully created {linked} NTFS hard links!")
attrs = live_packages.stat()
print(f"[*] packages directory stat: {attrs}")
