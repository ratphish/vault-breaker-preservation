from pathlib import Path

orig_dir = Path(r"D:\Marathon-preservation\build-26136895-20261031")
live_dir = Path(r"D:\Marathon-live")

orig_files = {p.relative_to(orig_dir): p for p in orig_dir.glob("*") if p.is_file()}
live_files = {p.relative_to(live_dir): p for p in live_dir.glob("*") if p.is_file()}

missing_in_live = set(orig_files.keys()) - set(live_files.keys())
print("Missing in live root:", missing_in_live)

orig_bin = {p.relative_to(orig_dir): p for p in (orig_dir / "bin" / "x64").glob("*") if p.is_file()}
live_bin = {p.relative_to(live_dir): p for p in (live_dir / "bin" / "x64").glob("*") if p.is_file()}

missing_in_live_bin = set(orig_bin.keys()) - set(live_bin.keys())
print("Missing in live bin/x64:", missing_in_live_bin)

for rel, p in orig_files.items():
    if rel in live_files:
        s1 = p.stat().st_size
        s2 = live_files[rel].stat().st_size
        if s1 != s2 and rel.name != "steam_api64.dll":
            print(f"Size mismatch in root {rel}: orig {s1} vs live {s2}")
