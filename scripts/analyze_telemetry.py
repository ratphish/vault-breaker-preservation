import json
import glob
import os

files = sorted(glob.glob('D:/Marathon-live/telemetry_*.bin'), key=os.path.getmtime)
if files:
    latest = files[-2:]
    for fn in latest:
        print(f"=== {fn} ===")
        with open(fn, 'r', encoding='utf-8', errors='ignore') as f:
            try:
                d = json.load(f)
                for ev in d.get('events', []):
                    print(f"  [{ev.get('seq_num')}] {ev.get('name')}: {ev.get('payload')}")
            except Exception as e:
                print(f"Error parsing JSON: {e}")
