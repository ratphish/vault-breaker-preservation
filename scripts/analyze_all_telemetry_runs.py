import glob
import json
import os

all_events = []
for p in ["D:/Marathon-live", "d:/vault-breaker-preservation"]:
    for f in glob.glob(f"{p}/telemetry_*.bin"):
        try:
            d = json.loads(open(f, 'rb').read())
            events = d.get('events', [])
            for e in events:
                name = e.get('name')
                payload = e.get('payload', {})
                all_events.append((os.path.basename(f), name, payload))
        except Exception:
            pass

print(f"Total telemetry events parsed: {len(all_events)}")
# Group by event name
from collections import Counter
c = Counter([e[1] for e in all_events])
for k, v in c.most_common():
    print(f"  {k:<55}: {v}")

print("\n--- Detailed state_change and timed_operation events ---")
for fn, name, p in all_events:
    if "state_change" in name or "bootflow" in name or "timed_operation" in name:
        print(f"[{fn}] {name}: {p}")
