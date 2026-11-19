import json

with open('D:/Marathon-live/telemetry_1794286403_49964.bin', 'r') as f:
    d = json.load(f)

print(f"Total events: {len(d.get('events', []))}")
for ev in d.get('events', []):
    seq = ev.get('seq_num')
    name = ev.get('name')
    t = ev.get('created_time')
    payload = ev.get('payload')
    print(f"[{seq}] t={t} {name}: {payload}")
