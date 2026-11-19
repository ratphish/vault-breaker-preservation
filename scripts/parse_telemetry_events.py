import json

fn = 'D:/Marathon-live/telemetry_1794286403_49964.bin'
with open(fn, 'r', encoding='utf-8') as f:
    d = json.load(f)
    for ev in d.get('events', []):
        seq = ev.get('seq_num')
        name = ev.get('name')
        payload = ev.get('payload')
        print(f"=== Event {seq}: {name} ===")
        print(json.dumps(payload, indent=2))
