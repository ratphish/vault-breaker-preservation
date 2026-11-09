path = r'D:\vault-breaker-preservation\scripts\marathon_server.py'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

target = 'membership_id = 1             # Bungie membership ID matching Project Dawn'
replacement = 'membership_id = 76561198000001001  # Match Steam ID for Goliath Retail client'

if target in text:
    text = text.replace(target, replacement, 1)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    print("SUCCESS: Updated membership_id to 76561198000001001!")
else:
    print("ERROR: Target not found!")
