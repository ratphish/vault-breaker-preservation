import re

with open(r"D:\Marathon-live\Marathon.exe", "rb") as f:
    data = f.read()

pattern = re.compile(b"(?:SteamAPI_|SteamInternal_|SteamClient|GetHSteam)[A-Za-z0-9_]+")
matches = set(m.group(0).decode() for m in pattern.finditer(data))

print(f"Found {len(matches)} unique Steam API symbols referenced in Marathon.exe:")
for sym in sorted(matches):
    print("  *", sym)
