import zipfile

with zipfile.ZipFile(r'C:\Users\marra\Downloads\MARATHON_TO_DAWN_HANDOFF.zip') as z:
    with open(r'D:\vault-breaker-preservation\scratch\handoff.txt', 'w', encoding='utf-8') as out:
        for name in z.namelist():
            out.write(f"=== {name} ===\n")
            if not name.endswith('/'):
                content = z.read(name).decode('utf-8', errors='ignore')
                out.write(content + "\n\n")
print("Done writing handoff.txt")
