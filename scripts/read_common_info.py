with open(r'D:\vault-breaker-preservation\scripts\dawn_signon_asm.txt', 'r') as f:
    lines = f.readlines()

for idx in range(340, 660):
    l = lines[idx].rstrip()
    print(f"{idx:4d}: {l}")
