with open(r'D:\vault-breaker-preservation\scripts\dawn_signon_asm.txt', 'r') as f:
    lines = f.readlines()

for i, l in enumerate(lines):
    l_str = l.strip()
    if "; ->" in l_str or "TAG" in l_str or "mov      r9d," in l_str or "mov      ebx," in l_str or "mov      eax," in l_str:
        print(f"{i:4d}: {l_str}")
