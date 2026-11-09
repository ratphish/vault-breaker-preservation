# Let's inspect the entire sequence of tags and writes in 0x1804BDD70
# from dawn_signon_asm.txt

with open(r'D:\vault-breaker-preservation\scripts\dawn_signon_asm.txt', 'r') as f:
    lines = f.readlines()

# Let's find every instruction that moves a constant or reference
for i, line in enumerate(lines[:1040]):
    # When is a tag written?
    # Tag encoding loop:
    #   and al, 0x7f
    #   shr rX, 7
    #   ...
    #   mov byte ptr [...], cl
    #   jne ...
    if 'cmove' in line:
        # The tag or value was loaded just prior
        # look backwards 10 lines
        prev = [lines[j].strip() for j in range(max(0, i-10), i)]
        print(f"Write at line {i}:")
        for p in prev:
            if any(k in p for k in ['mov', 'lea', 'xor', 'call', 'TAG', '; ->']):
                print(f"   {p}")
