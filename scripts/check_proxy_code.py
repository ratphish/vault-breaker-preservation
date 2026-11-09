import sys

path = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(path, 'r', encoding='utf-8') as f:
    code = f.read()

# Let's inspect where InitInterfaceTables is
print(f'Total lines: {len(code.splitlines())}')
