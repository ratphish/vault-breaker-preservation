p = r'D:\vault-breaker-preservation\client_proxy\steam_api64_diag.cpp'
with open(p, 'r', encoding='utf-8') as f:
    t = f.read()
t = t.replace(r'D:\Marathon-live\mem_hash', 'D:/Marathon-live/mem_hash')
with open(p, 'w', encoding='utf-8') as f:
    f.write(t)
print("Fixed path strings!")
