path = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(path, 'r', encoding='utf-8') as f:
    text = f.read()

# Replace any double newlines caused by \r\r\n
text = text.replace('\r\n', '\n').replace('\r', '\n')
while '\n\n\n' in text:
    text = text.replace('\n\n\n', '\n\n')

# Replace broken STUB_ROW_8 definition
old_stub_block = """#define STUB_ROW_8(base) \\

    (void*)UserStub<base+0>, (void*)UserStub<base+1>, (void*)UserStub<base+2>, (void*)UserStub<base+3>, \\

    (void*)UserStub<base+4>, (void*)UserStub<base+5>, (void*)UserStub<base+6>, (void*)UserStub<base+7>

static void* g_user_default_stubs[64] = {
    STUB_ROW_8(0),
    STUB_ROW_8(8),
    STUB_ROW_8(16),
    STUB_ROW_8(24),
    STUB_ROW_8(32),
    STUB_ROW_8(40),
    STUB_ROW_8(48),
    STUB_ROW_8(56)
};"""

new_stub_block = """#define S8(b) (void*)UserStub<b+0>, (void*)UserStub<b+1>, (void*)UserStub<b+2>, (void*)UserStub<b+3>, (void*)UserStub<b+4>, (void*)UserStub<b+5>, (void*)UserStub<b+6>, (void*)UserStub<b+7>

static void* g_user_default_stubs[64] = {
    S8(0), S8(8), S8(16), S8(24), S8(32), S8(40), S8(48), S8(56)
};"""

if old_stub_block in text:
    text = text.replace(old_stub_block, new_stub_block)
else:
    # Try with single newlines
    old_stub_block2 = """#define STUB_ROW_8(base) \\
    (void*)UserStub<base+0>, (void*)UserStub<base+1>, (void*)UserStub<base+2>, (void*)UserStub<base+3>, \\
    (void*)UserStub<base+4>, (void*)UserStub<base+5>, (void*)UserStub<base+6>, (void*)UserStub<base+7>

static void* g_user_default_stubs[64] = {
    STUB_ROW_8(0),
    STUB_ROW_8(8),
    STUB_ROW_8(16),
    STUB_ROW_8(24),
    STUB_ROW_8(32),
    STUB_ROW_8(40),
    STUB_ROW_8(48),
    STUB_ROW_8(56)
};"""
    text = text.replace(old_stub_block2, new_stub_block)

with open(path, 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(text.replace('\n', '\r\n'))

print("[+] Cleaned up stub definitions!")
