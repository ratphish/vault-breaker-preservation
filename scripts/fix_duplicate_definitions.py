import os

filepath = r'D:\vault-breaker-preservation\client_proxy\steam_api64.cpp'
with open(filepath, 'r', encoding='utf-8') as f:
    code = f.read()

# Remove the second duplicate block of PEB definitions
duplicate_block = '''static HMODULE g_hooked_modules[256];
static int g_num_hooked_modules = 0;

static bool IsModuleHooked(HMODULE hMod) {
    for (int i = 0; i < g_num_hooked_modules; i++) {
        if (g_hooked_modules[i] == hMod) return true;
    }
    return false;
}

static void MarkModuleHooked(HMODULE hMod) {
    if (g_num_hooked_modules < 256 && !IsModuleHooked(hMod)) {
        g_hooked_modules[g_num_hooked_modules++] = hMod;
    }
}

typedef struct _UNICODE_STRING_PEB {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_PEB;

typedef struct _LDR_DATA_TABLE_ENTRY_PEB {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING_PEB FullDllName;
    UNICODE_STRING_PEB BaseDllName;
} LDR_DATA_TABLE_ENTRY_PEB;

typedef struct _PEB_LDR_DATA_PEB {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA_PEB;
'''

assert duplicate_block in code, "duplicate_block not found"
code = code.replace(duplicate_block, "")

# Remove the SIO_GET_EXTENSION_FUNCTION_POINTER macro warning:
code = code.replace(
    '#define SIO_GET_EXTENSION_FUNCTION_POINTER 0xC8000006',
    '#ifndef SIO_GET_EXTENSION_FUNCTION_POINTER\n#define SIO_GET_EXTENSION_FUNCTION_POINTER 0xC8000006\n#endif'
)

with open(filepath, 'w', encoding='utf-8') as f:
    f.write(code)
print('Removed duplicate definitions!')
