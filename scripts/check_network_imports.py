import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
import pefile

pe = pefile.PE(r"D:\Marathon-live\Marathon.exe", fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    if any(k in dll.lower() for k in ["ws2", "dns", "winhttp", "wininet", "iphlpapi", "curl"]):
        print(f"DLL: {dll}")
        for imp in entry.imports:
            if imp.name:
                print(f"  {imp.name.decode()}")
