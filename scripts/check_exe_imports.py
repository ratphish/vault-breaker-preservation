import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
import pefile

pe = pefile.PE(r"D:\Marathon-live\Marathon.exe", fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])

imported_dlls = [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
print("Total imported DLLs:", len(imported_dlls))
for dll in imported_dlls:
    if any(k in dll.lower() for k in ["steam", "curl", "oo2", "ws2", "d3d"]):
        print(" -", dll)

launcher_path = r"D:\Marathon-live\MarathonLauncher.exe"
pe_launcher = pefile.PE(launcher_path, fast_load=True)
pe_launcher.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
print("\nLauncher imported DLLs:")
for entry in pe_launcher.DIRECTORY_ENTRY_IMPORT:
    print(" -", entry.dll.decode())
