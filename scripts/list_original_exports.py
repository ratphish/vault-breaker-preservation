import sys
sys.path.insert(0, r"D:\Marathon-preservation\tools\python")
import pefile

pe = pefile.PE(r"D:\Marathon-preservation\build-26136895-20261031\bin\x64\steam_api64.dll")
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])

print(f"Total exports in original steam_api64.dll: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")
for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
    name = exp.name.decode() if exp.name else f"ord_{exp.ordinal}"
    print(f"  {exp.ordinal}: {name}")
