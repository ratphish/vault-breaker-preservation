# Managed helper decompilation

The snapshot's `miniTicketDbg.exe` is a 224,336-byte x86-64 PE containing managed CIL. REA `inspect_managed_artifact` parent evidence `ev_58a5785661f2ee26d64d763dc800435f24a7096e8ac5878c1f970c32816f74d7` identifies .NET Framework 4.8, MVID `7a2cfb34-95d9-48dc-a71f-4746c6af87ed`, entry-point token `0x0600022e`, and SHA-256 `ff0ebb8b6e2cf30ec47c6a6ef62425d7cff9333371c7bbe5f89fa2ea3ef77cbf`. REA `inspect_managed_members` parent evidence `ev_1454050fc08b5c5cf402ee215ee4dba48e22411bf9054102ff194385c8930edd` reports 641 method rows and complete metadata coverage. These are static metadata facts and do not execute the helper.

ILSpy command-line decompiler 11.2.0.10050 generated a local project at `D:\Marathon-preservation\decompiled\build-26136895\miniTicketDbg`, including 66 `.cs` files and a project file. Targeting token `0x0600022e` separately decompiles a WPF application entry point; the generated `TicketDbg\App.cs` includes it. A search of generated C# found no standard decompilation-failure marker; that bounded check is not a proof of exact reconstruction. Generated C# is decompiler output, not recovered original source. It has not been built, executed, or checked for behavioral equivalence. Inspection indicates a debugger/ticket helper; this does not establish anything about Vault Breaker logic. Keep generated game-derived content private and outside this repository.

Reproduction (choose a new output directory):

```powershell
$env:DOTNET_ROOT='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\dotnet10'
& 'D:\Marathon-preservation\tools\ilspy\ilspycmd.cmd' -p -o 'D:\Marathon-preservation\decompiled\NEW-OUTPUT' 'D:\Marathon-preservation\build-26136895-20261031\miniTicketDbg.exe'
```

## Build validation

The initial project build failed on resource-generation settings and a missing `System.Resources.Extensions` reference. A separate sibling copy, `D:\Marathon-preservation\decompiled\build-26136895\miniTicketDbg-rebuild`, was created so the direct ILSpy output remains intact. In that copy, `System.Resources.Extensions` 8.0.0 was added; a conflicting LINQ range variable was renamed without changing the expression; the build was given `GenerateResourceUsePreserializedResources=true` and `StartupObject=TicketDbg.Entry` (the entry point decompiled from the original token). That build exited 0 with 134 warnings and produced `D:\Marathon-preservation\build-validation\miniTicketDbg\miniTicketDbg.exe`, SHA-256 `896846cccf4f566141533faa864f122ee066f93ed318f85471fbafc0cb26b6ba`. Build logs are under `D:\Marathon-preservation\build-validation-*.txt`.

The rebuilt output differs from the original and was not executed. Compilation and static PE identification do not establish functional, runtime, resource, or security equivalence; the warnings and added dependency matter. This helper is not the game or Vault Breaker implementation.

## Managed PE inventory and additional projects

`scripts/inventory_pe_cli.py` inspected the PE headers of the snapshot's `.exe` and `.dll` files: 33 files, no parser errors, three declared CLI directories. See `pe-inventory.jsonl` and `pe-inventory-summary.txt`. This is a header-based inventory, not a search inside packages or arbitrary file extensions. REA independently identified `SharpDX.dll` and `SharpDX.DXGI.dll` as managed assemblies named SharpDX and SharpDX.DXGI, version 3.0.2.0 (view Evidence `ev_0fe02c20e14e9b422fd6befb725149b4fcfd0ddfe4ef755a206805b8882d0569` and `ev_c906f87f2dfe4f162ae51f7127b6dc98de692efd3c1eb9f2e6e81a26335d42e1`). Original SHA-256 values are `87f7ba5d91fd967d7aeadf34f6e6b465a1689de099861614d55aaadb7ef694fd` and `66e2a98f53d74a49fa76fafe30eebcf02154d30ad09b535cdd5c3158fbea81e` respectively.

ILSpy 11.2.0.10050 generated projects locally in `D:\Marathon-preservation\decompiled\build-26136895\SharpDX` (130 C# files) and `D:\Marathon-preservation\decompiled\build-26136895\SharpDX.DXGI` (110 C# files), using the same command pattern above. A search for standard decompilation-failure messages found none in those `.cs` files; the projects have not been compiled or behaviorally verified. This covers generated decompilation projects for the three CLI-declared files found in this bounded inventory, not the 30 other PEs, files in packages, or the game as a whole.
