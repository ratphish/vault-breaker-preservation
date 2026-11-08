# Handle-map layout probe, build 26136895

The preserved build's `handle_map_win64.bin` is 1,058,778 bytes, SHA-256 `424d0f0c0c2873f103c27c67c40a2d16626550d12ee286c00d35ccd49cadf310`. A read-only candidate parser (`scripts/inspect_handle_map.py`) reads a little-endian 32-bit count of 105,877 and a second unclassified 32-bit header value. The exact file length equals `8 + 10 * count`. Interpreting the next `7 * count` bytes as sorted little-endian 32-bit IDs with 24-bit values, followed by `3 * count` bytes of 24-bit values, yields these whole-file invariants: all 105,877 IDs are nondecreasing; the first value array has 35,162 non-`FFFFFF` values; the second has 70,715; their non-sentinel values are unique, disjoint, and partition `0..count-1`. These numerical facts support the candidate layout but do not establish how the runtime uses it or whether the two values at a given row are related.

The first array contains ID `80B37FED` at row 70,954, offset `0x7942e`, followed by `FFFFFF`; ID `80B38567` appears at row 71,417, offset `0x7a0d7`, followed by `FFFFFF`. The separately indexed 24-bit array happens to have `007069` and `0070E2` at those same numerical indices, respectively; a relationship to those IDs has not been established. IDs `80B3808C` and `80B37C7E` are absent from the sorted first array. Results are in `handle-map-results.jsonl`. PowerShell independently read `ED 7F B3 80 FF FF FF` at `0x7942e`, corroborating one record's raw bytes. The parser rejects nonmatching size, sorting, and permutation invariants; `tests/test_handle_map.py` verifies one synthetic valid input and rejects a truncated one. This is a static layout observation, not a resolved handle, runtime lookup, server boundary, or recovered code. Only the first-array binary search establishes the stated bounded absences.

Reproduce:

```powershell
python scripts\inspect_handle_map.py 'D:\Marathon-preservation\build-26136895-20261031\handle_map_win64.bin' 80B3808C 80B37FED 80B38567 80B37C7E
python tests\test_handle_map.py
```

Next investigate how this table relates to the executable's lookup logic or independently documented format, and distinguish the two 24-bit arrays before assigning semantics. Other builds may differ.
All 105,877 candidate IDs are also distinct in this file. The parser reports the distinct count rather than assuming it for other builds.

## Comparison with package metadata

The separate `cryo_probe handle-types` pass treated each candidate first-array ID as a `FileHash` and asked MIDA for the corresponding snapshot package entry's metadata. Of 105,877 IDs, 96,105 resolved and 9,772 returned `ArgumentException`; the first three error messages identify package ID `0104` as absent from MIDA's path cache, but the other errors have not been individually classified. All resolved entries were type 8 or type 16, subtype 0: 93,756 type 8 and 2,349 type 16. These counts support the tag-ID interpretation for the resolved subset; they do not establish the meaning of either 24-bit value or prove missing files. Results and error samples are in `handle-map-entry-types.txt` and `handle-map-entry-types-summary.txt`.

Use the `MIDA_DIR` and `MARATHON_PACKAGES` environment from `2026-10-31-cryo-chain.md`, then run `dotnet run --project scripts\cryo_probe -p:MidaDir=$env:MIDA_DIR -- handle-types` with the listed SDK. This pass reads package metadata rather than executing the game.
A follow-up grouped the 9,772 failed rows by the candidate package IDs absent from MIDA's cache: all 9,772 fall across 17 IDs, listed in `handle-map-entry-types-summary.txt`. This identifies a concrete mismatch between the map's candidate IDs and the reader's active package map. It does not establish whether the IDs refer to missing depot files, intentionally unavailable content, stale entries, or a different interpretation of these values.
An independent two-byte header scan at offset `0x10` across all 627 snapshot `.pkg` files found none with any of those 17 candidate package IDs (`handle-map-header-check.txt`; reproduce with `scripts/find_package_headers.py`). This corroborates their absence from these local package headers, but does not prove the build is incomplete: stale map entries, unavailable content, or an incorrect interpretation remain possible.

## Comparative file

The same parser accepted the separate local Destiny 2 `handle_map_win64.bin` at `D:\SteamLibrary\steamapps\common\Destiny 2\handle_map_win64.bin` (SHA-256 `3bacc98c6fe898ab531dfa476d1860d4a60270edb11e82c3d506a62d6939df5a`). It reported 1,180,935 distinct sorted candidate IDs and the same whole-file length and permutation invariants (`destiny-handle-layout-comparison.jsonl`). This independently observed second file strengthens the candidate binary-layout hypothesis across two files. It does not identify the table's semantics, prove content or runtime compatibility, or validate any Marathon behavior. The Destiny file was read only.
