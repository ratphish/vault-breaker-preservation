# Cryo activity to Vault Breaker key pedestal, 2026-10-31

## Result and limits

In Steam build 26136895, MIDA's Marathon schema resolves the following chain from activity tag `80B3808C`:

`80B3808C` -> resource `80B38C23` -> group `80B38BEC` -> parent `80B38569` -> component `80B38567`.

The component's decoded 1,028 bytes contain `content\prefabs\activities\objects\pf_vault_breaker_key_pedestal.es` at byte offset `0x3c0`. The group contains 12 components using instance class `80B38561` and definition class `80B38555`; one is the component above. The activity has 74 listed resource references and the selected group has 61 component parents. These are observed links under MIDA's schema and a literal path, not a demonstration that the script is present, executable, or that a pedestal works. Cryo association comes from the local Cryo export and prior research; the chain alone does not establish mode exclusivity or server authority. Do not treat an `.es` path as recovered script code. MIDA itself warns some schema is inherited and obsolete.

## Provenance

Steam manifest `D:\SteamLibrary\steamapps\appmanifest_3065800.acf` reported app 3065800, build 26136895, depot 3065801 manifest 7988549751777473008 and depot 3065802 manifest 6568534677775178168. These are Steam-reported identifiers, not independent verification of every file. On October 31 a separate copy was made at `D:\Marathon-preservation\build-26136895-20261031`. Robocopy log `D:\Marathon-preservation\build-26136895-copy.log` reports 725 files copied, zero failures. This does not prove an atomic or complete Steam depot snapshot. The four `019c` package copies match the live installation's SHA-256 at verification time; see `package-019c-hashes.json`. The executable hash is recorded separately. The export `D:\MIDAExports\Maps\Cryo Archive\80B37729_Entities_info.cfg` has SHA-256 `203fbb6aa7caab8a936dcd42c6787b28867992bdcd70e0c1290d5fb4855705d9`; its original source build is unverified.

The prior Codex research at `C:\Users\marra\Documents\Codex\2026-10-27\hel\work\stringprobe` supplied candidate hashes and the initial probe. The local MIDA source checkout is commit `0a5adc9a31951bd1b244ab9792e20e496f598a7b`; the installed distribution DLLs were used, and their exact correspondence to that source commit has not been established. Schema traversal was rerun against the snapshot, with output in `probe-typed.txt`, `probe-keygroup.txt`, and `probe-evidence.txt`. The component SHA-256 is `61627badcce9b834fa028c267a5981a9321b855b0ecc48188281da2cb9dd16ba`. The prior extracted component has the same digest. Independently, REA `inspect_byte_entropy` evidence `ev_f06c4b2a4d8d00d702896f6f0a0a90e024b8449690f17dd9bde8f596526d0f47` reported the same 1,028 bytes and digest; a Python byte search on that matching extracted file located the path at 0x3c0. REA's entropy analysis does not establish semantic relationships. MIDA provides decoding and links, so an independent second package decoder would strengthen the result.

## Reproduction

With the existing local MIDA distribution and .NET 10 SDK:

```powershell
$env:MIDA_DIR='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\MIDA'
$env:MARATHON_PACKAGES='D:\Marathon-preservation\build-26136895-20261031\packages'
$dotnet='C:\Users\marra\Documents\Codex\2026-10-27\hel\work\tools\dotnet10\dotnet.exe'
foreach ($mode in @('typed','keygroup','evidence')) {
  & $dotnet run --project scripts\cryo_probe -p:MidaDir=$env:MIDA_DIR -- $mode
}
```

The probe is adapted from the earlier local research and uses the local MIDA assemblies. It reads package data; MIDA may maintain its own caches in its distribution directory. It does not launch the game or interact with services. Package tags, schemas, and addresses are build-specific. Output includes matching names rather than recovered executable logic.

## Sources and next steps

Bungie's [1.1.9.5 notes](https://www.bungie.net/7/en/News/Article/marathon_update_1_1_9_5) state Vault Breaker is available October 20–November 10, 2026. The initial mode was introduced in [1.1.5](https://www.bungie.net/7/en/News/Article/mid_season_2_preview); this build must not be assumed identical to that release. While available, record ordinary gameplay of entry, key pedestal, vault interactions, failure, extraction, and progression; user access and normal gameplay are required. Preserve recordings privately and do not modify the live client. Consider full snapshot hashing and Steam-depot verification before calling the copy a complete archive.

[MIDA](https://github.com/DeltaDesigns/MIDA) documents its Marathon focus and schema caveats; [tiger-pkg](https://github.com/v4nguard/tiger-pkg) documents Marathon package support and Oodle dependencies. Next investigate whether the referenced prefab script or compiled equivalents can be located, then map its links to client/service ownership. Corroborate the chain with another decoder and identify how this build differs from the July release. Sunrise is a Destiny research lead, not demonstrated Marathon compatibility.

## Full file comparison

After the original copy, `scripts/verify_snapshot.py` hashed every regular, non-symlink snapshot file and the corresponding live path. On 2026-10-31 it reported 725 files, zero unequal or unverified, with each source file's size and modification time stable across its read. A separate set comparison reported 725 paths on each side, zero unique paths; see `snapshot-file-set.txt`. The complete per-file manifest remains outside the repository at `D:\Marathon-preservation\build-26136895-hashes.jsonl`; its SHA-256 is `05f1b5c716f31a5e7c6e2fe0cee0bb7eaf289396aad876b953c9dc037caf5183`. The verification is not atomic across the tree and is not a Steam manifest or depot integrity audit. It establishes equality of the checked paths and bytes to the corresponding live files at their respective read times, not historical or depot completeness.

## Attribution correction

The chain described here was discovered in the earlier Codex research, not newly discovered in this workspace. This investigation reproduced it on the separate snapshot and checked the component digest against the previous extraction. The separate research had also traced the activity script and handler metadata. Completion of the first-breakthrough goal did not mean the user's broader preservation or decompilation objective was complete.

## Second decoder cross-check

A separately implemented Marathon package reader from [Audio Codex](https://github.com/Battleroid/audio-codex), checkout commit `543bf6e286b815d4f62f055a8ad6339e88085e17`, was used directly against snapshot `w64_marathon_deck_001_019c_3.pkg`. The local harness links that checkout's `TigerPackage.cs` and `Oodle.cs`; it does not copy them into this repository. Its README credits MIDA and other projects, so the implementations are distinct but their format knowledge is not fully independent. The checkout has no identified license file; do not redistribute its source or infer permission beyond local inspection.

For the six selected tags in `audio-codex-validation.jsonl`, the reader's lengths, reference identifiers and SHA-256 digests agree with MIDA's `probe-evidence.txt`. Run `python tests\compare_readers.py` to repeat that comparison. The pedestal component again contains the exact path at `0x3c0`. This validates decoded bytes and entry metadata for those selected records, not the typed activity traversal or runtime behavior. Audio Codex's decoder may fall back to CTR without GCM tag verification; digest agreement is not proof of package authenticity.

Reproduce with `dotnet run --project scripts\independent_reader -p:AudioCodexDir=D:\Marathon-preservation\tools\audio-codex -- D:\Marathon-preservation\build-26136895-20261031\packages\w64_marathon_deck_001_019c_3.pkg 140,3107,3052,1385,1383,1329 D:\Marathon-preservation\build-26136895-20261031\bin\x64\oo2core_9_win64.dll` using the local .NET 10 SDK. The exact target package/patch is explicitly selected; this does not independently verify MIDA's patch selection across all packages.

The second reader also found the next tag's raw little-endian ID in each decoded record: activity `80B3808C` at `0x89c` -> `80B38C23`; `80B38C23` at `0x18` -> `80B38BEC`; `80B38BEC` at `0xbc` -> `80B38569`; `80B38569` at `0x20` -> `80B38567`. These locations agree with the MIDA-interpreted route, but raw values alone do not prove field types. `tests/compare_readers.py` checks these offsets and the pedestal path as well as the six digests.

The same second decoder was applied to activity-script records in package `019b` as well. Its bytes for `80B37C7E`, `80B37FE9`, and `80B37FED` match the earlier MIDA extractions by SHA-256 (see `activity-decoder-comparison.txt`). Independent raw search finds group `80B38BEC` contains `80B37FEE` at `0x40`, and parent `80B37FEE` contains `80B37FED` at `0x20`. Component `80B37FED` contains `activity_vault_breaker.es` at offset 9377. These observations corroborate the previously researched activity -> resource -> group -> activity component route at the byte level; the route's field semantics still come from MIDA schema and the script body remains unknown. `tests/compare_readers.py` checks the selected byte values and filename offset.

The preserved `Marathon.exe` Windows version resource reports `248199.26.10.21.2300.gol_retail.rc` for both FileVersion and ProductVersion. This is embedded version metadata, distinct from Steam build ID 26136895. Bungie's [1.1.9.6 notes](https://www.bungie.net/7/en/news/article/marathon_update_1_1_9_6) are dated October 27, 2026, but date proximity alone does not independently map the embedded version or Steam ID to a specific release label.
