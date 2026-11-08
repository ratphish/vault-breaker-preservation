# Vault Breaker script-path search

The local MIDA-based `script_path_probe find-script` searched decoded effective `marathon_deck_001` entries for two exact ASCII substrings, `activity_vault_breaker.es` and `pf_vault_breaker_key_pedestal.es`. It examined 151,076 entries from 19 effective package IDs; there were zero reported read errors or skipped entries above 64 MiB. Output is `cryo-script-paths.jsonl`, with 17 matching records. These include the previously identified activity metadata `80B37C7E`, `80B37FE9` and component `80B37FED`, pedestal metadata `80B38555` and `80B38561`, and the 12 previously identified pedestal components. See the earlier `Cryo Archive evidence.md` in the separate research chat workspace for previous analysis and limits.

The offsets in this search point to the beginning of the filename substring, not the beginning of the longer path. The matches provide an enumerated set of references under this narrow search, not recovered source code. Code or bytecode may lack the filename or reside in another package family or on a server. The scan uses MIDA to decode and choose patches; it is not an independent decoder.

Reproduction uses the environment in `2026-10-31-cryo-chain.md` and `dotnet run --project scripts\script_path_probe -p:MidaDir=$env:MIDA_DIR -- find-script`.

## Broader data-entry pass

`find-script-all` searched all effective package IDs for the same two exact strings, restricted to MIDA entry types 8 and 16. It reports 151 package IDs, 690,610 entries, zero errors and zero entries over the 64 MiB bound. All 17 `(tag, needle, offset)` matches are identical to the Cryo results, checked by `tests/compare_path_scans.py`. See `data-script-paths.jsonl` and `data-script-paths-scan.txt`. Other file types, encoded strings, scripts with different names, and remote files remain outside this search.

## Implementation-name pass

`find-impl-all` searched the same 151 effective package IDs and types 8/16 for `sc_vault_1_objectives_d_execute_impl` and `spawn_initial_keys`: 690,610 entries, zero reported errors, zero >64 MiB skips. Each needle matched only the previously identified activity metadata `80B37C7E`, at offsets 23879 and 21895 respectively; see `implementation-name-matches.jsonl` and `implementation-name-scan.txt`. This is an exact ASCII search, not an exhaustive implementation search; compiled code, different names, other entry types or server-side code remain unsearched or unidentifiable by this method.
