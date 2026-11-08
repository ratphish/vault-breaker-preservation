# Research notes

The investigation is ongoing. The preserved build is `D:\Marathon-preservation\build-26136895-20261031`; do not alter it or the live install for experiments.

- [Cryo activity chain and build verification](2026-10-31-cryo-chain.md) — reproduction, earlier-work attribution and snapshot provenance.
- [Native executable analysis](2026-10-31-native-analysis.md) — REA/Ghidra attempts and limited direct disassembly.
- [Offline emulation](2026-11-01-offline-emulation.md) — synthetic entry and thread-wrapper probes with inert API markers.
- [Managed helper decompilation](2026-10-31-managed-helper.md) — decompiler output for three CLI-declared files; the main game is a separate native target.
- [Handle-map layout probe](2026-10-31-handle-map.md) — sorted IDs and bounded index-array observations; semantics remain unknown.
- [Lua signature scans](2026-10-31-lua-scan.md) — search bounds and results.
- [Script-path search](2026-10-31-script-path-search.md) — bounded scan of data entries.

The complete earlier research remains in `C:\Users\marra\Documents\Codex\2026-10-27\hel\outputs\Cryo Archive evidence.md`. Preserve uncertainty: a script name or serialized record is not executable logic; no standalone playable mode or full decompilation has been demonstrated. Game files and decoded assets must remain outside this repository.

The private Ghidra indexes currently contain 162,563 bounded pseudocode records derived from modeled text windows. They can be searched locally, but they are not an original source tree: see the offline-emulation note for the protection, coverage, warning and validation limits.

The expanded private indexes now contain 210,348 bounded pseudocode records across the modeled and extrapolated text-table windows. Their completion counts, quality warnings, build identity, and synthetic-model limitations are documented in the offline-emulation note.
