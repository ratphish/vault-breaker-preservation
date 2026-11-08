# Marathon Vault Breaker: Independent Evidence Verification Matrix

**Date**: 2026-11-07  
**Build Target**: `Marathon.exe` (Steam Build `26136895`, Version `248199.26.10.21.2300.gol_retail.rc`)  
**Scope**: Rigorous distinction between genuinely recovered original Bungie engine behavior and synthetic simulation / AI inferences.

---

## 1. Executive Summary & Audit Methodology

This document establishes the verified ground truth for the PvE activity **Vault Breaker** on the Cryo Archive map (`content\world\production\marathon_deck_001\exp_marathon_deck_001\activity_vault_breaker.es`), auditing all previous assumptions against raw binary offsets, serialized metadata tables, FNV-1 hash chains, and script compiler records.

### Classification Taxonomy
- **`VERIFIED ORIGINAL`**: Backed by exact binary offset, disassembly, or asset record in the preserved client build.
- **`SUPPORTED INFERENCE`**: Logical deduction from verified records (e.g., tier pairings matching member serialization and key chances).
- **`SYNTHETIC`**: Simulator/preservation artifacts created in Python/Unreal for standalone execution, not part of the original game logic.
- **`CONTRADICTED`**: Previous claims or hypotheses refuted by original data.
- **`UNKNOWN`**: Mechanics whose bytecode or runtime implementation was server-authoritative or omitted from the client binary.

---

## 2. Binary Ground Truth Inventory

| Asset Record | Path / Tag | Size | Role / Contents |
|---|---|---|---|
| `80B37FED.bin` | `analysis/vault-reference-records/80B37FED.bin` | 9,403 bytes | Serialized activity component instance (`c_encounter__activity_vault_breaker_instance`), 26 listener rows, 9 universal objective slots (`0x8080B8F1`). |
| `80B37FE9.bin` | `analysis/definition-followup/80B37FE9.bin` | 6,464 bytes | Serialized activity definition (`c_encounter__activity_vault_breaker_definition`), tier accessors, slot dependencies. |
| `80B37C7E.bin` | `analysis/script-compiler-metadata/80B37C7E.bin` | 27,348 bytes | BungieScript compiler metadata, 306 strings, variable symbols (`i_vault_*`, `i_key_chance_*`, `il_*`, `sh_*`). |
| `80B38561.bin` | `analysis/script-compiler-metadata/80B38561.bin` | 3,884 bytes | Key pedestal script compiler metadata (`pf_vault_breaker_key_pedestal.es`). |
| `80B38567.bin` | `analysis/pedestal-12-components/80B38567.bin` | 448 bytes | Key pedestal component instance, binds slot 4 (`sc_handle_create_d_execute_impl`). |

---

## 3. Topic-by-Topic Verification & Falsification

### 3.1 Topic 1: Vault Selection Logic & 4-Tier Progression
- **Original Evidence**:
  - `80B37FED.bin` (offsets `0x1f6c..0x2034`) contains an exact FNV-1 member chain:
    - Member 0: `sc_vault_1_objectives` (`0x1440`, Slot 21)
    - Member 1: `sc_vault_2_objectives` (`0x14f0`, Slot 22)
    - Member 2: `sc_vault_3_objectives` (`0x15a0`, Slot 23)
    - Member 3: `sc_vault_5_objectives` (`0x1650`, Slot 24)
    - Member 4: `sc_vault_4_objectives` (`0x1700`, Slot 25)
    - Member 5: `sc_vault_6_objectives` (`0x17b0`, Slot 26)
    - Member 6: `sc_monitor_secret_lab_visit` (`0x1860`, Slot 27)
    - Member 7: `sc_vault_7_objectives` (`0x1910`, Slot 29)
  - `80B37C7E.bin` contains exactly three key chance symbols: `i_key_chance_1`, `i_key_chance_2`, `i_key_chance_3`, and `spawn_initial_keys` (slot 2).
  - Definition `80B37FE9.bin` exports `get_activity_tier`.
- **Audit Assessment**:
  - The 4-tier model (Stage 1 = {1, 2}, Stage 2 = {3, 5}, Stage 3 = {4, 6}, Stage 4 = {7}) is a **`SUPPORTED INFERENCE`**. The pairing mirrors the serialized order and the three chance variables.
  - The runtime RNG selection algorithm inside `spawn_initial_keys` is **`UNKNOWN`** because its executable bytecode was server-authoritative and not stored in client x86 machine code.
  - Claims of "fixed two-track linear corridors" (e.g. only 1->3->4->7 vs 2->5->6->7) are **`CONTRADICTED`** by community gameplay evidence of mixed routes (e.g. 1->5->4->7).

### 3.2 Topic 2: Battery & Resource Mechanics
- **Original Evidence**:
  - In `80B37FED.bin`, exact raw integers for `i_vault_X_batteries_required`:
    - Vault 1: `5` (`0x384`)
    - Vault 2: `4` (`0x4e4`)
    - Vault 3: `5` (`0x6f4`)
    - Vault 5: `4` (`0x904`)
    - Vault 4: `6` (`0xbc4`)
    - Vault 6: `8` (`0xdd4`)
    - Vault 7: `7` (`0x1094`)
    - HEC Terminal: `3` (`0xfe4`)
  - Coolant canisters required (`i_vault_X_canister_required = 1`):
    - Vault 2: offset `0x594`
    - Vault 5: offset `0x9b4`
    - Vault 6: offset `0xe84`
    - Vaults 1, 3, 4, 7 do NOT require coolant canisters (`0`).
  - Faction credential scans required:
    - Vault 3: `"player.wing_vault_credentials_scan_succeeded"`
    - Vault 5: `"player.tranquility_credentials_scan_succeeded"`
    - Vault 4: `"player.colonist_credentials_scan_succeeded"`
    - Vault 7: `"player.command_credentials_scan_succeeded"`
    - Vaults 1, 2, 6 do NOT require credentials.
- **Audit Assessment**:
  - The battery requirement values `[5, 4, 5, 4, 6, 8, 7]` and `HEC=3` are **`VERIFIED ORIGINAL`**.
  - Canister and credential requirements are **`VERIFIED ORIGINAL`**.
  - The claim that *"Every vault door has a uniform physical capacity of 8 sockets with pre-installed batteries = 8 - required"* is **`CONTRADICTED / SYNTHETIC`**. There is no `total_sockets` or `pre_installed` variable in any engine structure. The engine operates purely on `i_vault_X_batteries_required`.

### 3.3 Topic 3: Secret Labs Antivirus & HEC Batteries
- **Original Evidence**:
  - `80B37FED.bin` Row 21 (`0xfe0`): `il_hec_battery_install` with `i_hec_batteries_required = 3` and incident `"player.marathon_hec_battery_deposited"`.
  - Record 6 (`0x1898`): `sc_monitor_secret_lab_visit` (`0x1860`, Slot 27).
  - Associated symbols: `b_secret_lab_visited`, `b_secret_lab_clue_visited`, `r_time_remaining_when_clue_visited`, `enable_secret_lab_location_ui`, `clear_secret_lab_location_ui`.
- **Audit Assessment**:
  - The HEC battery terminal (`required = 3`) is **`VERIFIED ORIGINAL`**.
  - Its association with the Secret Lab environmental hazard / clue terminal is **`VERIFIED ORIGINAL`**.
  - It is completely distinct from the 7 vaults and does not use credential cards.
  - The exact narrative / reward link between visiting the Secret Lab and DNA blueprints or extraction bonuses is **`SUPPORTED INFERENCE`**.

### 3.4 Topic 4: Vault 7, DNA Blueprints & The Compiler
- **Original Evidence**:
  - Vault 7 requires 7 batteries + Command credentials (`"player.command_credentials_scan_succeeded"`).
  - Interior puzzles trigger `il_vault_interior_puzzles_completed` (`sh_vault_interior_puzzle_completed_incident`).
  - DNA Blueprints are 6 permutations of AGCT: `agct`, `agtc`, `ctag`, `gact`, `tcag`, `tcga`.
  - DNA Vials exist for Vault 4 (`"vault_4_dna_vial"`, `sh_colonist_dna_id`) and Vault 7 (`"vault_7_dna_vial"`, `sh_command_dna_id`).
  - The Compiler fight completion sets boolean `b_compiler_killed`.
  - Script checks `get_current_activity_time_engineer_only` and records `r_time_remaining_when_clue_visited`.
- **Audit Assessment**:
  - Vault 7 requirements, interior puzzle completion, DNA symbols, and Compiler kill tracking are **`VERIFIED ORIGINAL`**.
  - The `120.0s` cutoff implemented in `vault_breaker_progression.py` is **`SYNTHETIC`**. There is no `120.0` constant in engine metadata; the engine dynamically checks remaining mission time, but the cutoff threshold was synthesized for the offline prototype.

---

## 4. Evidence Classification Matrix

| Feature / Mechanic | Status | Binary Offset / Evidence Source | Notes |
|---|---|---|---|
| **PvE Game Mode String** | `VERIFIED ORIGINAL` | `80A66232` (`cryo-activity-arrays-comparison.json`) | `"activity_exp.cryo.vault_breaker_server"`, `"vb_solo_synced"` |
| **7-Vault Objective Handlers** | `VERIFIED ORIGINAL` | `80B37FED.bin` (`0x1478..0x1948`) | Tag `0x8080B8F1`, slot `0xa`, member offsets `0x1440..0x1910` |
| **FNV-1 Member Chain Order** | `VERIFIED ORIGINAL` | `80B37FED.bin` (`0x1f6c..0x2034`) | `main -> 1 -> 2 -> 3 -> 5 -> 4 -> 6 -> lab -> 7` |
| **Battery Deposit Counts** | `VERIFIED ORIGINAL` | `80B37FED.bin` (`0x384..0x1094`) | `5, 4, 5, 4, 6, 8, 7` |
| **HEC Battery Requirement = 3** | `VERIFIED ORIGINAL` | `80B37FED.bin` (`0xfe4`), `80B37C7E.bin` | Neutralizes Secret Lab hazard field |
| **Canister Requirements (V2, V5, V6)** | `VERIFIED ORIGINAL` | `80B37FED.bin` (`0x594`, `0x9b4`, `0xe84`) | Exactly 1 coolant canister required for Vaults 2, 5, 6 |
| **Credential Scans (V3, V5, V4, V7)** | `VERIFIED ORIGINAL` | `80B37FED.bin` (`0x7a4`, `0xa64`, `0xc74`, `0x1144`) | Wing, Tranquility, Colonist, Command |
| **Secret Lab Clue & UI** | `VERIFIED ORIGINAL` | `80B37C7E.bin` | `b_secret_lab_visited`, `r_time_remaining_when_clue_visited` |
| **DNA Blueprints (6 AGCT Perms)** | `VERIFIED ORIGINAL` | `80B37C7E.bin` (`0x5113..0x5292`) | `agct`, `agtc`, `ctag`, `gact`, `tcag`, `tcga` |
| **DNA Vials (V4 & V7)** | `VERIFIED ORIGINAL` | `80B37C7E.bin` (`0x50d5`, `0x5313`) | Colonist (`vault_4`) vs Command (`vault_7`) |
| **Compiler Encounter Tracking** | `VERIFIED ORIGINAL` | `80B37C7E.bin` (`0x6a25`) | `b_compiler_killed` |
| **Activity Event 0x28 Dispatch** | `VERIFIED ORIGINAL` | Native disassembly `0x16fc9fd7f` -> `0x14cb728ed` | Dispatches objective phase transition (40 / `0x28`) |
| **4-Tier Progression Graph** | `SUPPORTED INFERENCE` | `80B37FE9.bin`, `i_key_chance_1..3`, community videos | Stage 1 {1,2}, Stage 2 {3,5}, Stage 3 {4,6}, Stage 4 {7} |
| **Mixed Route Permutations** | `SUPPORTED INFERENCE` | 8 possible paths across 3 independent tier stages | Verified in observed gameplay (e.g. 1 -> 5 -> 4 -> 7) |
| **8-Socket Universal Capacity** | `CONTRADICTED` | Refuted by `80B37FED.bin` field definitions | Engine tracks required batteries, not missing from 8 |
| **Pre-Installed Battery Math** | `CONTRADICTED` | No `8 - required` logic in engine scripts | Synthetic simulation assumption |
| **120-Second Compiler Cutoff** | `SYNTHETIC` | `vault_breaker_progression.py` line 125 | Configurable simulator cutoff; real engine checks dynamic timer |
| **Spawn Initial Keys Bytecode** | `UNKNOWN` | No native client entry point (`2026-11-01-offline-emulation.md`) | Server-authoritative script execution |
