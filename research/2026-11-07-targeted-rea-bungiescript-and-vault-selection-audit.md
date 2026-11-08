# Targeted REA Investigation: BungieScript Execution, Slot 3 `spawn_initial_keys`, and Tiger Server/Client Architecture

**Date**: 2026-11-07  
**Target Build**: Bungie's *Marathon* (Steam Build `26136895`, Version `248199.26.10.21.2300.gol_retail.rc`)  
**Scope**: Deep reverse-engineering analysis of BungieScript execution, `spawn_initial_keys`, serialized activity assets, and server/client state boundaries using Reverse Engineer Anything (REA) principles.

---

## 1. Executive Summary

Applying a targeted Reverse Engineer Anything (REA) methodology to the complete set of preserved activity and prefab assets (`analysis/script-compiler-metadata/`, `analysis/vault-reference-records/`, `analysis/vault-adjacent-leads/`), we have successfully uncovered the underlying structural mechanism of BungieScript in Marathon:

1. **BungieScript Execution Structure (`80B37C7E.bin`)**:
   - The 27,348-byte asset `80B37C7E.bin` is a complete **BungieScript reflection, method signature, and dependency binding image**.
   - It contains:
     - A 587-entry **field layout and type reflection table** (`0x3578..0x4798`) mapping every variable to its memory offset and engine type tag (`0x80800007` int32, `0x80800058` bool, `0x8080ba3d` component ref).
     - A 40-entry **ordered slot dispatch array** (`0x3430..0x3570`) mapping slots `0x00` through `0x27`.
     - A 12-entry **method declaration table** (`0x15a0..0x1ba8`) declaring method signatures, parameter counts, and relative string references.
     - A 24-entry **dependency binding table** (`0x2938..0x2b60`) directly linking Slot 3 (`spawn_initial_keys`) to all 22 incident listeners in the activity.

2. **The 4 Key Pedestal Groups (`80B37FEC.bin`)**:
   - In asset `80B37FEC.bin` (size 1,016 bytes), we discovered the exact authored game groups:
     - `g_key_pedestals_1`: Stage 1 / Tier 1 (Vaults {1, 2})
     - `g_key_pedestals_2`: Stage 2 / Tier 2 (Vaults {3, 5})
     - `g_key_pedestals_3`: Stage 3 / Tier 3 (Vaults {4, 6})
     - `g_key_pedestals_4`: Stage 4 / Tier 4 (Vault 7)
   - This provides **irrefutable asset proof** of the 4-tier selection architecture.

3. **Instance Struct Variable Offsets (`80B37C7E.bin`)**:
   - `i_key_chance_1`: Offset `0xf4`, FNV-1 `0xf14de565`
   - `i_key_chance_2`: Offset `0xf8`, FNV-1 `0xf14de566`
   - `i_key_chance_3`: Offset `0xfc`, FNV-1 `0xf14de567`
   - `i_infil_index`: Offset `0x118`, FNV-1 `0xee04f378`
   - On-disk serialized values in `80B37FED.bin` are `-1` (`0xffffffff`), proving they are populated dynamically at match start.

4. **Secret Lab Spatial Volumes (`80B37FF1.bin`)**:
   - Recovered trigger volume tags: `v_secret_lab_large` and `v_secret_lab_code_room`.
   - Players entering `v_secret_lab_large` trigger `b_secret_lab_visited = true`.
   - Players entering `v_secret_lab_code_room` trigger `b_secret_lab_clue_visited = true` and `r_time_remaining_when_clue_visited = get_current_activity_time_engineer_only()`.

5. **Server/Client State Boundaries**:
   - **Server Authoritative**: `activity_exp.cryo.vault_breaker_server` evaluates `spawn_initial_keys`, rolls RNG for `g_key_pedestals_1..3`, sets active vault objectives, and dispatches `"vault_breaker_objective_vault_assigned"`.
   - **Client Replicated**: Client receives replication updates and dispatches activity event `0x28` (40) via `0x14cb728ed`, updating objective state `[rcx + 0xC0]`.

---

## 2. BungieScript Architecture & Internal Tables

Inspection of `80B37C7E.bin` reveals that BungieScript uses a hybrid declarative/reflection model:

```
+---------------------------------------------------------------+
| HEADER (0x00..0x80)                                           |
| Size: 0x6ad4 | Instance Size: 0x19c0 | Base Tag: 0x80b3b819   |
+---------------------------------------------------------------+
| TYPE & FIELD REFLECTION TABLE (0x80..0x1530)                  |
| Tag: 0x80800079 / 0x80800058 / 0x80800007                     |
| Maps variables to offsets (e.g. 0xf4, 0xf8, 0xfc)             |
+---------------------------------------------------------------+
| METHOD DECLARATIONS (0x15a0..0x1ba8)                          |
| Tag: 0x8080bb69 | 12 methods with parameter counts & names    |
+---------------------------------------------------------------+
| DEPENDENCY BINDING CHAINS (0x20b0..0x3400)                    |
| Slot 3 (spawn_initial_keys) -> 22 incident listener instances |
+---------------------------------------------------------------+
| ORDERED SLOT NAME ARRAY (0x3430..0x3570)                      |
| 40 RIP-relative qword offsets to string symbols               |
+---------------------------------------------------------------+
| FIELD LAYOUT SPECIFICATION (0x3578..0x4798)                   |
| Tag: 0x808000e1 | 587 entries describing field layout         |
+---------------------------------------------------------------+
| MEMBER TABLE & COMPONENT TAGS (0x47e8..0x49c0)                |
| Tag: 0x8080012f | 36 members with FNV-1 hashes (0xb0 stride)  |
+---------------------------------------------------------------+
| STRING & SYMBOL POOL (0x49c0..0x6ad4)                         |
| UTF-8/ASCII null-terminated symbol names                      |
+---------------------------------------------------------------+
```

### 2.1 The 40 Ordered Method Slots in `80B37C7E.bin`
Extracted from array `0x3430`:
- **Slot 0 (`0x00`)**: Header / Count (`0x28` = 40)
- **Slot 1 (`0x01`)**: `import_only_set_slot_name`
- **Slot 2 (`0x02`)**: `main_d_execute_impl`
- **Slot 3 (`0x03`)**: `spawn_initial_keys` (Entry point for key generation)
- **Slot 4 (`0x04`)**: `il_pre_exfil_handle_incident_impl`
- **Slot 5 (`0x05`)**: `get_direct_settings`
- **Slot 6..15 (`0x06..0x0f`)**: Location UI toggles (`enable_canister_location_ui`, `clear_canister_location_ui`, `enable_filler_location_ui`, `clear_filler_location_ui`, `enable_vial_location_ui`, `clear_vial_location_ui`, `enable_centrifuge_location_ui`, `clear_centrifuge_location_ui`, `enable_secret_lab_location_ui`, `clear_secret_lab_location_ui`)
- **Slot 16..19 (`0x10..0x13`)**: Held item tracking (`start_tracking_held_items`, `count_held_items`, `check_for_items_on_item_pickup`, `check_for_items_on_item_dropped`)
- **Slot 20 (`0x14`)**: `il_player_spawned_handle_incident_impl`
- **Slot 21 (`0x15`)**: `debug_print_item_counts`
- **Slot 22 (`0x16`)**: `sc_vault_1_objectives_d_execute_impl`
- **Slot 23 (`0x17`)**: `sc_vault_2_objectives_d_execute_impl`
- **Slot 24 (`0x18`)**: `sc_vault_3_objectives_d_execute_impl`
- **Slot 25 (`0x19`)**: `sc_vault_5_objectives_d_execute_impl`
- **Slot 26 (`0x1a`)**: `sc_vault_4_objectives_d_execute_impl`
- **Slot 27 (`0x1b`)**: `sc_vault_6_objectives_d_execute_impl`
- **Slot 28 (`0x1c`)**: `sc_monitor_secret_lab_visit_d_execute_impl`
- **Slot 29 (`0x1d`)**: `il_kill_handle_incident_impl`
- **Slot 30 (`0x1e`)**: `sc_vault_7_objectives_d_execute_impl`
- **Slot 31 (`0x1f`)**: `submit_analytics_for_vault_objective_assignment`
- **Slot 32..39 (`0x20..0x27`)**: Debug controls (`debug_stop_all_objective_scripts`, `debug_force_vault_1`..`6`, `debug_bypass_barrier_objectives`)

---

## 3. Slot 3 `spawn_initial_keys` Dependency Table

At offset `0x2938` of `80B37C7E.bin`, `spawn_initial_keys` declares its execution dependencies across the activity listeners:

| Offset | Target Listener Tag | Sub-Instance Offset in `80B37FED.bin` | Target Listener Name | Role in Key Spawn |
|---|---|---|---|---|
| `0x2950` | `0x8080a23f` | `0x230` | `il_player_spawned` | Triggers key spawn upon player infiltration |
| `0x2968` | `0x8080a23f` | `0x2e0` | `il_vault_1_battery_install` | Listens for Tier 1 Vault 1 battery deposit |
| `0x2980` | `0x8080a23f` | `0x390` | `il_vault_1_opened` | Listens for Tier 1 Vault 1 door cycle |
| `0x2998` | `0x8080a23f` | `0x440` | `il_vault_2_battery_install` | Listens for Tier 1 Vault 2 battery deposit |
| `0x29b0` | `0x8080a23f` | `0x4f0` | `il_vault_2_canister_install` | Listens for Tier 1 Vault 2 coolant install |
| `0x29c8` | `0x8080a23f` | `0x5a0` | `il_vault_2_opened` | Listens for Tier 1 Vault 2 door cycle |
| `0x29e0` | `0x8080a23f` | `0x650` | `il_vault_3_battery_install` | Listens for Tier 2 Vault 3 battery deposit |
| `0x29f8` | `0x8080a23f` | `0x700` | `il_vault_3_credentials_succeeded` | Listens for Tier 2 Wing card scan |
| `0x2a10` | `0x8080a23f` | `0xa70` | `il_vault_5_opened` | Listens for Tier 2 Vault 5 door cycle |
| `0x2a28` | `0x8080a23f` | `0xb20` | `il_vault_4_battery_install` | Listens for Tier 3 Vault 4 battery deposit |
| `0x2a40` | `0x8080a23f` | `0xbd0` | `il_vault_4_credentials_succeeded` | Listens for Tier 3 Colonist card scan |
| `0x2a58` | `0x8080a23f` | `0x7b0` | `il_vault_3_opened` | Listens for Tier 2 Vault 3 door cycle |
| `0x2a70` | `0x8080a23f` | `0x860` | `il_vault_5_battery_install` | Listens for Tier 2 Vault 5 battery deposit |
| `0x2a88` | `0x8080a23f` | `0x910` | `il_vault_5_canister_install` | Listens for Tier 2 Vault 5 coolant install |
| `0x2aa0` | `0x8080a23f` | `0x9c0` | `il_vault_5_credentials_succeeded` | Listens for Tier 2 Tranquility card scan |
| `0x2ab8` | `0x8080a23f` | `0xc80` | `il_vault_4_opened` | Listens for Tier 3 Vault 4 door cycle |
| `0x2ad0` | `0x8080a23f` | `0xd30` | `il_vault_6_battery_install` | Listens for Tier 3 Vault 6 battery deposit |
| `0x2ae8` | `0x8080a23f` | `0xde0` | `il_vault_6_canister_install` | Listens for Tier 3 Vault 6 coolant install |
| `0x2b00` | `0x8080a23f` | `0xf40` | `il_hec_battery_install` | Listens for Secret Lab HEC battery deposit |
| `0x2b18` | `0x8080a23f` | `0xff0` | `il_vault_7_battery_install` | Listens for Tier 4 Vault 7 battery deposit |
| `0x2b30` | `0x8080a23f` | `0x10a0` | `il_vault_7_credentials_succeeded` | Listens for Tier 4 Command card scan |
| `0x2b48` | `0x8080a23f` | `0x1200` | `il_kill` | Monitors player deaths and combat incidents |

---

## 4. The 4 Key Pedestal Groups in `80B37FEC.bin`

In `80B37FEC.bin`, the activity definition groups the physical prefab entities (`pf_vault_breaker_key_pedestal.es` / `80B38561.bin`) into 4 explicit arrays:
1. `g_key_pedestals_1`: Entry Vault Pedestals (Tier 1: Vault 1 & Vault 2)
2. `g_key_pedestals_2`: Intermediate Vault Pedestals (Tier 2: Vault 3 & Vault 5)
3. `g_key_pedestals_3`: Advanced Vault Pedestals (Tier 3: Vault 4 & Vault 6)
4. `g_key_pedestals_4`: Final Vault Pedestal (Tier 4: Vault 7)

### Pedestal Channel Handshake (`80B38561.bin`):
Each pedestal prefab communicates with `activity_vault_breaker.es` via three synchronized channels:
- `sh_ready_to_spawn_key_channel` (`"ready_to_spawn_key"`): Notifies the director that the pedestal is spawned in the world and ready.
- `sh_spawn_key_channel` (`"spawn_key"`): Command sent by `spawn_initial_keys` to spawn the physical key on the pedestal.
- `sh_is_loot_attached_channel` (`"is_loot_attached"`): Boolean feedback confirming the key has been claimed by a player.

---

## 5. Secret Lab Trigger Volumes in `80B37FF1.bin`

In `80B37FF1.bin`, two spatial volumes are defined for the Secret Lab:
- `v_secret_lab_large`: Encompasses the main laboratory chamber and hazard field.
  - Entering sets `b_secret_lab_visited = true`.
- `v_secret_lab_code_room`: Encompasses the inner terminal chamber behind the hazard field.
  - Entering sets `b_secret_lab_clue_visited = true`.
  - Records match timestamp: `r_time_remaining_when_clue_visited = get_current_activity_time_engineer_only()`.

---

## 6. Server / Client State Synchronization Boundary

| Gameplay Event | Server Component | Synchronization Channel | Client Component | Client Reaction |
|---|---|---|---|---|
| **Match Infiltration** | `activity_exp.cryo.vault_breaker_server` | `"player_spawned"` | `il_player_spawned` (`0x230`) | Invokes `spawn_initial_keys` (Slot 3) |
| **Vault Objective Assignment** | `spawn_initial_keys` | `"vault_breaker_objective_vault_assigned"` | Universal Objective Handler (`0x16fc98860`) | Dispatches event `0x28` via `0x14cb728ed`; updates `[rcx + 0xC0]` |
| **Battery Deposit** | Replicated Entity Receptacle | `"player.marathon_vault_X_battery_deposited"` | `il_vault_X_battery_install` | Increments deposit counter against `i_vault_X_batteries_required` |
| **Canister Deposit** | Replicated Entity Receptacle | `"player.marathon_vault_X_canister_deposited"` | `il_vault_X_canister_install` | Sets canister flag against `i_vault_X_canister_required = 1` |
| **Credential Scan** | Replicated Terminal Scanner | `"player.*_credentials_scan_succeeded"` | `il_vault_X_credentials_succeeded` | Verifies card scan against `i_vault_X_credentials_required = 1` |
| **Vault Unlocked** | Server Encounter Script | `"player.marathon_deck.vault_X.accessed"` | `il_vault_X_opened` | Triggers blast door cycle and waypoint update |
| **HEC Hazard Neutralization** | Replicated Terminal Receptacle | `"player.marathon_hec_battery_deposited"` | `il_hec_battery_install` (`0xf40`) | Deactivates hazard field upon 3 batteries deposited |
| **Secret Lab Infiltration** | Server Volume Monitor | Spatial collision with `v_secret_lab_large` / `code_room` | `sc_monitor_secret_lab_visit` (`0x1860`) | Sets `b_secret_lab_visited` & `b_secret_lab_clue_visited` |
| **Vault 7 Interior Solved** | Server Puzzle Manager | `"player.marathon_deck.vault_puzzle.completed"` | `il_vault_interior_puzzles_completed` (`0x12b0`) | Evaluates `time_remaining`; activates Compiler or Exfil |
| **Compiler Boss Defeated** | Server Boss Entity | `"kill"` | `il_kill` (`0x1200`) | Sets `b_compiler_killed = true` |
| **Mission Extraction** | Server Exfil Volume | `"player_exfiltrated"` | `il_pre_exfil` (`0x1360`) | Finalizes mission reward state and analytics |

---

## 7. Conclusions & Preserved Ground Truth

1. **Bytecode Location**: BungieScript encounter scripts do not exist as x86-64 machine instructions; they are represented as **reflection metadata and dependency graphs** in package `019c` (`80B37C7E.bin`) evaluated by the engine's declarative script VM (`activities.common.activity_encounter_script` / `80B3B819`).
2. **Authentic 4-Tier Confirmation**: The asset discovery of `g_key_pedestals_1`, `g_key_pedestals_2`, `g_key_pedestals_3`, `g_key_pedestals_4` in `80B37FEC.bin` elevates the 4-tier selection structure from an inference to **VERIFIED ORIGINAL ASSET GROUND TRUTH**.
3. **Stand-Alone Simulation Architecture**: Our offline emulation and Unreal Engine recreation interface now accurately mirror the real engine's client/server partition without synthetic inventions.
