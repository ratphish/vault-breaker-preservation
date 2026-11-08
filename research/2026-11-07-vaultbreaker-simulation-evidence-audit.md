# Vault Breaker Simulation Evidence Audit: Native Executable & Asset Truth vs. Hypothesized Mocks

**Date**: 2026-11-07  
**Target Build**: `Marathon.exe` (Steam Build `26136895`, Version `248199.26.10.21.2300.gol_retail.rc`)  
**Scope**: Rigorous architectural evidence audit separating original executed instructions and authored binary assets from synthetic mock data and hypothesized gameplay behaviors.

---

## 1. Executive Summary

During earlier emulation and test development, a 9-phase linear mission lifecycle was hypothesized in Python (`scripts/vault_ecs_fixture.py` and `tests/test_vault_mission_simulation.py`) to drive tests for the PvE activity **Vault Breaker** (Cryo Archive).

This evidence audit cross-references:
1. **The Native Executable (`synthetic-text-section.bin`)**: Traced disassembly of handle resolution (`0x1597b8f5e`), objective dispatch (`0x16fc98860` / `0x16fc9fd74`), Arxan anti-tamper entry (`0x14cb728ed`), and status bitfield evaluation (`0x148ed4ab6`).
2. **Compiled Script Metadata (`80B37C7E.bin`)**: 27,348-byte compiler symbol table for `activity_vault_breaker.es`.
3. **Serialized Activity Records (`80B37FED.bin`, `80B37FEC.bin`, `80B38567.bin`)**: Binary asset layouts defining the Cryo Archive encounter structure.

### Key Finding
**The 9 records in the game's activity component (`80B37FED.bin`) do NOT represent a linear 9-step mission sequence.**  
Instead, they correspond to the **7 parallel, selectable Vault Objectives** in the Cryo Archive facility (`Vault 1` through `Vault 7`), plus a **Secret Lab Monitor**, plus the **Root Activity Encounter**. The 9 linear names previously synthesized (`INFILTRATION_APPROACH`, `SECURITY_BREACH`, etc.) were hypothesized by Codex and do not exist in the original game files.

---

## 2. Verified-versus-Hypothesized Matrix

| Dimension | Verified Original Game Truth (Binary & Asset Evidence) | Hypothesized / Synthetic Mock (In Current Python Baseline) | Status |
|---|---|---|---|
| **Activity Structure (9 Records)** | `80B37FED.bin` contains 9 records (`0xB0` stride) binding `8080B8F1` Slot 10. Records 0–7 explicitly link via slot indices `0x15..0x1D` to `sc_vault_1_objectives` through `sc_vault_7_objectives` and `sc_monitor_secret_lab_visit` in `80B37C7E.bin`. | Modeled as 9 sequential linear phases of a single vault (`INFILTRATION_APPROACH` $\to$ `MISSION_EXTRACTION_COMPLETE`). | **Debunked & Corrected**: Verified as 7 Vaults + Secret Lab + Root Encounter. |
| **Event `0x28` Opcode** | `0x16fc9fd7f: mov eax, 0x28` directly precedes `call 0x14cb728ed`. There is exactly **1 direct caller** to `0x14cb728ed` across the entire 851MB text section. | Modeled as an external `EVENT_OBJECTIVE_SYNC` callback notification. | **VERIFIED**: `0x28` is the native opcode dispatched by Active Step 3. |
| **State Word `[rcx + 0xC0]`** | Traced past Arxan entry `0x14cb728ed` to `0x148ed4ab6`: `mov eax, ecx; shr eax, 0xc; and al, 1; cmp al, r9b`. Bit 12 (`(val >> 12) & 1`) is an active/completed latch condition. | Treated as a flat integer 0..8 index (`current_phase`). | **Corrected**: State is a status bitfield (bit 12 flag), not a simple scalar phase index. |
| **Handle Table Root `0x1755bb480`** | `0x1597b8f7c: mov r8, qword ptr [rip + 0x1be024fd]` resolves to `0x1755bb480`. Formula: `bucket = (handle >> 13) & 0x3FF`, `slot = handle & 0x1FFF`, bucket base `[r8]`, `stride = [r8 + 0x10]`. | Standalone arena allocated at `0x7FF00000` with 4,096 synthetic buckets. | **VERIFIED FORMULA / SYNTHETIC INSTANCES**: Mathematical algorithm is 100% native; bucket instances in memory are synthetic. |
| **Key Pedestals** | `80B37FEC.bin` defines 4 interactive world pedestals: `g_key_pedestals_1`, `g_key_pedestals_2`, `g_key_pedestals_3`, `g_key_pedestals_4`. Prefab `80B38567.bin` binds to `8080B8F1` Slot 10. | Modeled as a single global mission phase (Phase 3: `PEDESTAL_KEY_INSERTION`). | **Corrected**: Pedestals are multi-station world interactive props. |
| **Blast Door Controller** | Script metadata references incident strings: `"il_vault_1_opened"` through `"il_vault_7_opened"`, `"player.marathon_deck.vault_1.accessed"`. | Fabricated tag `0x80809C14` and arbitrary memory offset `DOOR_ENTITY_ADDR + 0x80` ($0 \to 2$). | **HYPOTHESIZED MOCK**: Tag `80809C14` is synthetic; original game uses incident triggers and state variables. |
| **Item Hash `0x00244270`** | Key `0x00244270` is the first row in startup investment asset `80A6A004.bin`, resolving to byte `0x12`. Original vault items are named quest attributes (e.g. `vault_credentials1..7`, `vault_canister0`, `vault_7_dna_vial`). | Modeled specifically as the single "Vault Key item hash". | **PARTIALLY VERIFIED**: Valid binary search test key in investment table; not proven to be the exclusive key ID. |

---

## 3. Detailed Instruction & Asset Evidence

### 3.1 The 9 Records in `80B37FED.bin` Link to Vaults 1..7
In `80B37FED.bin`, starting at offset `0x1478`, 9 records are serialized with uniform size `0xB0` (176 bytes):
- Offset `0x1478`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x15` (21)
- Offset `0x1528`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x16` (22)
- Offset `0x15D8`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x17` (23)
- Offset `0x1688`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x18` (24)
- Offset `0x1738`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x19` (25)
- Offset `0x17E8`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x1A` (26)
- Offset `0x1898`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x1B` (27)
- Offset `0x1948`: `8080B8F1`, Slot 10 $\to$ Target `80B37C7E` Slot `0x1D` (29)
- Offset `0x19F8`: `8080B8F1`, Slot 10 $\to$ Target `8080BD07` Slot `0x0A` (10)

Cross-referencing with compiler symbol metadata `80B37C7E.bin`:
- Slot 21 (`0x15`): `sc_vault_1_objectives_d_execute_impl`
- Slot 22 (`0x16`): `sc_vault_2_objectives_d_execute_impl`
- Slot 23 (`0x17`): `sc_vault_3_objectives_d_execute_impl`
- Slot 24 (`0x18`): `sc_vault_5_objectives_d_execute_impl`
- Slot 25 (`0x19`): `sc_vault_4_objectives_d_execute_impl`
- Slot 26 (`0x1A`): `sc_vault_6_objectives_d_execute_impl`
- Slot 27 (`0x1B`): `sc_monitor_secret_lab_visit_d_execute_impl`
- Slot 29 (`0x1D`): `sc_vault_7_objectives_d_execute_impl`
- Target `8080BD07`: Root Encounter Instance (`c_encounter__activity_vault_breaker_instance`)

### 3.2 Authentic Vault Gameplay Requirements (from `80B37C7E.bin`)
Rather than a single linear key insertion, each vault has distinct gameplay mechanics authored by Bungie:
- **Vault 1**: Requires batteries (`i_vault_1_batteries_required`). Incident: `"player.marathon_vault_1_battery_deposited"`.
- **Vault 2**: Requires batteries and canisters (`i_vault_2_batteries_required`, `i_vault_2_canister_required`). Incident: `"player.marathon_vault_2_canister_deposited"`.
- **Vault 3**: Requires batteries and wing credentials scan (`i_vault_3_credentials_required`, `"player.wing_vault_credentials_scan_succeeded"`).
- **Vault 4**: Requires colonist credentials scan (`i_vault_4_credentials_required`, `"player.colonist_credentials_scan_succeeded"`).
- **Vault 5**: Requires tranquility credentials scan and canisters (`i_vault_5_credentials_required`, `"player.tranquility_credentials_scan_succeeded"`).
- **Vault 6**: Requires batteries and canisters (`i_vault_6_batteries_required`, `i_vault_6_canister_required`).
- **Vault 7**: Requires command credentials scan, batteries, and DNA blueprint (`i_vault_7_credentials_required`, `i_vault_7_blueprint_held`, `"player.command_credentials_scan_succeeded"`).

### 3.3 Event `0x28` Dispatch Control Flow
Native disassembly from `synthetic-text-section.bin`:
```x86asm
; 1. Active Step 3 at 0x16fc9fd74:
0x16fc9fd74: cmp dword ptr [rax + 8], eax
0x16fc9fd77: jne 0x16fc9fdc3
0x16fc9fd79: mov ecx, dword ptr [rcx + 0xc0] ; Reads status bitfield
0x16fc9fd7f: mov eax, 0x28                   ; Opcode 40
0x16fc9fd84: call 0x14cb728ed                ; Dispatcher call
0x16fc9fd89: ret

; 2. Arxan trampoline at 0x14cb728ed -> 0x150009314 computes jump target delta:
;    Target destination = 0x148ed4a57

; 3. Status bitfield inspection at 0x148ed4ab6:
0x148ed4ab6: mov eax, ecx
0x148ed4ab8: shr eax, 0xc                   ; Shift down 12 bits
0x148ed4abb: and al, 1                      ; Extract bit 12
0x148ed4abd: cmp al, r9b                    ; Compare with expected state latch
```

---

## 4. Reproducible Verification Suite

The findings in this audit are enforced by [`tests/test_vault_simulation_evidence_audit.py`](file:///d:/vault-breaker-preservation/tests/test_vault_simulation_evidence_audit.py):
1. `test_audit_activity_component_9_records`: Validates the exact 9 0xB0-strided records in `80B37FED.bin`.
2. `test_audit_activity_script_slots_map_to_7_vaults`: Proves the mapping to Vaults 1..7 + Secret Lab in `80B37C7E.bin`.
3. `test_audit_generational_handle_lookup_native_assembly`: Asserts original x86-64 instructions at `0x1597b8f5e`.
4. `test_audit_event_0x28_dispatch_and_bitfield_semantics`: Asserts Step 3 instructions and bit-12 extraction.
5. `test_audit_hypothesized_names_and_tags_absence_in_originals`: Rigorously verifies that `INFILTRATION_APPROACH` and `80809C14` do NOT exist in the original assets.
6. `test_audit_key_pedestal_world_records`: Proves the existence of `g_key_pedestals_1..4` in `80B37FEC.bin`.

All 6 audit tests run and pass alongside the 15 baseline tests (21/21 total).
