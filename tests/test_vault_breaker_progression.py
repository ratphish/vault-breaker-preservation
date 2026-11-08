"""Deterministic unit tests for Vault Breaker 4-stage progression,
battery socket capacity, mixed route generation, and Compiler encounter logic.
"""
import pytest
from vault_breaker_progression import (
    VaultTier, TOTAL_BATTERY_SOCKET_CAPACITY,
    VAULT_BATTERIES_REQUIRED, VAULT_CANISTER_REQUIRED,
    VAULT_CREDENTIALS_REQUIRED, VAULT_DNA_REQUIRED,
    TIER_ELIGIBILITY, INFILTRATION_REGIONS, DNA_BLUEPRINT_CARDS,
    VaultBreakerDirector, GameMode
)


def test_battery_capacity_and_raw_integers():
    """Verify that every vault uses total battery socket capacity 8,

    and verify the meaning of recovered raw integers [5, 4, 5, 6, 4, 8, 7].
    """
    assert TOTAL_BATTERY_SOCKET_CAPACITY == 8
    
    # Expected: (vault_id, required, pre_installed)
    expected_specs = [
        (1, 5, 3),
        (2, 4, 4),
        (3, 5, 3),
        (4, 6, 2),
        (5, 4, 4),
        (6, 8, 0),
        (7, 7, 1),
    ]
    
    director = VaultBreakerDirector(seed=42)
    for v_id, req, pre_inst in expected_specs:
        assert VAULT_BATTERIES_REQUIRED[v_id] == req, f"Vault {v_id} expected {req} batteries required"
        assert director.get_pre_installed_batteries(v_id) == pre_inst, f"Vault {v_id} expected {pre_inst} pre-installed"
        assert req + pre_inst == TOTAL_BATTERY_SOCKET_CAPACITY, f"Vault {v_id} sum must equal 8"
        
    print("PASS: Verified total socket capacity 8 and exact raw integers 5, 4, 5, 6, 4, 8, 7")


def test_tier_eligibility_and_permutation_coverage():
    """Find deterministic seeds that generate all 8 possible 3-vault route permutations,

    including observed mixed routes like 1 -> 5 -> 4 -> 7.
    """
    found_permutations = {}
    
    # Search seeds 0..500 to map all 8 permutations
    for seed in range(500):
        d = VaultBreakerDirector(seed=seed)
        route_tuple = tuple(d.plan.selected_vaults)
        if route_tuple not in found_permutations:
            found_permutations[route_tuple] = seed
            
        if len(found_permutations) == 8:
            break
            
    assert len(found_permutations) == 8, f"Expected 8 permutations, found {len(found_permutations)}"
    
    # Verify all 8 combinations are present:
    # Tier 1: {1, 2}, Tier 2: {3, 5}, Tier 3: {4, 6}, Tier 4: {7}
    all_expected = {
        (1, 3, 4, 7), (1, 3, 6, 7),
        (1, 5, 4, 7), (1, 5, 6, 7),
        (2, 3, 4, 7), (2, 3, 6, 7),
        (2, 5, 4, 7), (2, 5, 6, 7),
    }
    assert set(found_permutations.keys()) == all_expected
    
    # Specifically assert the observed mixed route (1, 5, 4, 7) exists and is reproducible
    seed_mixed = found_permutations[(1, 5, 4, 7)]
    d_mixed = VaultBreakerDirector(seed=seed_mixed)
    assert d_mixed.plan.selected_vaults == [1, 5, 4, 7]
    print(f"PASS: Verified all 8 tier route permutations. Mixed route [1, 5, 4, 7] verified with seed {seed_mixed}")


def test_full_playthrough_mixed_route_with_compiler():
    """Simulate complete mixed route 1 -> 5 -> 4 -> 7 followed by Compiler boss fight."""
    # Seed known to produce [1, 5, 4, 7]
    seed_mixed = None
    for s in range(500):
        if VaultBreakerDirector(seed=s).plan.selected_vaults == [1, 5, 4, 7]:
            seed_mixed = s
            break
            
    assert seed_mixed is not None
    d = VaultBreakerDirector(seed=seed_mixed)
    assert d.plan.selected_vaults == [1, 5, 4, 7]
    assert d.current_tier == VaultTier.TIER_1
    assert d.current_active_vault == 1

    # Stage 1: Vault 1 (Requires 5 batteries)
    assert d.attempt_unlock_active_vault() is False, "Must fail without batteries"
    d.supply_loot_for_vault(1)
    assert d.attempt_unlock_active_vault(elapsed_seconds=150.0) is True
    assert d.current_tier == VaultTier.TIER_2
    assert d.current_active_vault == 5

    # Stage 2: Vault 5 (Requires 4 batteries + 1 canister + Tranquility creds)
    assert d.attempt_unlock_active_vault() is False, "Must fail without canister and credentials"
    d.supply_loot_for_vault(5)
    assert d.attempt_unlock_active_vault(elapsed_seconds=200.0) is True
    assert d.current_tier == VaultTier.TIER_3
    assert d.current_active_vault == 4

    # Stage 3: Vault 4 (Requires 6 batteries + Colonist creds)
    assert d.attempt_unlock_active_vault() is False
    d.supply_loot_for_vault(4)
    assert d.attempt_unlock_active_vault(elapsed_seconds=200.0) is True
    assert d.current_tier == VaultTier.TIER_4
    assert d.current_active_vault == 7

    # Stage 4: Vault 7 (Requires 7 batteries + Command creds + DNA card)
    assert d.attempt_unlock_active_vault() is False
    d.supply_loot_for_vault(7)
    assert d.attempt_unlock_active_vault(elapsed_seconds=250.0) is True
    assert d.current_tier == VaultTier.FINALE
    assert d.completed_vaults == [1, 5, 4, 7]

    # Finale: Compiler Encounter (Elapsed: 150+200+200+250 = 800s, Time remaining: 1200 - 800 = 400s >= 120s)
    assert d.time_remaining_seconds == 400.0
    compiler_success = d.attempt_compiler_encounter()
    assert compiler_success is True
    assert d.compiler_killed is True
    assert d.mission_completed is True
    assert "b_compiler_killed" in d.event_log
    assert "il_pre_exfil" in d.event_log
    print("PASS: Full playthrough 1 -> 5 -> 4 -> 7 -> Compiler verified")


def test_compiler_timeout_exfil():
    """Verify that if insufficient time remains after Vault 7, Compiler is skipped and exfil occurs."""
    d = VaultBreakerDirector(seed=0)
    # Fast forward through all 4 vaults but consume 1150 seconds (remaining: 50s < 120s)
    for v_id in d.plan.selected_vaults:
        d.supply_loot_for_vault(v_id)
        d.attempt_unlock_active_vault(elapsed_seconds=287.5)
        
    assert d.time_remaining_seconds == 50.0
    assert d.current_tier == VaultTier.FINALE
    
    # Attempt compiler
    result = d.attempt_compiler_encounter()
    assert result is False, "Compiler encounter must not start when time < 120s"
    assert d.compiler_killed is False
    assert d.mission_completed is True
    assert "il_pre_exfil" in d.event_log
    print("PASS: Timeout handling verified: Compiler skipped and direct exfiltration initiated")


def test_pve_mode_string_differentiation():
    """Verify distinction between standard Cryo Archive and Vault Breaker PvE modes."""
    d_pve = VaultBreakerDirector(mode=GameMode.VAULT_BREAKER_PVE)
    assert d_pve.mode.value == "activity_exp.cryo.vault_breaker_server"
    
    d_std = VaultBreakerDirector(mode=GameMode.CRYO_STANDARD)
    assert d_std.mode.value == "activity_exp.cryo.standard_synced"
    print("PASS: Differentiated Vault Breaker PvE mode from Cryo standard mode")
