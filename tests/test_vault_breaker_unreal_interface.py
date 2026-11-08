"""Test suite for Vault Breaker Unreal Engine Recreation Interface."""
import pytest
from vault_breaker_unreal_interface import (
    VaultId, VaultState, AudioCue, VisualTrigger,
    VAULT_DEFINITIONS, KEY_PEDESTALS, DNA_BLUEPRINTS,
    VaultBreakerEncounterState, generate_unreal_cpp_header
)


def test_vault_definitions_integrity():
    """Verify that all 7 vaults are defined with correct verified properties."""
    assert len(VAULT_DEFINITIONS) == 7
    for v_id in VaultId:
        assert v_id in VAULT_DEFINITIONS
        defn = VAULT_DEFINITIONS[v_id]
        assert defn.batteries_required >= 1
        assert defn.open_incident.startswith("il_vault_")
        assert defn.open_incident.endswith("_opened")
        assert defn.battery_incident.startswith("il_vault_")
        assert defn.battery_incident.endswith("_battery_install")


def test_vault_1_progression():
    """Verify Vault 1 progression: 1 battery -> door opens."""
    sim = VaultBreakerEncounterState(VaultId.VAULT_1)
    assert sim.state == VaultState.LOCKED
    
    # Battery installed
    assert sim.install_battery() is True
    assert sim.state == VaultState.DOOR_OPEN
    assert "il_vault_1_opened" in sim.incident_log
    assert AudioCue.SFX_BATTERY_INSERT in sim.audio_log
    assert AudioCue.SFX_BLAST_DOOR_CYCLE in sim.audio_log
    assert VisualTrigger.BLAST_DOOR_OPEN_SEQUENCE in sim.visual_log
    
    # Interior puzzle
    assert sim.complete_interior_puzzle() is True
    assert sim.state == VaultState.PUZZLE_COMPLETED
    assert "il_vault_interior_puzzles_completed" in sim.incident_log


def test_vault_2_progression():
    """Verify Vault 2 progression: battery + canister -> door opens."""
    sim = VaultBreakerEncounterState(VaultId.VAULT_2)
    assert sim.state == VaultState.LOCKED
    
    # Battery only -> still locked
    assert sim.install_battery() is True
    assert sim.state == VaultState.LOCKED
    
    # Canister installed -> opens
    assert sim.install_canister() is True
    assert sim.state == VaultState.DOOR_OPEN
    assert "il_vault_2_canister_install" in sim.incident_log
    assert "il_vault_2_opened" in sim.incident_log


def test_vault_5_progression():
    """Verify Vault 5 progression: battery + canister + credentials -> door opens."""
    sim = VaultBreakerEncounterState(VaultId.VAULT_5)
    
    sim.install_battery()
    assert sim.state == VaultState.LOCKED
    
    sim.install_canister()
    assert sim.state == VaultState.LOCKED
    
    # Wrong credentials -> fail
    assert sim.scan_credentials("invalid_creds") is False
    assert AudioCue.SFX_CREDENTIALS_SCAN_FAIL in sim.audio_log
    assert sim.state == VaultState.LOCKED
    
    # Correct credentials -> opens
    assert sim.scan_credentials("quest.run_objectives.cryo.vault_objectives.vault_credentials2") is True
    assert sim.state == VaultState.DOOR_OPEN
    assert "il_vault_5_credentials_succeeded" in sim.incident_log
    assert "il_vault_5_opened" in sim.incident_log


def test_vault_7_progression():
    """Verify Vault 7 progression: battery + credentials + DNA blueprint -> door opens."""
    sim = VaultBreakerEncounterState(VaultId.VAULT_7)
    
    sim.install_battery()
    sim.scan_credentials("quest.run_objectives.cryo.vault_objectives.vault_credentials7")
    assert sim.state == VaultState.LOCKED
    
    # DNA blueprint validation
    assert sim.insert_dna_blueprint("dna_blueprint_agct") is True
    assert sim.state == VaultState.DOOR_OPEN
    assert "il_vault_7_opened" in sim.incident_log


def test_unreal_cpp_header_generation():
    """Verify clean Unreal Engine 5 C++ header generation."""
    header = generate_unreal_cpp_header()
    assert "UVaultBreakerSubsystem" in header
    assert "EVaultId" in header
    assert "FOnVaultIncidentTriggered" in header
    assert "FOnVaultAudioCue" in header
    assert "FOnVaultVisualTrigger" in header
    print("PASS: Unreal Engine 5 C++ interface header generated successfully")
