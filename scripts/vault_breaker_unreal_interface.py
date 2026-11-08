"""Vault Breaker Unreal Engine Recreation Interface & Audio/Visual Mapping.
Implements the verified 7-Vault incident state machine, interactive pedestals,
and audio/visual trigger mappings derived from 80B37FE9.bin and 80B37C7E.bin.
"""
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Callable


class VaultId(Enum):
    VAULT_1 = 1
    VAULT_2 = 2
    VAULT_3 = 3
    VAULT_4 = 4
    VAULT_5 = 5
    VAULT_6 = 6
    VAULT_7 = 7


class VaultState(Enum):
    LOCKED = 0
    BATTERY_INSERTED = 1
    CANISTER_INSERTED = 2
    CREDENTIALS_VERIFIED = 3
    DOOR_OPENING = 4
    DOOR_OPEN = 5
    PUZZLE_COMPLETED = 6


class AudioCue(Enum):
    SFX_BATTERY_INSERT = "Play_SFX_Vault_Battery_Insert"
    SFX_CANISTER_INSERT = "Play_SFX_Vault_Canister_Insert"
    SFX_CREDENTIALS_SCAN_SUCCESS = "Play_SFX_Vault_Credentials_Scan_Success"
    SFX_CREDENTIALS_SCAN_FAIL = "Play_SFX_Vault_Credentials_Scan_Fail"
    SFX_BLAST_DOOR_UNLOCK = "Play_SFX_Vault_BlastDoor_Unlock"
    SFX_BLAST_DOOR_CYCLE = "Play_SFX_Vault_BlastDoor_Opening"
    SFX_PUZZLE_SOLVE = "Play_SFX_Vault_Interior_Puzzle_Solve"
    SFX_ALARM_LOCKDOWN = "Play_SFX_Vault_Alarm_Lockdown"


class VisualTrigger(Enum):
    PEDESTAL_GLYPH_ACTIVE = "VT_Pedestal_Hologram_Activate"
    BLAST_DOOR_OPEN_SEQUENCE = "VT_BlastDoor_Cycle_Start"
    TERMINAL_CREDENTIALS_PROMPT = "VT_Terminal_Display_ScanPrompt"
    CENTRIFUGE_UI_ACTIVATE = "VT_Centrifuge_UI_Activate"
    SECRET_LAB_WAYPOINT_REVEAL = "VT_SecretLab_Waypoint_Reveal"


@dataclass
class VaultDefinition:
    vault_id: VaultId
    name: str
    script_slot: str
    batteries_required: int
    canister_required: bool
    credentials_key: Optional[str]
    dna_blueprint_required: bool
    open_incident: str
    battery_incident: str
    canister_incident: Optional[str] = None
    credentials_incident: Optional[str] = None


# Authentic 7-Vault Configurations verified from 80B37C7E.bin & 80B37FE9.bin
VAULT_DEFINITIONS: Dict[VaultId, VaultDefinition] = {
    VaultId.VAULT_1: VaultDefinition(
        vault_id=VaultId.VAULT_1,
        name="Vault 1 (Battery Core)",
        script_slot="sc_vault_1_objectives",
        batteries_required=1,
        canister_required=False,
        credentials_key=None,
        dna_blueprint_required=False,
        open_incident="il_vault_1_opened",
        battery_incident="il_vault_1_battery_install"
    ),
    VaultId.VAULT_2: VaultDefinition(
        vault_id=VaultId.VAULT_2,
        name="Vault 2 (Cryo Canister Storage)",
        script_slot="sc_vault_2_objectives",
        batteries_required=1,
        canister_required=True,
        credentials_key=None,
        dna_blueprint_required=False,
        open_incident="il_vault_2_opened",
        battery_incident="il_vault_2_battery_install",
        canister_incident="il_vault_2_canister_install"
    ),
    VaultId.VAULT_3: VaultDefinition(
        vault_id=VaultId.VAULT_3,
        name="Vault 3 (Wing Archive)",
        script_slot="sc_vault_3_objectives",
        batteries_required=1,
        canister_required=False,
        credentials_key="quest.run_objectives.cryo.vault_objectives.vault_credentials0",
        dna_blueprint_required=False,
        open_incident="il_vault_3_opened",
        battery_incident="il_vault_3_battery_install",
        credentials_incident="il_vault_3_credentials_succeeded"
    ),
    VaultId.VAULT_4: VaultDefinition(
        vault_id=VaultId.VAULT_4,
        name="Vault 4 (Colonist Archive)",
        script_slot="sc_vault_4_objectives",
        batteries_required=1,
        canister_required=False,
        credentials_key="quest.run_objectives.cryo.vault_objectives.vault_credentials1",
        dna_blueprint_required=False,
        open_incident="il_vault_4_opened",
        battery_incident="il_vault_4_battery_install",
        credentials_incident="il_vault_4_credentials_succeeded"
    ),
    VaultId.VAULT_5: VaultDefinition(
        vault_id=VaultId.VAULT_5,
        name="Vault 5 (Tranquility Bio-Lab)",
        script_slot="sc_vault_5_objectives",
        batteries_required=1,
        canister_required=True,
        credentials_key="quest.run_objectives.cryo.vault_objectives.vault_credentials2",
        dna_blueprint_required=False,
        open_incident="il_vault_5_opened",
        battery_incident="il_vault_5_battery_install",
        canister_incident="il_vault_5_canister_install",
        credentials_incident="il_vault_5_credentials_succeeded"
    ),
    VaultId.VAULT_6: VaultDefinition(
        vault_id=VaultId.VAULT_6,
        name="Vault 6 (Centrifuge Facility)",
        script_slot="sc_vault_6_objectives",
        batteries_required=1,
        canister_required=True,
        credentials_key=None,
        dna_blueprint_required=False,
        open_incident="il_vault_6_opened",
        battery_incident="il_vault_6_battery_install",
        canister_incident="il_vault_6_canister_install"
    ),
    VaultId.VAULT_7: VaultDefinition(
        vault_id=VaultId.VAULT_7,
        name="Vault 7 (Command DNA Sanctum)",
        script_slot="sc_vault_7_objectives",
        batteries_required=1,
        canister_required=False,
        credentials_key="quest.run_objectives.cryo.vault_objectives.vault_credentials7",
        dna_blueprint_required=True,
        open_incident="il_vault_7_opened",
        battery_incident="il_vault_7_battery_install",
        credentials_incident="il_vault_7_credentials_succeeded"
    ),
}

# Verified 4 Interactive Pedestal stations from 80B37FEC.bin
KEY_PEDESTALS = [
    "g_key_pedestals_1",
    "g_key_pedestals_2",
    "g_key_pedestals_3",
    "g_key_pedestals_4",
]

# Verified DNA Blueprints for Vault 7 Puzzle from 80B37C7E.bin
DNA_BLUEPRINTS = [
    "dna_blueprint_agct",
    "dna_blueprint_agtc",
    "dna_blueprint_ctag",
    "dna_blueprint_gact",
    "dna_blueprint_tcag",
    "dna_blueprint_tcga",
]


class VaultBreakerEncounterState:
    """Authentic activity state machine managing Cryo Archive vaults."""

    def __init__(self, assigned_vault: VaultId = VaultId.VAULT_1):
        self.assigned_vault: VaultId = assigned_vault
        self.defn: VaultDefinition = VAULT_DEFINITIONS[assigned_vault]
        self.state: VaultState = VaultState.LOCKED
        
        self.batteries_installed: int = 0
        self.canister_installed: bool = False
        self.credentials_verified: bool = False
        self.blueprint_verified: bool = False
        
        self.active_pedestal: str = KEY_PEDESTALS[0]
        self.assigned_dna_blueprint: Optional[str] = DNA_BLUEPRINTS[0] if self.defn.dna_blueprint_required else None
        
        self.audio_log: List[AudioCue] = []
        self.visual_log: List[VisualTrigger] = []
        self.incident_log: List[str] = []

    def install_battery(self) -> bool:
        """Process battery insertion."""
        if self.batteries_installed < self.defn.batteries_required:
            self.batteries_installed += 1
            self.incident_log.append(self.defn.battery_incident)
            self.audio_log.append(AudioCue.SFX_BATTERY_INSERT)
            self._check_door_transition()
            return True
        return False

    def install_canister(self) -> bool:
        """Process canister insertion (Vaults 2, 5, 6)."""
        if self.defn.canister_required and not self.canister_installed:
            self.canister_installed = True
            if self.defn.canister_incident:
                self.incident_log.append(self.defn.canister_incident)
            self.audio_log.append(AudioCue.SFX_CANISTER_INSERT)
            self._check_door_transition()
            return True
        return False

    def scan_credentials(self, credentials_key: str) -> bool:
        """Process credentials scan (Vaults 3, 4, 5, 7)."""
        if self.defn.credentials_key:
            if credentials_key == self.defn.credentials_key:
                self.credentials_verified = True
                if self.defn.credentials_incident:
                    self.incident_log.append(self.defn.credentials_incident)
                self.audio_log.append(AudioCue.SFX_CREDENTIALS_SCAN_SUCCESS)
                self._check_door_transition()
                return True
            else:
                self.audio_log.append(AudioCue.SFX_CREDENTIALS_SCAN_FAIL)
                return False
        return False

    def insert_dna_blueprint(self, blueprint_key: str) -> bool:
        """Process DNA blueprint validation for Vault 7."""
        if self.defn.dna_blueprint_required:
            if blueprint_key == self.assigned_dna_blueprint:
                self.blueprint_verified = True
                self.audio_log.append(AudioCue.SFX_PUZZLE_SOLVE)
                self._check_door_transition()
                return True
        return False

    def complete_interior_puzzle(self) -> bool:
        """Complete vault interior puzzle."""
        if self.state == VaultState.DOOR_OPEN:
            self.state = VaultState.PUZZLE_COMPLETED
            self.incident_log.append("il_vault_interior_puzzles_completed")
            self.audio_log.append(AudioCue.SFX_PUZZLE_SOLVE)
            return True
        return False

    def _check_door_transition(self):
        """Evaluate whether all required locks for the assigned vault are cleared."""
        if self.batteries_installed < self.defn.batteries_required:
            return
        if self.defn.canister_required and not self.canister_installed:
            return
        if self.defn.credentials_key and not self.credentials_verified:
            return
        if self.defn.dna_blueprint_required and not self.blueprint_verified:
            return

        # All locks cleared: trigger blast door opening sequence
        self.state = VaultState.DOOR_OPENING
        self.incident_log.append(self.defn.open_incident)
        self.audio_log.append(AudioCue.SFX_BLAST_DOOR_UNLOCK)
        self.audio_log.append(AudioCue.SFX_BLAST_DOOR_CYCLE)
        self.visual_log.append(VisualTrigger.BLAST_DOOR_OPEN_SEQUENCE)
        self.state = VaultState.DOOR_OPEN


def generate_unreal_cpp_header() -> str:
    """Generate clean Unreal Engine 5 C++ interface header."""
    return """// Copyright (c) 2026 Marathon Preservation Project. Standalone Recreation Interface.
#pragma once

#include "CoreMinimal.h"
#include "Subsystems/WorldSubsystem.h"
#include "VaultBreakerObjectiveTypes.generated.h"

UENUM(BlueprintType)
enum class EVaultId : uint8
{
    Vault1 UMETA(DisplayName = "Vault 1 - Battery Core"),
    Vault2 UMETA(DisplayName = "Vault 2 - Cryo Canister Storage"),
    Vault3 UMETA(DisplayName = "Vault 3 - Wing Archive"),
    Vault4 UMETA(DisplayName = "Vault 4 - Colonist Archive"),
    Vault5 UMETA(DisplayName = "Vault 5 - Tranquility Bio-Lab"),
    Vault6 UMETA(DisplayName = "Vault 6 - Centrifuge Facility"),
    Vault7 UMETA(DisplayName = "Vault 7 - Command DNA Sanctum")
};

UENUM(BlueprintType)
enum class EVaultState : uint8
{
    Locked,
    BatteryInserted,
    CanisterInserted,
    CredentialsVerified,
    DoorOpening,
    DoorOpen,
    PuzzleCompleted
};

DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FOnVaultIncidentTriggered, EVaultId, VaultId, FName, IncidentName);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FOnVaultAudioCue, EVaultId, VaultId, FName, AudioEvent);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FOnVaultVisualTrigger, EVaultId, VaultId, FName, TriggerName);

UCLASS(BlueprintType, Blueprintable)
class UVaultBreakerSubsystem : public UWorldSubsystem
{
    GENERATED_BODY()

public:
    UFUNCTION(BlueprintCallable, Category = "Vault Breaker")
    virtual void InitializeVaultEncounter(EVaultId AssignedVault) = 0;

    UFUNCTION(BlueprintCallable, Category = "Vault Breaker")
    virtual bool InstallBattery(EVaultId VaultId) = 0;

    UFUNCTION(BlueprintCallable, Category = "Vault Breaker")
    virtual bool InstallCanister(EVaultId VaultId) = 0;

    UFUNCTION(BlueprintCallable, Category = "Vault Breaker")
    virtual bool ScanCredentials(EVaultId VaultId, FName CredentialsId) = 0;

    UFUNCTION(BlueprintCallable, Category = "Vault Breaker")
    virtual bool SolveInteriorPuzzle(EVaultId VaultId) = 0;

    UPROPERTY(BlueprintAssignable, Category = "Vault Breaker|Events")
    FOnVaultIncidentTriggered OnIncidentTriggered;

    UPROPERTY(BlueprintAssignable, Category = "Vault Breaker|Events")
    FOnVaultAudioCue OnAudioCue;

    UPROPERTY(BlueprintAssignable, Category = "Vault Breaker|Events")
    FOnVaultVisualTrigger OnVisualTrigger;
};
"""
