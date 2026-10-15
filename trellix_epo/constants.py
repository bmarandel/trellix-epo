# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines CONSTANTES to use with trellix_epo Class
"""

class State():
    """
    State constants can be used with all policies to change the state of an option
    """
    VISIBLE = '1'
    HIDDEN = '0'
    ENABLED = '1'
    DISABLED = '0'

class Priority():
    """
    Priority constants can be used with McAfee Agent, General policy
        '0' = INFORMATIONAL
        '1' = WARNING
        '2' = MINOR
        '3' = MAJOR
        '4' = CRITICAL
    """
    INFORMATIONAL, WARNING, MINOR, MAJOR, CRITICAL = ['{}'.format(r) for r in range(5)]

class Gti():
    """
    GTI constants can be used with Endpoint Security, Threat Prevention OAS policy
        '0' = DISABLED
        '1' = VERY_LOW
        '2' = LOW
        '3' = MEDIUM
        '4' = HIGH
        '5' = VERY_HIGH
    """
    DISABLED, VERY_LOW, LOW, MEDIUM, HIGH, VERY_HIGH = ['{}'.format(r) for r in range(6)]

class OASState():
    """
    OASState constants can be used with Endpoint Security, Threat Prevention OAS policy
    (on_access_scan property), radio buttons of the "On-Access Scan" group:
        '1' = ENABLED                  Enable
        '0' = DISABLED                 Disable
        '2' = DISABLED_UNREGISTER_WSC  Disable and unregister with Windows Security Center

    '2' is not an ePO value: the console stores it as bOASEnabled = 0 plus
    bUnregisterWithWSC = 1 (checked against ePO 5.10 exports).
    """
    DISABLED, ENABLED, DISABLED_UNREGISTER_WSC = ['{}'.format(r) for r in range(3)]

class Severity():
    """
    Severity constants can be used with Endpoint Security, Threat Prevention Exploit Prevention policy
        '0' = DISABLED
        '1' = INFORMATIONAL
        '2' = LOW
        '3' = MEDIUM
        '4' = HIGH
    """
    DISABLED, INFORMATIONAL, LOW, MEDIUM, HIGH = ['{}'.format(r) for r in range(5)]

class Language():
    """
    Language constants can be used with McAfee Agent, Troubleshooting policy
    (agent_language property) instead of remembering the raw Windows LCID hex
    code shown in the "Select language used by agent" dropdown.

    Only UI_DEFAULT ('0000') and ENGLISH ('0409') have been confirmed against
    real ePO exports so far. The rest follow the standard Windows LCID table
    for the language names listed in that dropdown but have not been
    individually confirmed - please report any mismatch you notice.
    """
    UI_DEFAULT = '0000'
    CHINESE_SIMPLIFIED = '0804'
    CHINESE_TRADITIONAL = '0404'
    CZECH = '0405'
    DANISH = '0406'
    DUTCH = '0413'
    ENGLISH = '0409'
    FINNISH = '040B'
    FRENCH = '040C'
    GERMAN = '0407'
    ITALIAN = '0410'
    JAPANESE = '0411'
    KOREAN = '0412'
    NORWEGIAN = '0414'
    POLISH = '0415'
    PORTUGUESE = '0816'
    PORTUGUESE_BRAZILIAN = '0416'
    RUSSIAN = '0419'
    SPANISH = '040A'
    SWEDISH = '041D'
    TURKISH = '041F'

class SCException():
    """
    SCException constants can be used with Solidcore, General > Exception Rules
    policy (SCGENPolicyExceptionRules) to select the type of an exclusion, as
    shown in the "Add exclusion rules" dialog of the ePO console.

    Exclusions applying to a process/file name (stored as an 'attr' rule):
        CASP                        Disable buffer overflow protection (CASP) for a process
        NX                          Disable buffer overflow protection (NX) for a process on
                                    64-bit Windows
        VASR_FORCED_RELOCATION      Disable ROP protection for a process using Forced
                                    Relocation (VASR) (optional Library Name)
        VASR_DLL_RELOCATION         Disable ROP protection for a DLL using DLL Relocation (VASR)
        VASR_STACK_RANDOMIZATION    Disable ROP protection for a process using Stack
                                    Randomization (VASR)
        ALLOW_UNINSTALLATIONS       Allow uninstallations (with a Parent Process Name)
        PROCESS_CONTEXT             Exclude file from write-protection rules and allow script
                                    execution (Windows and Unix; optional Parent Process
                                    Name on Windows)
        PROCESS_CONTEXT_REGISTRY    Exclude file from registry operations
    Exclusions applying to a path, a volume or a registry path (stored as a 'skiplist' rule):
        IGNORE_FILE_OPERATIONS      Ignore path for file operations
        EXCLUDE_FILE_OPERATIONS     Exclude path from file operations
        EXCLUDE_WRITE_PROTECTION    Exclude path from write-protection rules
        EXCLUDE_ALLOW_LIST          Exclude local path and all its files and sub-directories
                                    from the allow list (Windows and Unix)
        EXCLUDE_VOLUME              Exclude volume from Application Control protection
        SKIP_REGISTRY               Do not enforce deny write operation for this registry path
        SKIP_CHANGE_TRACKING        Do not track changes for this path
    Only the two exclusions marked "(Windows and Unix)" are offered for Unix.
    """
    CASP = 'casp_bypass'
    NX = 'dep_bypass'
    VASR_FORCED_RELOCATION = 'vasr_force_reloc_bypass'
    VASR_DLL_RELOCATION = 'vasr_reloc_bypass'
    VASR_STACK_RANDOMIZATION = 'vasr_rand_bypass'
    ALLOW_UNINSTALLATIONS = 'uninstall_bypass'
    PROCESS_CONTEXT = 'process_ctx_bypass'
    PROCESS_CONTEXT_REGISTRY = 'process_ctx_reg_bypass'
    IGNORE_FILE_OPERATIONS = 'skipFileOperation'
    EXCLUDE_FILE_OPERATIONS = 'skipFileOperation_f'
    EXCLUDE_WRITE_PROTECTION = 'skipDenyWrite'
    EXCLUDE_ALLOW_LIST = 'skipSolidification'
    EXCLUDE_VOLUME = 'skipVolume'
    SKIP_REGISTRY = 'skipRegistry'
    SKIP_CHANGE_TRACKING = 'skipChangeTracking'

class SCReputation():
    """
    SCReputation constants can be used with Solidcore, Application Control Options
    policy (SCAWLPolicyOptions) for the reputation levels of the Reputation tab:
        '99' = KNOWN_TRUSTED            This is a trusted file.
        '85' = MOST_LIKELY_TRUSTED      Almost certainly a trusted file.
        '70' = MIGHT_BE_TRUSTED         Appears to be a benign file.
        '50' = UNKNOWN                  Cannot determine at this time.
        '30' = MIGHT_BE_MALICIOUS       Appears to be a suspicious file.
        '15' = MOST_LIKELY_MALICIOUS    Almost certainly a malicious file.
        '1'  = KNOWN_MALICIOUS          This is a malicious file.
    """
    KNOWN_TRUSTED = '99'
    MOST_LIKELY_TRUSTED = '85'
    MIGHT_BE_TRUSTED = '70'
    UNKNOWN = '50'
    MIGHT_BE_MALICIOUS = '30'
    MOST_LIKELY_MALICIOUS = '15'
    KNOWN_MALICIOUS = '1'
