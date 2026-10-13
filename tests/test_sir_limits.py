"""
System Information Reporter: values accepted by the console (lab SIR pages,
compared with the local 1.0.5 extension: the Set Registry functions are
identical, the Find File / Find Folder ones of the lab are newer).

The rules come from generalPolicy.js and setRegistryPolicy.js: no double
quote nor semicolon (charexist), registry hives, 1000 / 255 characters per
registry path / element, file searches starting with [SYSTEMDRIVE]\\,
[SystemRoot]\\, [PROGRAMFILES]\\, [COMMONPROGRAMFILES]\\ or {A}\\ to {Z}\\
(not ending with \\), folder searches with a drive only, 240 characters,
trailing blanks removed, no duplicate (case ignored), DWORD / binary / string
data, backup file names.

sir_limits.xml: "Claude - SIR Collect Test" and "Claude - SIR Registry
Test", copies written by the library at the limits and imported on the lab.
"""

from pathlib import Path

import pytest

from mcafee_epo_policies.sir import SIRPolicies
from mcafee_epo_policies.sir.collect import SIRPolicyCollectData
from mcafee_epo_policies.sir.registry import SIRPolicySetRegistry, SIRRegistryValue

FIXTURE = Path(__file__).parent / 'fixtures' / 'sir_limits.xml'


def load(cls, type_id, name):
    policies = SIRPolicies()
    policies.load_from_file(str(FIXTURE))
    return cls(policies.get_policy(type_id, name))


def collect():
    return load(SIRPolicyCollectData, 'SIR_____1000_COLLECT_DATA', 'Claude - SIR Collect Test')


def registry():
    return load(SIRPolicySetRegistry, 'SIR_____1000_SET_REGISTRY', 'Claude - SIR Registry Test')


def test_collect_limits():
    policy = collect()
    assert len(policy.get_environment_variable()) == 255
    assert [len(path) for path in policy.get_registry_queries()] == [1000, 24]
    assert policy.get_files()[1] == '{Z}\\tool.exe'       # trailing blanks removed
    assert policy.get_folders()[1] == '{D}\\Data\\'
    assert (policy.get_collection_interval(), policy.get_search_depth()) == (999, 9)
    for setter, value in [
            ('set_environment_variable', 'E' * 256),
            ('set_registry_queries', ['[HKLM]\\' + 'K' * 256]),
            ('set_registry_queries', ['[HKLM]\\A;B']),
            ('set_registry_queries', ['[HKLM]\\App', '[hklm]\\APP']),
            ('set_files', ['{C}\\a"b.exe']),
            ('set_files', ['{C}\\a.exe', '{c}\\A.EXE']),
            ('set_files', ['{C}\\' + 'f' * 237]),
            ('set_folders', ['[SYSTEMDRIVE]\\Data']),
            ('set_folders', ['{C}\\Data', '{C}\\data']),
            ('set_collection_interval', 1000), ('set_search_depth', 10)]:
        with pytest.raises(ValueError):
            getattr(policy, setter)(value)
    policy.set_folders(['{C}\\Data  '])
    assert policy.get_folders() == ['{C}\\Data']


def test_registry_limits():
    policy = registry()
    values = policy.get_values()
    assert len(values) == 5
    assert [(value.reg_type, value.data) for value in values[1:3]] == [
        ('REG_DWORD', '4294967295'), ('REG_BINARY', '0a10')]
    assert len(values[0].name) == 255 and len(values[0].data) == 400
    bad = [SIRRegistryValue.create('V', '[HKLM]\\App\\V', 'REG_DWORD', '4294967296'),
           SIRRegistryValue.create('V', '[HKLM]\\App\\V', 'REG_DWORD', '-1'),
           SIRRegistryValue.create('V', '[HKLM]\\App\\V', 'REG_BINARY', 'zz'),
           SIRRegistryValue.create('V', '[HKLM]\\App\\V', 'REG_SZ', 'a\nb'),
           SIRRegistryValue.create('V;1', '[HKLM]\\App\\V', 'REG_SZ', 'x'),
           SIRRegistryValue.create('V', '[HKLM]\\App\\V', 'REG_SZ', 'd' * 401),
           SIRRegistryValue.create('', '[HKLM]\\App\\', 'REG_DWORD', '1'),
           SIRRegistryValue.create('V', 'HKLM\\App\\V', 'REG_SZ', 'x'),
           SIRRegistryValue('V', '[HKLM]\\App\\V', 'REG_SZ', '', SIRRegistryValue.DELETE, 5)]
    for value in bad:
        with pytest.raises(ValueError):
            value.check()
    good = [SIRRegistryValue.create('V', '[HKLM]\\App\\V', 'REG_SZ', 'x')]
    for name in ['claude LIMITS_1.BAK', 'bad/name', 'x' * 21, ' ']:
        with pytest.raises(ValueError):
            policy.set_values(good, name)
    assert policy.set_values(good, ' Claude limits_2.bak ')
    assert policy.get_backup_file() == 'Claude limits_2.bak'
