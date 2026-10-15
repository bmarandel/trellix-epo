"""
System Information Reporter (sir): Collect Data and Set Registry policies.

sir_policies.xml is an export of the lab ePO 5.10 (productId SIR_____1000)
with "My Default", "Demo (All)" (all items collected, one registry query,
one file), "Demo (Run TestKey)" (one value created, three backups) and two
test copies changed in the console:

- "Claude - SIR Collect Test": saved twice; last save: Environment
  Variables, Network cards, Services, Software, NullSession, Processes
  collected (CollectionFlags 1638; the first save, USB/Network cards/MSI/
  Software/IE/Processes, gave 1365), variable CLAUDEVAR, 2 registry
  queries, 12 hours, start 2026-10-04 3:15 PM, 2 files, 1 folder, depth 3,
  "only send properties when the policy changes" and debug logging off.
- "Claude - SIR Registry Test": backup file ClaudeBackup, one REG_DWORD
  value created (overwrite existing).
"""

import datetime
from pathlib import Path

import pytest

from trellix_epo import (SIRPolicies, SIRPolicyCollectData, SIRPolicySetRegistry,
                                 SIRRegistryValue)

FIXTURE = Path(__file__).parent / 'fixtures' / 'sir_policies.xml'
COLLECT, REGISTRY = SIRPolicies.COLLECT_DATA, SIRPolicies.SET_REGISTRY


def load_policies():
    policies = SIRPolicies()
    policies.load_from_file(str(FIXTURE))
    return policies


def load(cls, name='My Default'):
    feature = COLLECT if cls is SIRPolicyCollectData else REGISTRY
    return cls(load_policies().get_policy(feature, name))


def test_policies():
    """
    Both categories have the typeid "General": SIRPolicies uses the featureid.
    """
    policies = load_policies()
    assert [(item['typeid'], item['name']) for item in policies.list()] == [
        (COLLECT, 'Claude - SIR Collect Test'), (COLLECT, 'Demo (All)'), (COLLECT, 'My Default'),
        (REGISTRY, 'Claude - SIR Registry Test'), (REGISTRY, 'Demo (Run TestKey)'),
        (REGISTRY, 'My Default')]
    policy = policies.get_policy(COLLECT, 'My Default')
    assert len(policy.findall('EPOPolicyObject')) == 1
    with pytest.raises(ValueError):
        SIRPolicySetRegistry(policy)
    copy = SIRPolicyCollectData(policies.new_policy(COLLECT, 'Copy', 'Demo (All)'))
    assert copy.get_name() == 'Copy' and copy.files == ['[SystemRoot]\\psexec.exe']


def test_collect_read():
    default = load(SIRPolicyCollectData)
    assert [default.get_collect(key) for key, _ in SIRPolicyCollectData.ITEMS] == ['0'] * 12
    assert (default.collection_interval, default.start_datetime, default.search_depth) == (
        None, None, None)
    demo = load(SIRPolicyCollectData, 'Demo (All)')
    assert [demo.get_collect(key) for key, _ in SIRPolicyCollectData.ITEMS] == ['1'] * 12
    assert demo.environment_variable == 'DEFLOGDIR'

    test = load(SIRPolicyCollectData, 'Claude - SIR Collect Test')
    assert [key for key, _ in SIRPolicyCollectData.ITEMS if test.get_collect(key) == '1'] == [
        'environment', 'network_cards', 'services', 'software', 'null_sessions', 'processes']
    assert test.registry_queries == ['[HKLM]\\SOFTWARE\\Claude\\Value1',
                                     '[HKCU]\\Software\\Claude\\Value2']
    assert (test.collection_interval, test.on_policy_change, test.debug_logging) == (12, '0', '0')
    assert test.start_datetime == datetime.datetime(2026, 10, 4, 15, 15)
    assert test.files == ['[SystemRoot]\\claude1.exe', '[PROGRAMFILES]\\Claude\\claude2.dll']
    assert (test.folders, test.search_depth) == (['{C}\\ClaudeFolder'], 3)


def test_collect_write():
    policy = load(SIRPolicyCollectData)
    # The first console save of the test policy: CollectionFlags 1365.
    for key in ['usb', 'network_cards', 'msi', 'software', 'ie', 'processes']:
        policy.set_collect(key, '1')
    assert policy.get_setting_value('General', 'CollectionFlags') == '1365'
    version = policy.get_setting_value('Custom', 'PolicyChangeVersionGetProps')
    assert len(version) == 36
    policy.set_collect('usb', '0')
    assert policy.get_setting_value('General', 'CollectionFlags') == '1364'
    assert policy.get_setting_value('Custom', 'PolicyChangeVersionGetProps') != version
    policy.set_collect_all('1')
    assert policy.get_setting_value('General', 'CollectionFlags') == '4095'
    policy.environment_variable = 'MYVAR'
    policy.registry_queries = ['[HKLM]\\SOFTWARE\\Example\\Version']
    policy.collection_interval = 24
    policy.on_policy_change = '1'
    policy.start_datetime = datetime.datetime(2026, 11, 1, 6, 30, 45)
    policy.debug_logging = '1'
    policy.files = ['{D}\\Data\\app.exe']
    policy.folders = ['{E}\\Data']
    policy.search_depth = 2
    get = policy.get_setting_value
    assert (get('SpecialEnvironment', 'CustomEnvVar'), get('List', 'Branch0'),
            get('List', 'dwItemCount'), get('Custom', 'dwHourlyInterval'),
            get('Custom', 'dwOnPolicyChangeGetProps'), get('Custom', 'szPolicyStartDateTime'),
            get('Custom', 'dwDebugLog'), get('FindFile', 'SearchPattern0'),
            get('FindFile', 'FolderPattern0'), get('FindFile', 'FolderCount'),
            get('FindFile', 'dwSearchDepth')) == (
        'MYVAR', '[HKLM]\\SOFTWARE\\Example\\Version', '1', '24', '1', '2026-11-01 06:30:00',
        '1', '{D}\\Data\\app.exe', '{E}\\Data', '1', '2')
    # Values refused by the console ("Not a valid format of ...").
    for bad in [lambda: policy.set_files(['C:\\Tools\\app.exe']),
                lambda: policy.set_files(['[PROGRAMFILES]\\Tools\\']),
                lambda: policy.set_files(['[ProgramFiles]\\Tools\\app.exe']),
                lambda: policy.set_folders(['C:\\Data']),
                lambda: policy.set_folders(['[SYSTEMDRIVE]\\Data']),
                lambda: policy.set_registry_queries(['HKLM\\SOFTWARE\\Example']),
                lambda: policy.set_search_depth(10),
                lambda: policy.set_collect('usb', 'yes')]:
        with pytest.raises(ValueError):
            bad()
    with pytest.raises(ValueError):
        policy.set_collect('no_such_item', '1')


def test_registry_read():
    test = load(SIRPolicySetRegistry, 'Claude - SIR Registry Test')
    assert test.get_values() == [SIRRegistryValue.create(
        'ClaudeValue', '[HKLM]\\SOFTWARE\\Claude\\ClaudeValue', 'REG_DWORD', '1', overwrite=True)]
    assert test.get_backup_file() == 'ClaudeBackup'
    assert test.get_backups() == [{'name': 'ClaudeBackup', 'keys': '[HKLM]\\SOFTWARE\\Claude\\, ',
                                   'date': '04 oct. 2026, 07:14 PM'}]
    demo = load(SIRPolicySetRegistry, 'Demo (Run TestKey)')
    assert [backup['name'] for backup in demo.get_backups()] == ['DemoBackup', 'DemoBackup2',
                                                                 'Demo.txt']
    assert demo.restore_file == ''
    assert load(SIRPolicySetRegistry).get_values() == []


def test_registry_write():
    """
    The console save of the test policy, made by the library.
    """
    policy = load(SIRPolicySetRegistry)
    console = load(SIRPolicySetRegistry, 'Claude - SIR Registry Test')
    policy.set_values(console.get_values(), 'ClaudeBackup',
                      datetime.datetime(2026, 10, 4, 19, 14))
    for setting in ['RegKey_1', 'RegName_1', 'RegType_1', 'RegValue_1', 'action_name_1',
                    'flag_1', 'dwSetRegistryCount', 'RegistryBackupFile',
                    'RegistryBackupFileList', 'szBackupKeyList']:
        assert policy.get_setting_value('SetRegistry', setting) == \
            console.get_setting_value('SetRegistry', setting), setting
    assert policy.get_setting_value('SetRegistry', 'RegistryBackupFileDateList') == \
        ';04 Oct 2026, 07:14 PM'
    assert len(policy.get_setting_value('SetRegistry', 'PolicyChangeVersion')) == 36
    with pytest.raises(ValueError):     # backup file names are not reused
        policy.set_values([], 'ClaudeBackup')
    policy.set_values([SIRRegistryValue.delete('Old', '[HKCU]\\Software\\Old\\Value'),
                       SIRRegistryValue.delete('OldKey', '[HKCU]\\Software\\OldKey\\',
                                               SIRRegistryValue.DELETE_KEY)], 'Cleanup')
    assert [(v.action, v.flag) for v in policy.get_values()] == [('1', 6), ('1', 7)]
    assert [backup['name'] for backup in policy.get_backups()] == ['ClaudeBackup', 'Cleanup']
    assert policy.get_backups()[1]['keys'] == '[HKCU]\\Software\\Old\\, [HKCU]\\Software\\OldKey\\, '
    policy.restore_file = 'ClaudeBackup'
    assert policy.restore_file == 'ClaudeBackup'
    for bad in [lambda: policy.set_restore_file('Unknown'),
                lambda: policy.set_values([], ''),
                lambda: policy.set_values([], 'x' * 21),
                lambda: policy.set_values([SIRRegistryValue('a', 'SOFTWARE\\a')], 'New1'),
                lambda: policy.set_values([SIRRegistryValue('a', '[HKLM]\\a', 'REG_QWORD')],
                                          'New2')]:
        with pytest.raises(ValueError):
            bad()


def test_markdown():
    text = load(SIRPolicyCollectData, 'Claude - SIR Collect Test').to_markdown()
    assert 'System Information Reporter - Collect Data - General policy' in text
    assert '| Environment Variables (in SYSTEM context) | Yes |' in text
    assert '| USB devices | No |' in text
    assert '| 2 | \\[HKCU\\]\\\\Software\\\\Claude\\\\Value2 |' in text
    assert '| Time on endpoint when the policy is in effect | 03:15 PM |' in text
    assert '| Search Depth | 3 |' in text
    text = load(SIRPolicySetRegistry, 'Demo (Run TestKey)').to_markdown()
    assert '**Warning:** Using System Information Reporter' in text
    assert '| TestKey | \\[HKLM\\]' in text
    assert '| REG\\_SZ | demo.exe | Create: Overwrite existing |' in text
    assert '| Select the file to restore | Do not restore any file |' in text
    assert '| 3 | Demo.txt |' in text
