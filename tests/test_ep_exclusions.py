"""
ENS Threat Prevention Exploit Prevention exclusions.

- ep_console.xml: a copy of "My Default" where the console was used to
  add one exclusion of each type (Illegal API Use, File - Process - Registry
  with process/SIDs/hostname, file target, registry target and user/group
  names, Services, Network IPS, Linux File - Process) - the reference of the
  storage format. Only the signatures used by the exclusions are kept.
"""

import re
from pathlib import Path

import pytest

from trellix_epo import Policies, ESTPPolicyExploitPrevention, EPExclusion, EPExecutable

FIXTURES = Path(__file__).parent / 'fixtures'
GUID = re.compile(r'^[0-9a-f-]{36}$')
SECTIONS = ['bopExclItems', 'bopExclusions', 'bopExclusions10713', 'bopExclusions153']


@pytest.fixture
def policy():
    policy = ESTPPolicyExploitPrevention()
    policy.load_from_file(str(FIXTURES / 'ep_console.xml'))
    return policy


def snapshot(policy):
    settings_obj = policy.root.find('./EPOPolicySettings[@name="{}"]'.format(policy.main))
    return {section.get('name'): {setting.get('name'): setting.get('value')
                                  for setting in section.findall('Setting')}
            for section in settings_obj.findall('Section') if section.get('name') in SECTIONS}


def test_read_console_exclusions(policy):
    exclusions = policy.get_exclusions()
    assert [exclusion.type_name for exclusion in exclusions] == [
        'Illegal API Use - Buffer Overflow', 'File - Process - Registry',
        'File - Process - Registry', 'File - Process - Registry', 'Services', 'Network IPS',
        'Linux File - Process', 'File - Process - Registry']
    api, fpr, target, registry, service, nips, linux, names = exclusions
    assert api.name == 'Claude API Excl'
    assert api.processes == [EPExecutable(r'**\claudeapiproc.exe')]
    assert api.caller_module == EPExecutable(r'**\claudemodule.dll',
                                             'fedcba9876543210fedcba9876543210', '**',
                                             'Claude Caller Module')
    assert (api.api_name, api.signatures, api.notes) == ('ClaudeTestApi', ['2201'],
                                                         'Claude test notes API')
    assert fpr.processes == [EPExecutable(r'**\claudeproc.exe',
                                          '0123456789abcdef0123456789abcdef',
                                          'C=US, O=Claude Test Signer, CN=Claude Test Signer')]
    assert (fpr.user_sid, fpr.group_sid, fpr.hostname) == (
        'S-1-5-21-1111-2222-3333-1001', 'S-1-5-32-544', 'CLAUDE-HOST*')
    assert fpr.signatures == ['2600', '6127']
    assert (target.processes, target.target_file) == ([], r'C:\ClaudeTarget\*.dat')
    assert (registry.target_file, registry.target_registry) == (
        '', r'HKLM\SOFTWARE\ClaudeTest\Value1')
    assert (service.name, service.service_name) == ('', 'ClaudeTestSvc')
    assert nips.ip_addresses == '192.168.100.50, 10.0.0.1-10.0.0.9, 2001:db8::/48'
    assert nips.signatures == ['2231', '2230']
    assert (linux.name, linux.processes) == ('Claude Linux Excl',
                                             [EPExecutable('/opt/claude/bin/claudetool')])
    # The 2nd process was entered without signature check, but the processes
    # of an exclusion share one ID and the console copied the signer of the
    # 1st one to it when the policy was saved again (console behaviour).
    assert names.processes == [EPExecutable('claudeany.exe', signer='**'),
                               EPExecutable(r'C:\Claude\second.exe', signer='**')]
    assert (names.user_name, names.group_name) == (r'LAB\claudeuser', 'claudegroup')


def test_round_trip_is_lossless(policy):
    before = snapshot(policy)
    policy.set_exclusions(policy.get_exclusions())
    assert snapshot(policy) == before


def test_down_level_sections(policy):
    sections = snapshot(policy)
    # Illegal API Use only in the oldest sections, the others in bopExclusions153.
    assert sections['bopExclItems'] == {
        'bopExclusionProcess_1': r'**\claudeapiproc.exe||**\claudemodule.dll|ClaudeTestApi',
        'bopProcessExclCount': '1'}
    assert sections['bopExclusions']['ExclusionCount'] == '1'
    assert sections['bopExclusions153']['ExclusionCount'] == '7'
    assert sections['bopExclusions10713']['ExclusionCount'] == '8'


def test_console_checks():
    with pytest.raises(ValueError):
        EPExclusion.file_process_registry('x')
    with pytest.raises(ValueError):
        EPExclusion.file_process_registry('x', [EPExecutable('a.exe')], target_file='b')
    with pytest.raises(ValueError):
        EPExclusion.file_process_registry('x', target_file='a', target_registry='b')
    with pytest.raises(ValueError):
        EPExclusion.file_process_registry('x', user_sid='S-1-5-18', user_name='a')
    with pytest.raises(ValueError):
        EPExclusion.file_process_registry('x', group_name=r'LAB\group')
    with pytest.raises(ValueError):
        EPExclusion.illegal_api('x', [])
    with pytest.raises(ValueError):
        EPExclusion.service('')
    with pytest.raises(ValueError):
        EPExclusion.network_ips()
    with pytest.raises(ValueError):
        EPExecutable()


def test_add_and_remove(policy):
    exclusion = EPExclusion.file_process_registry(
        'Lib Proc', [EPExecutable(r'**\libproc.exe', signer=EPExecutable.ANY_SIGNATURE)],
        user_sid='S-1-5-18', hostname='LIBHOST*', signatures=['2600'], notes='lib')
    assert policy.add_exclusion(exclusion)
    exclusions = policy.get_exclusions()
    assert len(exclusions) == 9 and exclusions[-1] == exclusion
    assert GUID.match(exclusion.id)
    sections = snapshot(policy)
    assert sections['bopExclusions10713']['ExclusionCount'] == '9'
    assert sections['bopExclusions153']['ExclusionCount'] == '8'
    values = sections['bopExclusions10713']
    assert values['Exclusion#8_Executable#0_Parameter#6_Value'] == 'S-1-5-18'
    assert values['Exclusion#8_Executable#3_Type'] == 'UserSID'
    assert values['Exclusion#8_Executable#3_Name'] == 'S-1-5-18'
    with pytest.raises(ValueError):
        policy.add_exclusion(EPExclusion.network_ips(['99999']))
    assert policy.remove_exclusion(exclusion.id)
    assert len(policy.get_exclusions()) == 8
    assert not policy.remove_exclusion('unknown')


def test_new_sections_are_created(policy):
    settings_obj = policy.root.find('./EPOPolicySettings[@name="{}"]'.format(policy.main))
    for section in settings_obj.findall('Section'):
        if section.get('name') == 'bopExclusions10713':
            settings_obj.remove(section)
    exclusions = policy.get_exclusions()
    # Without the recent section the down-level ones are read (and merged).
    assert len(exclusions) == 8
    policy.set_exclusions(exclusions)
    names = [section.get('name') for section in settings_obj.findall('Section')]
    assert names == sorted(names)
    assert snapshot(policy)['bopExclusions10713']['ExclusionCount'] == '8'


def test_markdown(policy):
    text = policy.to_markdown()
    section = text[text.index('## 5. Exclusions'):]
    section = section[:section.index('\n## ')]
    assert '| 1 | Illegal API Use - Buffer Overflow | Claude API Excl | \\*\\*\\\\claudeapiproc.exe' \
        in section
    assert 'Group SID' in section and 'IP Addresses' in section
    assert '### 2. Claude FPR Excl' in section
    assert 'Signed by: C=US, O=Claude Test Signer, CN=Claude Test Signer' in section


def test_copy_gets_new_exclusion_ids(policy):
    # The console fails to open a policy whose exclusion IDs are used by
    # another policy: a copy made with Policies.new_policy() gets new ones.
    policies = Policies((FIXTURES / 'ep_console.xml').read_text(encoding='utf-8'))
    copy = ESTPPolicyExploitPrevention(policies.new_policy(
        'EAM_BufferOverflow_Policies', 'Copy', 'Claude - EP Exclusions Default'))
    old, new = policy.get_exclusions(), copy.get_exclusions()
    assert [exclusion.name for exclusion in new] == [exclusion.name for exclusion in old]
    old_ids = {exclusion.id for exclusion in old} | {exclusion.process_id for exclusion in old}
    assert not old_ids & ({exclusion.id for exclusion in new} |
                          {exclusion.process_id for exclusion in new})
    # The same exclusion keeps one ID in the current and down-level sections.
    sections = snapshot(copy)
    assert sections['bopExclusions']['Exclusion#0_ID'] == new[0].id
    assert sections['bopExclusions153']['Exclusion#0_ID'] == new[1].id
