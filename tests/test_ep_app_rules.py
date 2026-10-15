"""
ENS Threat Prevention Exploit Prevention Application Protection Rules.

- ep_console.xml: a copy of "My Default" where the console was used to add
  two user-defined rules ("Claude App Rule": enabled, Exclude, two
  executables with MD5/signer/notes; "Claude App Rule Disabled": disabled,
  Include, one executable with an MD5 only) - the reference of the storage
  format.
  Two Trellix-defined rules (".Net Framework Host", "Adobe Acrobat Reader")
  are kept too.
- ep_policy.xml: a policy with the Trellix-defined rules.
"""

import re
from pathlib import Path

import pytest

from trellix_epo import (ESTPPolicyExploitPrevention, EPAppRule, APExecutable)

FIXTURES = Path(__file__).parent / 'fixtures'
GUID = re.compile(r'^[0-9a-f-]{36}$')


def load(name):
    policy = ESTPPolicyExploitPrevention()
    policy.load_from_file(str(FIXTURES / name))
    return policy


def rule_values(policy, rule_id):
    for settings_obj in policy.root.findall('EPOPolicySettings'):
        section_obj = settings_obj.find('Section[@name="EXPAPRule"]')
        if section_obj is not None and \
                section_obj.find('Setting[@name="appProtectionId"]').get('value') == rule_id:
            return {setting.get('name'): setting.get('value')
                    for setting in section_obj.findall('Setting')}
    return None


def test_read_console_rules():
    policy = load('ep_console.xml')
    net, adobe, rule, disabled = policy.get_application_rules()
    assert (net.name, net.origin, net.id) == ('.Net Framework Host', EPAppRule.TRELLIX,
                                              'IPSAppHookRule_DOTNETFRAMEWORKHOST')
    assert (rule.name, rule.origin, rule.enabled, rule.inclusion) == (
        'Claude App Rule', EPAppRule.USER, True, 'exclude')
    assert rule.notes == 'Claude app rule notes'
    assert [(exe.name, exe.path, exe.md5, exe.signer, exe.notes) for exe in rule.executables] == [
        ('Claude Exe Two', r'C:\Claude\apptwo.exe', '', '**', ''),
        ('Claude Exe One', r'**\claudeapp.exe', 'abcdefabcdefabcdefabcdefabcdefab',
         'C=US, O=Claude App Signer, CN=Claude App Signer', 'Claude exe notes')]
    assert (disabled.enabled, disabled.inclusion) == (False, 'include')
    assert disabled.executables[0].md5 == '22222222222222222222222222222222'
    assert policy.get_application_rule('Claude App Rule').id == rule.id


def test_round_trip_is_lossless():
    for name in ['ep_console.xml', 'ep_policy.xml']:
        policy = load(name)
        for rule in policy.get_application_rules():
            before = rule_values(policy, rule.id)
            assert rule.to_values() == before


def test_add_rule():
    policy = load('ep_console.xml')
    rule = EPAppRule('Lib App', [APExecutable('Lib exe', path=r'**\lib.exe',
                                              signer=APExecutable.ANY_SIGNATURE)],
                     inclusion='exclude', notes='lib')
    assert policy.add_application_rule(rule)
    values = rule_values(policy, rule.id)
    assert GUID.match(rule.id)
    assert values['appProtectionUUID'] == rule.id
    assert values['appProtectionType'] == 'Custom'
    assert values['appProtectionInclusionStatus'] == '0'
    assert values['Executable#0_IncludeStatus'] == '0'
    assert values['Executable#0Parameter#2_Value'] == '**'
    assert values['appProtectionDateModified'].endswith(' GMT+0000 ')
    assert [known.name for known in policy.get_application_rules()] == [
        '.Net Framework Host', 'Adobe Acrobat Reader', 'Claude App Rule',
        'Claude App Rule Disabled', 'Lib App']
    # The dict based API sees it too.
    assert policy.application_rule_contains_name('Lib App')
    # The settings are listed before the EPOPolicyObject, as in exports.
    assert policy.root[-1].tag == 'EPOPolicyObject'


def test_add_rule_checks():
    policy = load('ep_console.xml')
    with pytest.raises(ValueError):
        policy.add_application_rule(EPAppRule('No executable'))
    with pytest.raises(ValueError):
        policy.add_application_rule(EPAppRule('claude app rule',
                                              [APExecutable('x', path='x.exe')]))
    with pytest.raises(ValueError):
        EPAppRule('x', inclusion='maybe')


def test_update_and_remove_user_rule():
    policy = load('ep_console.xml')
    rule = policy.get_application_rule('Claude App Rule Disabled')
    rule.name = 'Renamed'
    rule.enabled = True
    rule.inclusion = 'exclude'
    assert policy.update_application_rule(rule)
    values = rule_values(policy, rule.id)
    assert (values['appProtectionName'], values['appProtectionStatus'],
            values['Executable#0_IncludeStatus']) == ('Renamed', '1', '0')
    assert policy.remove_application_rule(rule.id)
    assert [known.name for known in policy.get_application_rules()
            if known.origin == EPAppRule.USER] == ['Claude App Rule']
    assert not policy.application_rule_contains_name('Renamed')
    assert not policy.remove_application_rule(rule.id)


def test_trellix_defined_rule():
    policy = load('ep_policy.xml')
    rule = policy.get_application_rules()[0]
    assert rule.origin == EPAppRule.TRELLIX
    rule.notes = 'changed'
    rule.enabled = False
    rule.add_executable(APExecutable('extra', path=r'**\extra.exe'))
    assert policy.update_application_rule(rule)
    values = rule_values(policy, rule.id)
    assert (values['appProtectionType'], values['appProtectionNotes'],
            values['appProtectionStatus']) == ('Canned', 'changed', '0')
    rule.name = 'Other name'
    with pytest.raises(ValueError):
        policy.update_application_rule(rule)
    with pytest.raises(ValueError):
        policy.remove_application_rule(rule.id)


def test_markdown():
    text = load('ep_console.xml').to_markdown()
    assert '| 3 | Claude App Rule | Enabled | Exclude | C:\\\\Claude\\\\apptwo.exe;' \
        '\\*\\*\\\\claudeapp.exe; |' in text
    assert '| 4 | Claude App Rule Disabled | Disabled | Include | ; |' in text
