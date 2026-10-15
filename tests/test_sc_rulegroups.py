"""
Tests for SCRuleGroups and the SCAWLRuleGroup / SCCCRuleGroup / SCFIMRuleGroup
classes (Solidcore Rule Groups, Menu > Configuration > Solidcore Rules), and for
SCPolicy.add_rule_group(), using real exports of the ePO API:
  - sc_rulegroups_awl_win.xml: "scor.rulegroup.export WIN APPLICATION_CONTROL"
    (user defined Rule Groups only): two groups created in the ePO console
    ("Claude - RG AWL (Windows)", "Claude - RG Import (Windows)"), two created
    with this library and imported ("Claude - RG Lib AWL (Windows)", "Claude -
    RG Copy IE (Windows)"), and the empty "Global Rules";
  - sc_rulegroups_cc_unix.xml, sc_rulegroups_fim_win.xml: one group each,
    created with this library and imported;
  - sc_rulegroups_ie.xml: the Trellix predefined "Internet Explorer (32 bit)";
  - sc_awl_rules_win_groups.xml: a policy referencing three Rule Groups with
    add_rule_group(), imported into ePO and exported back.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import (SCRuleGroups, SCAWLRuleGroup, SCCCRuleGroup, SCFIMRuleGroup,
                                 SCAWLPolicyRules, SCCCPolicyRules, SCException as exc)

FIXTURES = Path(__file__).parent / 'fixtures'


def load(name):
    return SCRuleGroups((FIXTURES / name).read_bytes())


@pytest.fixture
def awl_groups():
    return load('sc_rulegroups_awl_win.xml')


def test_list(awl_groups):
    assert [g['name'] for g in awl_groups.list()] == [
        'Claude - RG AWL (Windows)', 'Claude - RG Copy IE (Windows)',
        'Claude - RG Import (Windows)', 'Claude - RG Lib AWL (Windows)', 'Global Rules']
    assert all(not g['read_only'] for g in awl_groups.list())
    assert awl_groups.contain('Global Rules')
    assert awl_groups.get_rule_group('Unknown') is None
    with pytest.raises(ValueError):
        SCRuleGroups(b'<EPOPolicySchema/>')


def test_typed_rule_groups(awl_groups):
    group = awl_groups.get_rule_group('Claude - RG Lib AWL (Windows)')
    assert isinstance(group, SCAWLRuleGroup)
    assert (group.get_type(), group.get_platform(), group.is_read_only()) == (
        'application_control', 'WIN', False)
    assert isinstance(load('sc_rulegroups_cc_unix.xml').get_rule_group(
        'Claude - RG Lib CC (Unix)'), SCCCRuleGroup)
    fim = load('sc_rulegroups_fim_win.xml').get_rule_group('Claude - RG Lib FIM (Windows)')
    assert isinstance(fim, SCFIMRuleGroup)
    assert fim.get_registry_list() == [
        {'pattern': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\LibRG', 'action': 'Include'}]
    ie = load('sc_rulegroups_ie.xml').get_rule_group('Internet Explorer (32 bit)')
    assert ie.is_read_only()
    assert {'exclusion': exc.NX, 'name': '%ProgramFiles(x86)%\\Internet Explorer\\iexplore.exe'} \
        in ie.get_exclusion_list()


def test_tab_methods_on_rule_group(awl_groups):
    group = awl_groups.get_rule_group('Claude - RG Lib AWL (Windows)')
    assert group.get_updaters()[0]['parent'] == 'svc.exe'
    assert group.get_exclusion_list() == [
        {'exclusion': exc.EXCLUDE_ALLOW_LIST, 'name': 'C:\\LibRG\\Data\\'}]
    assert group.get_execution_control_rules()[0]['description'] == 'LibRG block mshta'
    assert group.get_filters()[0]['apply_to_events']
    group.add_trusted_directory('C:\\Tools')
    assert group.remove_updater('LibRGUpdater') == 1
    # Changes are written to the export, "type" first as ePO does.
    rule_obj = awl_groups.root.find('Rule-Group[@name="Claude - RG Lib AWL (Windows)"]/Rule[last()]')
    assert [c.get('name') for c in rule_obj] == ['type', 'action', 'path', 'updater']
    reloaded = SCRuleGroups(awl_groups.get_xml_content()).get_rule_group(group.get_name())
    assert reloaded.get_trusted_directories() == [
        {'type': 'trusted', 'action': 'Include', 'path': 'C:\\Tools', 'updater': 'false'}]
    assert reloaded.get_updaters() == []


def test_new_and_copy_rule_groups():
    groups = SCRuleGroups()
    assert [c.tag for c in groups.root] == ['Active-Directories']
    cc = groups.new_rule_group('CC group', SCRuleGroups.CHANGE_CONTROL, SCRuleGroups.UNIX)
    cc.add_read_protect('/etc/shadow')
    assert cc.is_unix()
    with pytest.raises(ValueError):
        groups.new_rule_group('CC group', SCRuleGroups.CHANGE_CONTROL, SCRuleGroups.UNIX)
    with pytest.raises(ValueError):
        groups.new_rule_group('Bad', 'firewall', SCRuleGroups.WINDOWS)
    with pytest.raises(ValueError):
        groups.new_rule_group('Bad', SCRuleGroups.CHANGE_CONTROL, 'MAC')

    ie = load('sc_rulegroups_ie.xml').get_rule_group('Internet Explorer (32 bit)')
    copy = groups.copy_rule_group(ie, 'My IE')
    assert not copy.is_read_only()
    assert copy.get_rules() == ie.get_rules()
    assert groups.copy_rule_group('CC group', 'CC group 2').get_read_protect_list() == [
        {'pattern': '/etc/shadow', 'action': 'Include'}]
    assert groups.copy_rule_group('Unknown', 'X') is None
    # New groups are inserted before Active-Directories, as in ePO exports.
    assert [c.tag for c in groups.root] == ['Rule-Group'] * 3 + ['Active-Directories']
    assert groups.remove_rule_group('My IE')
    assert not groups.remove_rule_group('My IE')


def test_policy_referencing_rule_groups():
    policy = SCAWLPolicyRules(et.parse(str(FIXTURES / 'sc_awl_rules_win_groups.xml')).getroot())
    assert policy.get_rule_group_names() == [
        'Claude - RG Copy IE (Windows)', 'Claude - RG Lib AWL (Windows)',
        'Internet Explorer (32 bit)']
    lib_rules = load('sc_rulegroups_awl_win.xml').get_rule_group(
        'Claude - RG Lib AWL (Windows)').get_rules()
    for rule in lib_rules:
        assert rule in policy.get_rules(all_groups=True)
    assert all(rule not in policy.get_rules() for rule in lib_rules)


def test_add_rule_group(awl_groups):
    policy = SCAWLPolicyRules(et.parse(str(FIXTURES / 'sc_awl_rules_win.xml')).getroot())
    group = awl_groups.get_rule_group('Claude - RG AWL (Windows)')
    before = policy.get_rules(all_groups=True)
    assert policy.add_rule_group(group)
    assert not policy.add_rule_group(group)
    added = [g for g in policy.get_rule_groups() if g['group_name'] == group.get_name()][0]
    assert added['shared'] and added['settings'].startswith(group.get_name())
    assert policy.root.findall('EPOPolicyObject/PolicySettings')[-1].text == added['settings']
    settings_obj = policy.root.findall('EPOPolicySettings')[-1]
    assert settings_obj.get('typeid') == 'AWL Rules (Windows)'
    assert settings_obj.get('featureid') == 'SCOR_AWL'
    def items(rules):
        return sorted(tuple(sorted(r.items())) for r in rules)
    assert items(policy.get_rules(all_groups=True)) == items(before + group.get_rules())
    assert policy.remove_rule_group(group.get_name())

    cc_group = load('sc_rulegroups_cc_unix.xml').get_rule_group('Claude - RG Lib CC (Unix)')
    with pytest.raises(ValueError):
        policy.add_rule_group(cc_group)
    cc_policy = SCCCPolicyRules(et.parse(str(FIXTURES / 'sc_cc_rules_unix.xml')).getroot())
    assert cc_policy.add_rule_group(cc_group)
    assert cc_policy.get_rule_group_names() == ['Claude - RG Lib CC (Unix)']


def test_new_empty_policy():
    from trellix_epo import SCPolicies
    policies = SCPolicies((FIXTURES / 'sc_awl_rules_win_groups.xml').read_bytes())
    empty = SCAWLPolicyRules(policies.new_empty_policy('AWL Rules (Windows)', 'Empty'))
    assert empty.get_name() == 'Empty'
    assert empty.get_rules() == [] and empty.get_rule_group_names() == []
    assert len(empty.root.findall('EPOPolicySettings')) == 1
    assert empty.add_updater('a.exe', 'A')
    # The template itself is left untouched.
    template = SCAWLPolicyRules(policies.get_policy('AWL Rules (Windows)', 'Claude - RG Policy (Windows)'))
    assert len(template.get_rule_group_names()) == 3
    assert policies.new_empty_policy('CC Rules (Unix)', 'X') is None


def test_rename_rule_group_in_export(awl_groups):
    renamed = awl_groups.rename_rule_group('Claude - RG Lib AWL (Windows)',
                                           'Claude - RG Lib AWL Renamed (Windows)')
    assert renamed.get_name() == 'Claude - RG Lib AWL Renamed (Windows)'
    assert not awl_groups.contain('Claude - RG Lib AWL (Windows)')
    assert awl_groups.contain('Claude - RG Lib AWL Renamed (Windows)')
    assert awl_groups.rename_rule_group('Unknown', 'x') is None
    with pytest.raises(ValueError):
        awl_groups.rename_rule_group('Claude - RG AWL (Windows)', 'Claude - RG Import (Windows)')
    with pytest.raises(ValueError):
        awl_groups.rename_rule_group('Claude - RG AWL (Windows)', ' ')
    # The Rule Groups predefined by Trellix can't be renamed.
    predefined = load('sc_rulegroups_ie.xml')
    name = [g['name'] for g in predefined.list() if g['read_only']][0]
    with pytest.raises(ValueError):
        predefined.rename_rule_group(name, 'Renamed')


def test_rename_rule_group_in_policy():
    policy = SCAWLPolicyRules(et.parse(str(FIXTURES / 'sc_awl_rules_win_groups.xml')).getroot())
    assert policy.rename_rule_group('Claude - RG Lib AWL (Windows)',
                                    'Claude - RG Lib AWL Renamed (Windows)')
    assert 'Claude - RG Lib AWL Renamed (Windows)' in policy.get_rule_group_names()
    assert 'Claude - RG Lib AWL (Windows)' not in policy.get_rule_group_names()
    # My Rules is not a shared Rule Group.
    assert not policy.rename_rule_group('My Rules', 'Other')
    with pytest.raises(ValueError):
        policy.rename_rule_group('Claude - RG Copy IE (Windows)', 'Internet Explorer (32 bit)')
