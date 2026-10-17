"""
Markdown export, information and representation of the Solidcore Rule Groups
(trellix_epo.sc.rulegroups), with the Rule Group exports of the ePO 5.10 lab
(sc_rulegroups_*.xml) and the policy using three of them
(sc_awl_rules_win_groups.xml).
"""

import doctest
from pathlib import Path

from trellix_epo import SCPolicies, SCRuleGroups
from trellix_epo.sc import rulegroups as module
from trellix_epo.sc.rulegroups import rule_group_users

FIXTURES = Path(__file__).parent / 'fixtures'


def load_groups(name):
    """
    Returns the SCRuleGroups of a fixture.
    """
    groups = SCRuleGroups()
    groups.load_from_file(str(FIXTURES / name))
    return groups


def load_policies():
    """
    Returns the Solidcore policy export using shared Rule Groups.
    """
    policies = SCPolicies()
    policies.load_from_file(str(FIXTURES / 'sc_awl_rules_win_groups.xml'))
    return policies


def test_docstring_examples():
    assert doctest.testmod(module).failed == 0


def test_info_and_representation():
    groups = load_groups('sc_rulegroups_awl_win.xml')
    assert repr(groups) == '<SCRuleGroups: 5 rule groups>'
    assert groups.get_info() == {'rule_groups': 5, 'types': {'Application Control (Windows)': 5}}
    group = groups.get_rule_group('Claude - RG Lib AWL (Windows)')
    assert repr(group) == ("<SCAWLRuleGroup 'Claude - RG Lib AWL (Windows)' "
                           "(Application Control, Windows): 5 rules>")
    assert group.get_info() == {'name': 'Claude - RG Lib AWL (Windows)',
                                'type': 'Application Control', 'platform': 'Windows',
                                'origin': 'User defined', 'rules': 5}
    trellix = load_groups('sc_rulegroups_ie.xml').get_rule_group('Internet Explorer (32 bit)')
    assert trellix.get_info()['origin'] == 'Predefined by Trellix (read-only)'


def test_policies_using_the_rule_groups():
    users = rule_group_users(load_policies())
    expected = ['Claude - RG Policy (Windows) (Application Control Rules (Windows))']
    assert users == {
        ('application_control', 'WIN', 'Claude - RG Copy IE (Windows)'): expected,
        ('application_control', 'WIN', 'Claude - RG Lib AWL (Windows)'): expected,
        ('application_control', 'WIN', 'Internet Explorer (32 bit)'): expected}


def test_rule_group_document():
    group = load_groups('sc_rulegroups_awl_win.xml').get_rule_group(
        'Claude - RG Lib AWL (Windows)')
    text = group.to_markdown(load_policies(), author='Claude')
    lines = text.splitlines()
    assert lines[:3] == ['# Claude - RG Lib AWL (Windows)', '',
                         'Solidcore - Application Control Rule Group (Windows)']
    assert '1. Rule Group\n2. Rules\n3. Document control' in text
    assert '| Origin | User defined |' in text and '| Rules | 5 |' in text
    assert ('| Used by policies | Claude - RG Policy (Windows) (Application Control Rules '
            '(Windows)) |') in text
    # The tabs of the console, with the tables of the policy documents.
    assert '### Updater Processes' in text and '| LibRGUpdater | Name |' in text
    assert '| LibRG block mshta | Block | mshta.exe |' in text
    assert '| Prepared by | Claude |' in text
    # Without policies, no "Used by" line.
    assert 'Used by policies' not in group.to_markdown()


def test_other_types():
    change = load_groups('sc_rulegroups_cc_unix.xml').get_rule_group('Claude - RG Lib CC (Unix)')
    assert 'Solidcore - Change Control Rule Group (Unix)' in change.to_markdown()
    assert '### Write-Protect File' in change.to_markdown()
    monitor = load_groups('sc_rulegroups_fim_win.xml').get_rule_group(
        'Claude - RG Lib FIM (Windows)')
    assert 'Solidcore - Integrity Monitor Rule Group (Windows)' in monitor.to_markdown()
    assert '### Registry' in monitor.to_markdown()


def test_rule_groups_document(tmp_path):
    groups = load_groups('sc_rulegroups_awl_win.xml')
    text = groups.to_markdown(load_policies(), title='Application Control Rule Groups')
    assert text.startswith('# Application Control Rule Groups\n\nSolidcore - Rule Groups\n')
    assert '| Application Control (Windows) | 5 |' in text
    summary = [line for line in text.splitlines() if line.startswith('| 1 |') or
               line.startswith('| 2 |')]
    assert summary[0].startswith('| 1 | Claude - RG AWL (Windows) | Application Control | '
                                 'Windows | User defined |')
    assert summary[0].endswith('| None |')
    assert '## 4. Claude - RG Import (Windows)' in text and '## 6. Global Rules' in text
    groups.save_markdown(str(tmp_path / 'groups.md'))
    assert (tmp_path / 'groups.md').read_text(encoding='utf-8').startswith(
        '# Solidcore Rule Groups')
    empty = SCRuleGroups().to_markdown()
    assert '## 1. Rule Groups\n\n*None*' in empty
