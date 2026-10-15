"""
Policy Assignment Rules (trellix_epo.assignmentrules), without a server.

assignment_rules.xml: console export (Policy Assignment Rules > Actions >
Export) of the ePO 5.10 Update 7 lab, byte for byte:
- "Disable Endpoint Security": rule of the user (tag OFF);
- "Claude - Rule System Test": saved in the console wizard (two groups
  without subgroups, has and doesn't have tag, five policies of which two
  Exploit Prevention, notes with quotes and markup);
- "Claude - Rule Disabled Test": first saved in the console, then replaced
  by an import (kept disabled and at priority 3);
- "Claude - Rule Import A", "C1", "B4": imported from files written by this
  module (C1 without tag; B4 with an unknown tag, exported without its tag
  criteria).
The library rebuilds this file identically (test_lab_file_rebuilt).
"""

import doctest
from pathlib import Path

import pytest

from trellix_epo import assignmentrules as module
from trellix_epo import (AssignmentRule, AssignmentRuleList, PolicyAssignment, RuleTagCriteria,
                         SystemGroups)
from trellix_epo.assignmentrules import CATEGORIES, MULTI_SLOT

FIXTURE = Path(__file__).parent / 'fixtures' / 'assignment_rules.xml'
SIR = ('My Default', 'General', 'SIR_____1000_COLLECT_DATA')
NONE_GROUP = 'Lost and Found\\(none)'


def test_docstring_examples():
    result = doctest.testmod(module)
    assert result.attempted >= 45 and result.failed == 0


def test_read_lab_export():
    rules = AssignmentRuleList.load_from_file(FIXTURE)
    assert [rule.name for rule in rules] == [
        'Disable Endpoint Security', 'Claude - Rule System Test', 'Claude - Rule Disabled Test',
        'Claude - Rule Import A', 'Claude - Rule Import C1', 'Claude - Rule Import B4']
    off = rules.get('Disable Endpoint Security')
    assert off.groups == SystemGroups('My Organization')
    assert off.tags.conditions == [('OFF', True)]
    assert off.policies == [PolicyAssignment('OFF', 'EAM_General_Policies', 'ENDP_AM_1000')]
    test = rules.get('Claude - Rule System Test')
    assert test.groups.paths == ['My Organization\\Linux Servers', 'My Organization\\Workstations']
    assert not test.groups.subgroups
    assert str(test.tags) == 'Has tag SQL Server and Does not have tag OFF'
    assert test.notes == 'Notes "quoted" & <b>'
    assert [p.labels[1] for p in test.policies] == [
        'General', 'Exploit Prevention', 'Exploit Prevention', 'On-Access Scan',
        'Configuration (Client)']
    assert rules.get('Claude - Rule Import C1').tags.conditions == []
    assert not any(rule.user_based for rule in rules)


def test_lab_file_rebuilt():
    """
    The rules written with the library give the console export, byte for
    byte (CRLF, escapes, id numbering).
    """
    expected = FIXTURE.read_bytes()
    assert AssignmentRuleList(expected).get_xml_content() == expected
    rules = AssignmentRuleList()
    rules.add(AssignmentRule('Disable Endpoint Security', 'My Organization',
                             [PolicyAssignment.from_console('Endpoint Security Threat Prevention',
                                                            'On-Access Scan', 'OFF')], ['OFF']))
    test = AssignmentRule('Claude - Rule System Test', ['Linux Servers', 'Workstations'],
                          tags=[('SQL Server', True), ('OFF', False)],
                          notes='Notes "quoted" & <b>', subgroups=False)
    test.add_policy('Demo (Systray)', 'General', 'EPOAGENTMETA')
    test.add_policy('Demo (Monitor Fileless)', 'EAM_BufferOverflow_Policies', 'ENDP_AM_1000')
    test.add_policy('Demo (Monitor Linux)', 'EAM_BufferOverflow_Policies', 'ENDP_AM_1000')
    test.add_policy('Demo (Ransomware)', 'EAM_General_Policies', 'ENDP_AM_1000')
    test.add_policy(PolicyAssignment.from_console('Solidcore 8.4.5:General',
                                                  'Configuration (Client)', 'Demo (No Throttling)'))
    rules.add(test)
    rules.add(AssignmentRule('Claude - Rule Disabled Test', 'OT Systems', [SIR], ['SQL Server'],
                             'overwritten'))
    rules.add(AssignmentRule('Claude - Rule Import A', ['Linux Servers', 'Workstations'],
                             [('Demo (Systray)', 'General', 'EPOAGENTMETA'),
                              ('Demo (Monitor Fileless)', 'EAM_BufferOverflow_Policies',
                               'ENDP_AM_1000')],
                             RuleTagCriteria(['SQL Server', ('OFF', False)]), 'Imported A',
                             subgroups=False))
    rules.add(AssignmentRule('Claude - Rule Import C1', NONE_GROUP, [SIR], notes='no tag'))
    rules.add(AssignmentRule('Claude - Rule Import B4', NONE_GROUP, [SIR]))
    assert rules.get_xml_content() == expected


def test_multiline_notes():
    """
    The export writes the line ends of the notes as they are; the library
    reads them back and writes them as character references (imported as
    line ends, checked on the lab with accents).
    """
    export = ('<?xml version="1.0" encoding="UTF-8"?>\r\n<epo:EPOPolicyRuleSchema '
              'xmlns:epo="mcafee-epo-policyassignmentrule" '
              'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\r\n'
              '<EPOPolicyRule name="Claude - Rule Import D" id="7" systemExpression="( where '
              '( descendsFrom ubp_system &quot;\\\\&quot; ) )" assignmentMethod="1" '
              'userExpression="( where ( hasTag tag_system &quot;EPO/SQL Server&quot; ) )" '
              'notes="Ligne 1\nSystèmes suspects &lt;é&gt; &amp; &quot;x&quot;">\r\n'
              '<EPOPolicyRuleAssignment policyname="Demo (Ransomware)" '
              'typeid="EAM_General_Policies" featureid="ENDP_AM_1000" '
              'categoryid="EAM_General_Policies">\r\n</EPOPolicyRuleAssignment>\r\n'
              '</EPOPolicyRule>\r\n</epo:EPOPolicyRuleSchema>').encode('utf-8')
    rule = AssignmentRuleList(export).get('Claude - Rule Import D')
    assert rule.notes == 'Ligne 1\nSystèmes suspects <é> & "x"'
    written = AssignmentRuleList()
    written.add(rule)
    assert 'notes="Ligne 1&#10;Systèmes' in written.get_xml_content().decode('utf-8')
    assert AssignmentRuleList(written.get_xml_content()).get(rule.name).notes == rule.notes


def test_groups():
    assert SystemGroups.squid_path('Workstations') == '\\Workstations\\'
    assert SystemGroups.squid_path('\\') == '\\'
    assert SystemGroups.squid_path('My Organization\\Lost and Found') == '\\Lost&Found\\'
    # Only the Lost and Found group under the root has an internal name.
    assert SystemGroups.squid_path('Servers\\Lost and Found') == '\\Servers\\Lost and Found\\'
    groups = SystemGroups(['Workstations', 'My Organization\\Workstations', 'OT Systems'])
    assert groups.paths == ['My Organization\\Workstations', 'My Organization\\OT Systems']
    assert SystemGroups.from_squid(groups.to_squid()) == groups
    with pytest.raises(ValueError):
        SystemGroups.from_squid('( where ( eq EPOLeafNode.NodeName "x" ) )')


def test_tags():
    tags = RuleTagCriteria(['A "quoted"', ('B\\C', False)], joiner='or')
    assert tags.to_squid() == ('( where ( or ( hasTag tag_system "EPO/A \\"quoted\\"" ) '
                               '( doesNotHaveTag tag_system "EPO/B\\\\C" ) ) )')
    assert RuleTagCriteria.from_squid(tags.to_squid()) == tags
    assert RuleTagCriteria.from_squid('') == RuleTagCriteria()
    assert RuleTagCriteria().to_squid() == ''
    with pytest.raises(ValueError):
        RuleTagCriteria().add(' ')
    with pytest.raises(ValueError):
        RuleTagCriteria.from_squid('( where ( hasTag tag_system "OTHER/A" ) )')


def test_policies_and_checks():
    rule = AssignmentRule('R', 'Workstations')
    with pytest.raises(ValueError, match='assigns no policy'):
        rule.check()
    rule.add_policy(SIR)
    with pytest.raises(ValueError, match='already assigns policy'):
        rule.add_policy(SIR)
    with pytest.raises(ValueError, match='not multi-slot'):
        rule.add_policy('Other', 'General', 'SIR_____1000_COLLECT_DATA')
    for feature_id, type_id in sorted(MULTI_SLOT):
        rule.add_policy('P1', type_id, feature_id).add_policy('P2', type_id, feature_id)
    rule.check()
    rule.notes = 'x' * 1025
    with pytest.raises(ValueError, match='notes longer'):
        rule.check()
    assert all(key in CATEGORIES for key in MULTI_SLOT)
    with pytest.raises(ValueError):
        PolicyAssignment('', 'General', 'EPOAGENTMETA')
    assert PolicyAssignment.from_console('System Information Reporter :Set Registry',
                                         'Registry General', 'X').key() == \
        ('SIR_____1000_SET_REGISTRY', 'General', 'X')


def test_from_policy():
    from trellix_epo import Policies, Policy
    fixtures = Path(__file__).parent / 'fixtures'
    policies = Policies((fixtures / 'oas_policy.xml').read_bytes())
    item = policies.list()[0]
    policy = Policy(policies.get_policy(item['typeid'], item['name']))
    assignment = PolicyAssignment.from_policy(policy)
    assert assignment.key() == ('ENDP_AM_1000', 'EAM_General_Policies', item['name'])


def test_user_based_kept():
    """
    A User Based rule (assignmentMethod other than 1, not testable on the
    lab without LDAP) is written back unchanged.
    """
    text = FIXTURE.read_bytes().decode('utf-8').replace(
        'assignmentMethod="1" userExpression="( where ( hasTag tag_system &quot;EPO/OFF&quot; ) )"',
        'assignmentMethod="2" userExpression="( where ( ubp_isUser ubp_user &quot;x&quot; ) )"', 1)
    rules = AssignmentRuleList(text)
    assert rules.get('Disable Endpoint Security').user_based
    assert rules.get_xml_content() == text.encode('utf-8')
    with pytest.raises(ValueError):
        AssignmentRuleList('<other/>')


class FakeEPO():
    """
    The answers of system.findGroups, system.findTag and policy.find.
    """

    def call(self, command, *args, **params):
        """
        Returns the answer of a read command.
        """
        return {
            'system.findGroups': [{'groupId': 2, 'groupPath': 'My Organization'},
                                  {'groupId': 6, 'groupPath': 'My Organization\\Workstations'}],
            'system.findTag': [{'tagId': 1, 'tagName': 'Suspicious'}],
            'policy.find': [{'featureId': 'ENDP_AM_1000', 'typeName': 'On-Access Scan',
                             'objectName': 'Hard'},
                            {'featureId': 'OTHER', 'typeName': 'Any', 'objectName': 'Other'}],
        }[command]


def test_check_server():
    rules = AssignmentRuleList()
    rules.add(AssignmentRule('Good', 'workstations', [('Hard', 'EAM_General_Policies',
                                                       'ENDP_AM_1000'),
                                                      ('Other', 'X', 'OTHER')], ['suspicious']))
    assert rules.check_server(FakeEPO()) == []
    rules.add(AssignmentRule('Bad', 'Servers', [('Hard', 'EAM_OnDemandScan_Policies',
                                                 'ENDP_AM_1000')], ['Missing']))
    assert rules.check_server(FakeEPO()) == [
        'Rule "Bad": System Tree group "My Organization\\Servers" not found (the import fails).',
        'Rule "Bad": tag "Missing" not found (the import drops the tag criteria).',
        'Rule "Bad": policy "Hard" (ENDP_AM_1000 / EAM_OnDemandScan_Policies) not found '
        '(the import fails).']


def test_markdown():
    rules = AssignmentRuleList.load_from_file(FIXTURE)
    lines = rules.to_markdown().splitlines()
    assert len(lines) == 2 + len(rules)
    assert lines[3].startswith('| Claude - Rule System Test | My Organization\\Linux Servers or ')
