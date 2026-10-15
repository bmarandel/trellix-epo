# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the ePO Policy Assignment Rules as objects, to write the
file of the console import (Policy > Policy Assignment Rules > Actions >
Import) or to read the file of its export (Actions > Export). The ePO Web
API has no command for these rules: the file is imported by hand in the
console.

A System Based rule assigns policies to the systems of System Tree groups
(the group only, or the group and its subgroups) that match tag criteria:

>>> rule = AssignmentRule('Suspicious systems', ['My Organization'],
...                       tags=RuleTagCriteria([('Suspicious', True)]))
>>> rule.add_policy('Suspicious', 'EAM_General_Policies', 'ENDP_AM_1000')
<AssignmentRule Suspicious systems: 1 policy>
>>> rules = AssignmentRuleList()
>>> rules.add(rule)
>>> b'hasTag tag_system &quot;EPO/Suspicious&quot;' in rules.get_xml_content()
True

The file has no rule state (enabled or disabled) and no priority: an
imported rule is added at the end of the list and enabled; a rule with the
name of an existing rule replaces its content and keeps its priority and
state (checked on ePO 5.10 Update 7).
"""

import re
import xml.etree.ElementTree as et
from xml.sax.saxutils import escape

from .tags import squid_quote, squid_parse

# Namespace of the root element (the tag export uses the same one).
NAMESPACE = 'mcafee-epo-policyassignmentrule'

# assignmentMethod of a System Based rule (radio "machine" of the console
# wizard). User Based rules (radio "ubp") need an LDAP server registered in
# ePO and are only kept as read (see AssignmentRule.user_based).
SYSTEM_BASED = '1'

# Console limits of the rule wizard (displayRuleDescription.do).
MAX_RULE_NAME = 128
MAX_NOTES = 1024

# Root group of the System Tree, and the "Lost and Found" group directly
# under it, which the rule expressions write with its internal name.
ROOT_GROUP = 'My Organization'
LOST_AND_FOUND = 'Lost and Found'
LOST_AND_FOUND_INTERNAL = 'Lost&Found'

# Tag family written before the tag name ("EPO/<tag name>"); the tag group
# is not written.
TAG_FAMILY = 'EPO'

# Policy categories of the products the library supports: (featureid,
# typeid) of the policy export -> (product, category) as the rule wizard
# shows them.
CATEGORIES = {
    ('EPOAGENTMETA', 'General'): ('Trellix Agent', 'General'),
    ('EPOAGENTMETA', 'Repository'): ('Trellix Agent', 'Repository'),
    ('EPOAGENTMETA', 'Troubleshooting'): ('Trellix Agent', 'Troubleshooting'),
    ('EPOAGENTMETA', 'CustomProps'): ('Trellix Agent', 'Custom Properties'),
    ('EPOAGENTMETA', 'Telemetry'): ('Trellix Agent', 'Product Improvement Program'),
    ('ENDP_AM_1000', 'EAM_General_Policies'): ('Endpoint Security Threat Prevention',
                                               'On-Access Scan'),
    ('ENDP_AM_1000', 'EAM_OnDemandScan_Policies'): ('Endpoint Security Threat Prevention',
                                                    'On-Demand Scan'),
    ('ENDP_AM_1000', 'EAM_CommonScan_Policies'): ('Endpoint Security Threat Prevention', 'Options'),
    ('ENDP_AM_1000', 'EAM_BehaviorBlock_Policies'): ('Endpoint Security Threat Prevention',
                                                     'Access Protection'),
    ('ENDP_AM_1000', 'EAM_BufferOverflow_Policies'): ('Endpoint Security Threat Prevention',
                                                      'Exploit Prevention'),
    ('ENDP_FW_META_FW', 'FW_StatusMode'): ('Endpoint Security Firewall', 'Options'),
    ('ENDP_FW_META_FW', 'FireCore_FW_Rules'): ('Endpoint Security Firewall', 'Rules'),
    ('ENDP_GS_1000', 'EGS_Product_Configuration_Policies'): ('Endpoint Security Common',
                                                             'Options'),
    ('TIEClientMETA', 'General'): ('Endpoint Security Adaptive Threat Protection', 'Options'),
    ('TIEClientMETA', 'TIE_DynamicApplicationContainment_Policies'): (
        'Endpoint Security Adaptive Threat Protection', 'Dynamic Application Containment'),
    ('ENDP_WP_1000', 'EWC_General'): ('Endpoint Security Web Control', 'Options'),
    ('ENDP_WP_1000', 'EWC_EnforcementMessaging'): ('Endpoint Security Web Control',
                                                   'Enforcement Messaging'),
    ('ENDP_WP_1000', 'EWC_BlockAndAllowList'): ('Endpoint Security Web Control',
                                                'Block and Allow List'),
    ('ENDP_WP_1000', 'EWC_ContentFiltering'): ('Endpoint Security Web Control', 'Content Actions'),
    ('ENDP_WP_1000', 'EWC_BrowserControl'): ('Endpoint Security Web Control', 'Browser Control'),
    ('VSESTOMD1300', 'VSES1000_Icap_Policies'): ('Endpoint Security Storage Protection',
                                                 'ICAP Policies'),
    ('VSESTOMD1300', 'VSES1000_Netapp_Policies'): ('Endpoint Security Storage Protection',
                                                   'NetApp Policies'),
    ('SCOR_AWL', 'AWL Rules (Windows)'): ('Solidcore:Application Control',
                                          'Application Control Rules (Windows)'),
    ('SCOR_AWL', 'AWL Rules (Unix)'): ('Solidcore:Application Control',
                                       'Application Control Rules (Unix)'),
    ('SCOR_AWL', 'AWL Options (Windows)'): ('Solidcore:Application Control',
                                            'Application Control Options (Windows)'),
    ('SCOR_AWL', 'AWL Options (Unix)'): ('Solidcore:Application Control',
                                         'Application Control Options (Unix)'),
    ('SCOR_CC', 'CC Rules (Windows)'): ('Solidcore:Change Control',
                                        'Change Control Rules (Windows)'),
    ('SCOR_CC', 'CC Rules (Unix)'): ('Solidcore:Change Control', 'Change Control Rules (Unix)'),
    ('SCOR_FIM', 'Mon Rules (Windows)'): ('Solidcore:Integrity Monitor',
                                          'Integrity Monitoring Rules (Windows)'),
    ('SCOR_FIM', 'Mon Rules (Unix)'): ('Solidcore:Integrity Monitor',
                                       'Integrity Monitoring Rules (Unix)'),
    ('SCOR_GEN', 'Lockdown Rules'): ('Solidcore:General', 'Configuration (Client)'),
    ('SCOR_GEN', 'Attr Rules (Windows)'): ('Solidcore:General', 'Exception Rules (Windows)'),
    ('SCOR_GEN', 'Attr Rules (Unix)'): ('Solidcore:General', 'Exception Rules (Unix)'),
    ('SIR_____1000_COLLECT_DATA', 'General'): ('System Information Reporter:Collect Data',
                                               'General'),
    ('SIR_____1000_SET_REGISTRY', 'General'): ('System Information Reporter:Set Registry',
                                               'Registry General'),
    ('XCLIENT_META', 'General'): ('Trellix EDR with Forensics', 'General'),
    ('XCLIENT_META', 'Streaming'): ('Trellix EDR with Forensics', 'Streaming'),
    ('XCLIENT_META', 'Detection'): ('Trellix EDR with Forensics', 'Detection'),
    ('XCLIENT_META', 'Investigation'): ('Trellix EDR with Forensics', 'Investigation'),
    ('XCLIENT_META', 'Remediation'): ('Trellix EDR with Forensics', 'Remediation'),
}

# Policy categories (featureid, typeid) marked "(Multi-slot)" in the rule
# wizard: a rule can assign several policies of these categories. The other
# categories take one policy per rule.
MULTI_SLOT = frozenset([
    ('ENDP_AM_1000', 'EAM_BufferOverflow_Policies'),
    ('ENDP_WP_1000', 'EWC_BlockAndAllowList'),
    ('ENDP_WP_1000', 'EWC_ContentFiltering'),
    ('SCOR_AWL', 'AWL Rules (Windows)'),
    ('SCOR_AWL', 'AWL Rules (Unix)'),
    ('SCOR_CC', 'CC Rules (Windows)'),
    ('SCOR_CC', 'CC Rules (Unix)'),
    ('SCOR_FIM', 'Mon Rules (Windows)'),
    ('SCOR_FIM', 'Mon Rules (Unix)'),
    ('SCOR_GEN', 'Lockdown Rules'),
    ('SCOR_GEN', 'Attr Rules (Windows)'),
    ('SCOR_GEN', 'Attr Rules (Unix)'),
])

# Line end of the console export.
_EOL = '\r\n'


def _attr(value):
    """
    Returns an attribute value escaped as the console export does (", &, <,
    >), the line ends as character references (a parser turns raw line ends
    of an attribute into spaces).

    >>> _attr('Notes "quoted" & <b>')
    'Notes &quot;quoted&quot; &amp; &lt;b&gt;'
    >>> _attr('a\\nb')
    'a&#10;b'
    """
    return escape(value, {'"': '&quot;', '\n': '&#10;', '\r': '&#13;', '\t': '&#9;'})


def _keep_line_ends(text):
    """
    Returns the XML with the line ends of the attribute values written as
    character references: the console export writes the line ends of the
    notes as they are, which an XML parser turns into spaces.

    >>> _keep_line_ends('<a notes="1\\n2"/>')
    '<a notes="1&#10;2"/>'
    """
    return re.sub(r'="([^"]*)"', lambda match: '="{}"'.format(
        match.group(1).replace('\r', '&#13;').replace('\n', '&#10;')), text)


def _label_key(label):
    """
    Returns a console label to compare: lower case, without the product
    versions and the blanks around ":".

    >>> _label_key('System Information Reporter :Collect Data')
    'system information reporter:collect data'
    >>> _label_key('Solidcore 8.4.5:General')
    'solidcore:general'
    """
    label = re.sub(r'\s+\d+(\.\d+)+', '', label.strip().lower())
    return re.sub(r'\s*:\s*', ':', label)


# ------------------------------ System Tree groups ------------------------------
class SystemGroups():
    """
    The System criteria of a rule: one or more System Tree groups (any of
    them), with or without their subgroups. The paths are written as in the
    console, from "My Organization" (which can be left out):

    >>> groups = SystemGroups(['My Organization\\\\Workstations', 'Lost and Found\\\\(none)'])
    >>> groups.to_squid()
    '( where ( descendsFrom ubp_system "\\\\\\\\Workstations\\\\\\\\" "\\\\\\\\Lost&Found\\\\\\\\(none)\\\\\\\\" ) )'
    >>> SystemGroups(['My Organization'], subgroups=False).to_squid()
    '( where ( childOf ubp_system "\\\\\\\\" ) )'
    >>> SystemGroups([])
    Traceback (most recent call last):
    ValueError: A rule needs at least one System Tree group.
    """

    def __init__(self, paths, subgroups=True):
        """
        :param: paths: A group path or a list of paths, e.g. 'My
                       Organization', 'Workstations' or 'My
                       Organization\\Lost and Found\\(none)'.
        :param: subgroups: True for "System is in group or subgroup"
                           (descendsFrom), False for "System is in group"
                           (childOf).
        """
        if isinstance(paths, str):
            paths = [paths]
        self.paths = []
        for path in paths:
            path = self.normalize(path)
            if path not in self.paths:
                self.paths.append(path)
        if not self.paths:
            raise ValueError('A rule needs at least one System Tree group.')
        self.subgroups = bool(subgroups)

    def __repr__(self):
        """
        Shows the groups and the operator.
        """
        return '<SystemGroups {}{}>'.format(' or '.join(self.paths),
                                            ' (and subgroups)' if self.subgroups else '')

    def __eq__(self, other):
        """
        Same groups and same operator.
        """
        return isinstance(other, SystemGroups) and \
            (self.paths, self.subgroups) == (other.paths, other.subgroups)

    @staticmethod
    def normalize(path):
        """
        Returns a group path from "My Organization", the backslashes as
        separators, without empty parts.

        >>> SystemGroups.normalize('\\\\Workstations\\\\')
        'My Organization\\\\Workstations'
        >>> SystemGroups.normalize('My Organization')
        'My Organization'
        >>> SystemGroups.normalize('Lost&Found\\\\(none)')
        'My Organization\\\\Lost and Found\\\\(none)'
        """
        parts = [part.strip() for part in path.split('\\') if part.strip()]
        if parts and parts[0].lower() == ROOT_GROUP.lower():
            parts = parts[1:]
        if parts and parts[0] == LOST_AND_FOUND_INTERNAL:
            parts[0] = LOST_AND_FOUND
        return '\\'.join([ROOT_GROUP] + parts)

    @staticmethod
    def squid_path(path):
        """
        Returns the path of a group in the rule expression: from the root,
        between backslashes, "Lost and Found" under its internal name.

        >>> SystemGroups.squid_path('My Organization')
        '\\\\'
        >>> SystemGroups.squid_path('My Organization\\\\Lost and Found\\\\(none)')
        '\\\\Lost&Found\\\\(none)\\\\'
        """
        parts = SystemGroups.normalize(path).split('\\')[1:]
        if parts and parts[0] == LOST_AND_FOUND:
            parts[0] = LOST_AND_FOUND_INTERNAL
        return '\\' + ''.join(part + '\\' for part in parts)

    def to_squid(self):
        """
        Returns the systemExpression of the rule.
        """
        return '( where ( {} ubp_system {} ) )'.format(
            'descendsFrom' if self.subgroups else 'childOf',
            ' '.join(squid_quote(self.squid_path(path)) for path in self.paths))

    @classmethod
    def from_squid(cls, text):
        """
        Returns the groups of a systemExpression.

        >>> SystemGroups.from_squid('( where ( childOf ubp_system "\\\\\\\\OT Systems\\\\\\\\" ) )')
        <SystemGroups My Organization\\OT Systems>

        :raise: ValueError: Not a System criteria of the rule wizard.
        """
        parsed = squid_parse(text)
        if len(parsed) != 2 or parsed[0] != 'where' or len(parsed[1]) < 3 or \
                parsed[1][0] not in ('descendsFrom', 'childOf') or parsed[1][1] != 'ubp_system':
            raise ValueError('Not a System criteria: {}'.format(text))
        return cls(list(parsed[1][2:]), parsed[1][0] == 'descendsFrom')


# ------------------------------ Tags ------------------------------
class RuleTagCriteria():
    """
    The Tag criteria of a rule: systems that have (or don't have) tags, all
    of them ("and") or any of them ("or"), as in the console (the tags are
    named without their tag group):

    >>> tags = RuleTagCriteria([('Suspicious', True), ('OFF', False)])
    >>> tags
    <RuleTagCriteria Has tag Suspicious and Does not have tag OFF>
    >>> tags.to_squid()   # doctest: +NORMALIZE_WHITESPACE
    '( where ( and ( hasTag tag_system "EPO/Suspicious" )
      ( doesNotHaveTag tag_system "EPO/OFF" ) ) )'
    >>> RuleTagCriteria([('Suspicious', True)]).to_squid()
    '( where ( hasTag tag_system "EPO/Suspicious" ) )'
    """

    def __init__(self, tags=None, joiner='and'):
        """
        :param: tags: A list of tag names (has the tag) or of (tag name,
                      has) tuples, has False for "Does not have tag".
        :param: joiner: 'and' (all the conditions) or 'or' (any).
        """
        self.conditions = []
        self.joiner = 'and'
        self.set_joiner(joiner)
        for item in tags or []:
            if isinstance(item, str):
                self.add(item)
            else:
                self.add(*item)

    def __repr__(self):
        """
        Shows the conditions as the console does.
        """
        return '<RuleTagCriteria {}>'.format(str(self) or 'empty')

    def __str__(self):
        """
        Returns the conditions as the console shows them.
        """
        return ' {} '.format(self.joiner).join(
            '{} {}'.format('Has tag' if has else 'Does not have tag', tag)
            for tag, has in self.conditions)

    def __len__(self):
        """
        Returns the number of conditions.
        """
        return len(self.conditions)

    def __eq__(self, other):
        """
        Same conditions and same joiner.
        """
        return isinstance(other, RuleTagCriteria) and \
            (self.conditions, self.joiner) == (other.conditions, other.joiner)

    def set_joiner(self, joiner):
        """
        Sets how the conditions are joined: 'and' or 'or'.

        >>> RuleTagCriteria().set_joiner('xor')
        Traceback (most recent call last):
        ValueError: The tag conditions are joined with "and" or "or".
        """
        if joiner not in ('and', 'or'):
            raise ValueError('The tag conditions are joined with "and" or "or".')
        self.joiner = joiner

    def add(self, tag, has=True):
        """
        Adds a condition on a tag (its name, without the tag group).

        >>> RuleTagCriteria().add('Suspicious').add('Suspicious')
        Traceback (most recent call last):
        ValueError: Tag Suspicious is already in the criteria.

        :return: The criteria (to chain the calls).
        """
        if not tag or not tag.strip():
            raise ValueError('A tag name is required.')
        if any(name.lower() == tag.lower() for name, _ in self.conditions):
            raise ValueError('Tag {} is already in the criteria.'.format(tag))
        self.conditions.append((tag, bool(has)))
        return self

    def remove(self, tag):
        """
        Removes the condition on a tag (case ignored).

        >>> RuleTagCriteria(['A', 'B']).remove('a')
        <RuleTagCriteria Has tag B>
        """
        self.conditions = [(name, has) for name, has in self.conditions
                           if name.lower() != tag.lower()]
        return self

    def to_squid(self):
        """
        Returns the userExpression of the rule ('' without condition).
        """
        items = ['( {} tag_system {} )'.format('hasTag' if has else 'doesNotHaveTag',
                                               squid_quote('{}/{}'.format(TAG_FAMILY, tag)))
                 for tag, has in self.conditions]
        if not items:
            return ''
        if len(items) == 1:
            return '( where {} )'.format(items[0])
        return '( where ( {} {} ) )'.format(self.joiner, ' '.join(items))

    @classmethod
    def from_squid(cls, text):
        """
        Returns the tag criteria of a userExpression.

        >>> RuleTagCriteria.from_squid('( where ( or ( hasTag tag_system "EPO/A" ) '
        ...                            '( hasTag tag_system "EPO/B" ) ) )')
        <RuleTagCriteria Has tag A or Has tag B>

        :raise: ValueError: Not a tag criteria of the rule wizard.
        """
        criteria = cls()
        if not text.strip():
            return criteria
        parsed = squid_parse(text)
        if len(parsed) != 2 or parsed[0] != 'where':
            raise ValueError('Not a tag criteria: {}'.format(text))
        items = [parsed[1]]
        if parsed[1] and parsed[1][0] in ('and', 'or'):
            criteria.set_joiner(parsed[1][0])
            items = parsed[1][1:]
        for item in items:
            if len(item) != 3 or item[0] not in ('hasTag', 'doesNotHaveTag') or \
                    item[1] != 'tag_system' or not item[2].startswith(TAG_FAMILY + '/'):
                raise ValueError('Not a tag criteria: {}'.format(text))
            criteria.add(item[2][len(TAG_FAMILY) + 1:], item[0] == 'hasTag')
        return criteria


# ------------------------------ Policies ------------------------------
class PolicyAssignment():
    """
    A policy assigned by a rule: its name, its category (typeid) and its
    product feature (featureid), as in the Policy Catalog export.

    >>> PolicyAssignment('Demo (Systray)', 'General', 'EPOAGENTMETA')
    <PolicyAssignment EPOAGENTMETA / General: Demo (Systray)>
    """

    def __init__(self, name, type_id, feature_id):
        """
        :param: name: The policy name.
        :param: type_id: The category, e.g. 'EAM_General_Policies' (ENS TP
                         On-Access Scan) or 'General' (Trellix Agent).
        :param: feature_id: The product feature, e.g. 'ENDP_AM_1000' or
                            'EPOAGENTMETA' (the policy export featureid:
                            'SCOR_GEN', not 'SOLIDCORE_META').
        """
        for value, label in ((name, 'policy name'), (type_id, 'category'),
                             (feature_id, 'feature')):
            if not value or not value.strip():
                raise ValueError('A {} is required.'.format(label))
        self.name = name
        self.type_id = type_id
        self.feature_id = feature_id

    def __repr__(self):
        """
        Shows the feature, the category and the name.
        """
        return '<PolicyAssignment {} / {}: {}>'.format(self.feature_id, self.type_id, self.name)

    def __eq__(self, other):
        """
        Same policy (name, category and feature).
        """
        return isinstance(other, PolicyAssignment) and self.key() == other.key()

    def key(self):
        """
        Returns (feature, category, name).
        """
        return (self.feature_id, self.type_id, self.name)

    @property
    def category(self):
        """
        Returns (feature, category): the slot of the policy.
        """
        return (self.feature_id, self.type_id)

    @property
    def multi_slot(self):
        """
        True when a rule can assign several policies of this category.

        >>> PolicyAssignment('A', 'EAM_BufferOverflow_Policies', 'ENDP_AM_1000').multi_slot
        True
        """
        return self.category in MULTI_SLOT

    @property
    def labels(self):
        """
        Returns (product, category) as the rule wizard shows them, or None
        for a category the library doesn't know.

        >>> PolicyAssignment('A', 'EAM_General_Policies', 'ENDP_AM_1000').labels
        ('Endpoint Security Threat Prevention', 'On-Access Scan')
        """
        return CATEGORIES.get(self.category)

    @classmethod
    def from_console(cls, product, category, name):
        """
        Returns the assignment of a policy given as in the rule wizard:
        product, category and policy name (case and product versions
        ignored).

        >>> PolicyAssignment.from_console('Solidcore 8.4.5:General', 'Configuration (Client)', 'X')
        <PolicyAssignment SCOR_GEN / Lockdown Rules: X>
        >>> PolicyAssignment.from_console('Trellix Agent', 'Nope', 'X')
        Traceback (most recent call last):
        ValueError: Unknown policy category: Trellix Agent / Nope.
        """
        wanted = (_label_key(product), _label_key(category))
        for (feature_id, type_id), labels in CATEGORIES.items():
            if (_label_key(labels[0]), _label_key(labels[1])) == wanted:
                return cls(name, type_id, feature_id)
        raise ValueError('Unknown policy category: {} / {}.'.format(product, category))

    @classmethod
    def from_policy(cls, policy):
        """
        Returns the assignment of a policy of the library (a Policy, e.g.
        from Policies.get_policy() or EPOClient.export_policies()).
        """
        policy_obj = policy.root.find('EPOPolicyObject')
        if policy_obj is None:
            raise ValueError('The policy has no EPOPolicyObject.')
        return cls(policy_obj.get('name'), policy_obj.get('typeid'), policy_obj.get('featureid'))

    def to_xml(self):
        """
        Returns the EPOPolicyRuleAssignment element as the console exports
        it (categoryid is the typeid).
        """
        return ('<EPOPolicyRuleAssignment policyname="{}" typeid="{}" featureid="{}" '
                'categoryid="{}">{eol}</EPOPolicyRuleAssignment>{eol}').format(
                    _attr(self.name), _attr(self.type_id), _attr(self.feature_id),
                    _attr(self.type_id), eol=_EOL)

    @classmethod
    def from_element(cls, element):
        """
        Returns the assignment of an EPOPolicyRuleAssignment element.
        """
        return cls(element.get('policyname'), element.get('typeid') or element.get('categoryid'),
                   element.get('featureid'))


# ------------------------------ Rules ------------------------------
class AssignmentRule():
    """
    A System Based Policy Assignment Rule: name, notes, System Tree groups,
    tag criteria (optional) and the policies to assign.

    >>> rule = AssignmentRule('Escalated', 'Workstations', subgroups=False)
    >>> rule.add_policy('Demo (Monitor Linux)', 'EAM_BufferOverflow_Policies', 'ENDP_AM_1000')
    <AssignmentRule Escalated: 1 policy>
    >>> rule.check()
    >>> AssignmentRule('X' * 129, 'Workstations').check()
    Traceback (most recent call last):
    ValueError: Rule name longer than 128 characters (console limit).
    """

    def __init__(self, name, groups, policies=None, tags=None, notes='', subgroups=True):
        """
        :param: name: The rule name (128 characters; a rule with the name of
                      an existing rule replaces it at the import).
        :param: groups: A SystemGroups, or a group path or list of paths.
        :param: policies: A list of PolicyAssignment, Policy or (name,
                          typeid, featureid) tuples.
        :param: tags: A RuleTagCriteria, a list of tag names or (name, has)
                      tuples, or None.
        :param: notes: The description (1024 characters).
        :param: subgroups: With paths: include the subgroups (True).
        """
        self.name = name
        self.notes = notes or ''
        self.groups = groups if isinstance(groups, SystemGroups) else SystemGroups(groups, subgroups)
        if tags is not None and not isinstance(tags, RuleTagCriteria):
            tags = RuleTagCriteria(tags)
        self.tags = tags if tags is not None else RuleTagCriteria()
        self.policies = []
        for policy in policies or []:
            self.add_policy(policy)
        # Kept as read from a file: assignmentMethod, and the expressions of
        # a rule the wizard can't show (User Based rule).
        self.assignment_method = SYSTEM_BASED
        self.raw_system_expression = None
        self.raw_user_expression = None

    def __repr__(self):
        """
        Shows the name and the number of policies.
        """
        count = len(self.policies)
        return '<AssignmentRule {}: {} polic{}>'.format(self.name, count,
                                                       'y' if count == 1 else 'ies')

    @property
    def user_based(self):
        """
        True for a User Based rule (read from a file: written back unchanged,
        not editable).
        """
        return self.assignment_method != SYSTEM_BASED

    def add_policy(self, policy, type_id=None, feature_id=None):
        """
        Adds a policy to assign: a PolicyAssignment, a Policy of the
        library, or its name, typeid and featureid. One policy per category
        except the "(Multi-slot)" categories, as in the console.

        >>> rule = AssignmentRule('R', 'Workstations')
        >>> rule.add_policy('A', 'General', 'EPOAGENTMETA').add_policy('B', 'General', 'EPOAGENTMETA')
        Traceback (most recent call last):
        ValueError: The rule already assigns a policy of category EPOAGENTMETA / General (not multi-slot).

        :return: The rule (to chain the calls).
        """
        if isinstance(policy, PolicyAssignment):
            assignment = policy
        elif isinstance(policy, (tuple, list)):
            assignment = PolicyAssignment(*policy)
        elif isinstance(policy, str):
            assignment = PolicyAssignment(policy, type_id, feature_id)
        else:
            assignment = PolicyAssignment.from_policy(policy)
        if assignment in self.policies:
            raise ValueError('The rule already assigns policy {}.'.format(assignment.name))
        if not assignment.multi_slot and \
                any(item.category == assignment.category for item in self.policies):
            raise ValueError('The rule already assigns a policy of category {} / {} '
                             '(not multi-slot).'.format(*assignment.category))
        self.policies.append(assignment)
        return self

    def remove_policy(self, name, type_id=None):
        """
        Removes the policies of this name (and of this category if given).

        >>> AssignmentRule('R', 'W', [('A', 'General', 'EPOAGENTMETA')]).remove_policy('A')
        <AssignmentRule R: 0 policies>
        """
        self.policies = [item for item in self.policies
                         if not (item.name == name and type_id in (None, item.type_id))]
        return self

    def check(self):
        """
        Checks the rule as the console wizard does before a save.

        :raise: ValueError: Empty name, name longer than 128 characters,
                            notes longer than 1024 characters, no policy.
        """
        if not self.name or not self.name.strip():
            raise ValueError('A rule name is required.')
        if len(self.name) > MAX_RULE_NAME:
            raise ValueError('Rule name longer than {} characters (console limit).'
                             .format(MAX_RULE_NAME))
        if len(self.notes) > MAX_NOTES:
            raise ValueError('Rule notes longer than {} characters (console limit).'
                             .format(MAX_NOTES))
        if not self.policies:
            raise ValueError('Rule {} assigns no policy.'.format(self.name))

    def system_expression(self):
        """
        Returns the systemExpression (the text read from the file for a
        rule the wizard can't show).
        """
        if self.raw_system_expression is not None:
            return self.raw_system_expression
        return self.groups.to_squid()

    def user_expression(self):
        """
        Returns the userExpression: the tag criteria of a System Based rule
        (the text read from the file for a User Based rule).
        """
        if self.raw_user_expression is not None:
            return self.raw_user_expression
        return self.tags.to_squid()

    def to_xml(self, rule_id):
        """
        Returns the EPOPolicyRule element as the console exports it.

        :param: rule_id: The id attribute (not used by the import).
        """
        text = ('<EPOPolicyRule name="{}" id="{}" systemExpression="{}" assignmentMethod="{}" '
                'userExpression="{}" notes="{}">{}').format(
                    _attr(self.name), rule_id, _attr(self.system_expression()),
                    _attr(self.assignment_method), _attr(self.user_expression()),
                    _attr(self.notes), _EOL)
        text += ''.join(policy.to_xml() for policy in self.policies)
        return text + '</EPOPolicyRule>' + _EOL

    @classmethod
    def from_element(cls, element):
        """
        Returns the rule of an EPOPolicyRule element. The expressions the
        wizard can't show are kept as read.
        """
        system = element.get('systemExpression', '')
        user = element.get('userExpression', '')
        try:
            groups = SystemGroups.from_squid(system)
            raw_system = None
        except ValueError:
            groups, raw_system = SystemGroups(ROOT_GROUP), system
        method = element.get('assignmentMethod', SYSTEM_BASED)
        tags, raw_user = RuleTagCriteria(), None
        if method == SYSTEM_BASED:
            try:
                tags = RuleTagCriteria.from_squid(user)
            except ValueError:
                raw_user = user
        else:
            raw_user = user
        rule = cls(element.get('name'), groups, tags=tags, notes=element.get('notes', ''))
        rule.policies = [PolicyAssignment.from_element(item)
                         for item in element.findall('EPOPolicyRuleAssignment')]
        rule.assignment_method = method
        rule.raw_system_expression = raw_system
        rule.raw_user_expression = raw_user
        return rule


class AssignmentRuleList():
    """
    The rules of a Policy Assignment Rules export, or a new list to import
    in the console (Actions > Import).

    >>> rules = AssignmentRuleList()
    >>> rules.add(AssignmentRule('R', 'Workstations', [('A', 'General', 'EPOAGENTMETA')]))
    >>> rules
    <AssignmentRuleList of 1 rule(s)>
    """

    def __init__(self, xml=None):
        """
        :param: xml: The XML of the console export (bytes or text), or None
                     for an empty list.
        """
        self.rules = []
        if xml is not None:
            text = xml.decode('utf-8') if isinstance(xml, bytes) else xml
            root = et.fromstring(_keep_line_ends(text).encode('utf-8'))
            if root.tag != '{%s}EPOPolicyRuleSchema' % NAMESPACE:
                raise ValueError('Not a Policy Assignment Rules file: {}'.format(root.tag))
            self.rules = [AssignmentRule.from_element(element)
                          for element in root.findall('EPOPolicyRule')]

    def __repr__(self):
        """
        Shows the number of rules.
        """
        return '<AssignmentRuleList of {} rule(s)>'.format(len(self.rules))

    def __iter__(self):
        """
        Iterates over the rules.
        """
        return iter(self.rules)

    def __len__(self):
        """
        Returns the number of rules.
        """
        return len(self.rules)

    def get(self, name):
        """
        Returns the rule of this name, or None.
        """
        for rule in self.rules:
            if rule.name == name:
                return rule
        return None

    def add(self, rule):
        """
        Adds a rule, or replaces the rule of the same name (as the import
        does).
        """
        rule.check()
        for index, item in enumerate(self.rules):
            if item.name == rule.name:
                self.rules[index] = rule
                return
        self.rules.append(rule)

    def remove(self, name):
        """
        Removes the rule of this name.
        """
        self.rules = [rule for rule in self.rules if rule.name != name]

    def get_xml_content_str(self):
        """
        Returns the file as the console exports it (text, CRLF line ends).
        The rule ids are numbered from 1 (the import doesn't use them).
        """
        text = ('<?xml version="1.0" encoding="UTF-8"?>' + _EOL +
                '<epo:EPOPolicyRuleSchema xmlns:epo="{}" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'.format(NAMESPACE) + _EOL)
        for index, rule in enumerate(self.rules, 1):
            text += rule.to_xml(index)
        return text + '</epo:EPOPolicyRuleSchema>'

    def get_xml_content(self):
        """
        Returns the file to import (UTF-8 bytes, as the console export).
        """
        for rule in self.rules:
            rule.check()
        return self.get_xml_content_str().encode('utf-8')

    def check_server(self, epo):
        """
        Checks the names of the rules against an ePO server (read only):
        System Tree groups, tags and policies. The console import refuses a
        file with an unknown group or policy ("Policy rules could not be
        imported because the uploaded file is either corrupt..."), and
        imports a rule with an unknown tag without its tag criteria: the
        rule then applies to every system of its groups (checked on ePO
        5.10 Update 7).

        :param: epo: An EPOClient.
        :return: The problems found, one text per problem ([] when the
                 file can be imported as written).
        """
        groups = {item['groupPath'].lower() for item in epo.call('system.findGroups')}
        tags = {item['tagName'].lower() for item in epo.call('system.findTag')}
        policies = {(item['featureId'], item['typeName'].lower(), item['objectName'])
                    for item in epo.call('policy.find')}
        named = {(feature, name) for feature, _, name in policies}
        problems = []
        for rule in self.rules:
            if rule.raw_system_expression is None:
                for path in rule.groups.paths:
                    if path.lower() not in groups:
                        problems.append('Rule "{}": System Tree group "{}" not found (the import '
                                        'fails).'.format(rule.name, path))
            if rule.raw_user_expression is None:
                for tag, _ in rule.tags.conditions:
                    if tag.lower() not in tags:
                        problems.append('Rule "{}": tag "{}" not found (the import drops the tag '
                                        'criteria).'.format(rule.name, tag))
            for policy in rule.policies:
                labels = policy.labels
                found = (policy.feature_id, labels[1].lower(), policy.name) in policies \
                    if labels else (policy.feature_id, policy.name) in named
                if not found:
                    problems.append('Rule "{}": policy "{}" ({} / {}) not found (the import '
                                    'fails).'.format(rule.name, policy.name, policy.feature_id,
                                                     policy.type_id))
        return problems

    def save_to_file(self, file_path):
        """
        Writes the file to import in the console.
        """
        with open(file_path, 'wb') as xml_file:
            xml_file.write(self.get_xml_content())

    @classmethod
    def load_from_file(cls, file_path):
        """
        Reads a file of the console export.
        """
        with open(file_path, 'rb') as xml_file:
            return cls(xml_file.read())

    def to_markdown(self):
        """
        Returns the rules as a Markdown table (one line per rule; the
        policies by product and category as the wizard shows them).

        >>> rules = AssignmentRuleList()
        >>> rules.add(AssignmentRule('R', 'Workstations', [('A', 'General', 'EPOAGENTMETA')], ['S']))
        >>> print(rules.to_markdown())   # doctest: +NORMALIZE_WHITESPACE
        | Rule | Systems | Tags | Policies |
        |---|---|---|---|
        | R | My Organization\\Workstations and subgroups | Has tag S | Trellix Agent / General: A |
        """
        def cell(text):
            """
            Escapes the Markdown table separators.

            >>> cell('a|b')
            'a\\\\|b'
            """
            return text.replace('|', '\\|').replace('\n', ' ')

        lines = ['| Rule | Systems | Tags | Policies |', '|---|---|---|---|']
        for rule in self.rules:
            if rule.raw_system_expression is not None:
                systems = rule.raw_system_expression
            else:
                systems = ' or '.join(rule.groups.paths) + (
                    ' and subgroups' if rule.groups.subgroups else '')
            tags = rule.raw_user_expression if rule.raw_user_expression is not None \
                else str(rule.tags)
            policies = '<br>'.join('{} / {}: {}'.format(*(item.labels or item.category), item.name)
                                   for item in rule.policies)
            lines.append('| {} | {} | {} | {} |'.format(cell(rule.name), cell(systems),
                                                        cell(tags or '-'), cell(policies)))
        return '\n'.join(lines)
