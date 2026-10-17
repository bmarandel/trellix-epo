# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the Class objects SCRuleGroups, SCRuleGroup, SCAWLRuleGroup,
SCCCRuleGroup and SCFIMRuleGroup, for the Solidcore Rule Groups managed in the
ePO console under Menu > Configuration > Solidcore Rules.

Rule Groups are exported and imported with the ePO API, not with the policies:
    scor.rulegroup.export <WIN|UNIX> <APPLICATION_CONTROL|CHANGE_CONTROL|INTEGRITY_MONITOR>
                          [ruleGroupName=<name>]
    scor.rulegroup.import file=<file.xml> [override=true]
Without ruleGroupName, the export only contains the user defined (editable)
Rule Groups. On import, a Rule Group whose name doesn't exist yet is created
(as user defined); an existing one is only replaced with override=true,
otherwise the import fails (check the "Import Solidcore Rule Groups" server
task: the API answers success even then).

A Rule Group is used by a policy through SCPolicy.add_rule_group(): ePO links
the policy to the Rule Group by its name, so the Rule Group must be imported
before the policy.
"""

import copy
import xml.etree.ElementTree as et
from ..policies import Policy, XmlObject, md_document
from ..policycatalog import CATEGORIES
from .rules import SCRules
from .awl import SCAWLRules
from .cc import SCCCRules
from .fim import SCFIMRules


# Console labels of the Rule Group types and platforms (Menu > Configuration >
# Solidcore Rules).
TYPE_LABELS = {'application_control': 'Application Control', 'change_control': 'Change Control',
               'mon': 'Integrity Monitor'}
PLATFORM_LABELS = {'WIN': 'Windows', 'UNIX': 'Unix'}


def rule_group_users(policies):
    """
    Returns the Solidcore policies using each shared Rule Group: {(type,
    platform, name): ['<policy name> (<policy category>)', ...]}, from a
    Solidcore policy export (SCPolicies, policy.export productId=SOLIDCORE_META)
    or a list of SCPolicy. A policy refers to a Rule Group by its name, type
    and platform (its scor_info section).

    >>> rule_group_users([])
    {}
    """
    from .scpolicies import SCPolicies, SCPolicy
    if isinstance(policies, SCPolicies):
        policies = [SCPolicy(policies.get_policy(row['typeid'], row['name']))
                    for row in policies.list()]
    users = {}
    for policy in policies:
        policy_obj = policy.root.find('EPOPolicyObject')
        labels = CATEGORIES.get((policy_obj.get('featureid'), policy_obj.get('typeid')))
        label = '{} ({})'.format(policy.get_name(), labels[1] if labels else
                                 policy_obj.get('typeid'))
        for group in policy.get_rule_groups():
            if group['shared']:
                key = (group['group_type'], group['platforms'], group['group_name'])
                users.setdefault(key, []).append(label)
    return {key: sorted(set(value), key=str.lower) for key, value in users.items()}


def check_rule_group_name(name):
    """
    Raise ValueError if the console refuses a Rule Group name (Add and
    Rename dialogs, scor.utils.validateRuleGroupName): required, not
    starting with @ = + - or | (spreadsheet formula characters).
    """
    if not isinstance(name, str) or not name.strip():
        raise ValueError('A Rule Group needs a name.')
    if name[0] in '@=+-|':
        raise ValueError('A Rule Group name cannot start with @ = + - or |: {!r}'.format(name))
    return name

class SCRuleGroup(SCRules):
    """
    SCRuleGroup is the base class object for one Solidcore Rule Group of a
    SCRuleGroups export. The rules are stored as <Rule><Content name value/></Rule>
    and edited with the same methods as the policies (see SCRules).
    """

    def __init__(self, rule_group_obj):
        self.root = rule_group_obj

    def __repr__(self):
        """
        Shows the class, the name, the type and platform and the number of
        rules, as the policies do, e.g. <SCAWLRuleGroup 'Docker' (Application
        Control, Windows): 12 rules>.
        """
        info = self.get_info()
        return '<{} {!r} ({}, {}): {} rule{}>'.format(
            type(self).__name__, info['name'], info['type'], info['platform'], info['rules'],
            '' if info['rules'] == 1 else 's')

    def get_info(self):
        """
        Returns what the Rule Group holds: name, type and platform (console
        labels), origin (predefined by Trellix or user defined) and the
        number of rules.

        Example: {'name': 'Docker', 'type': 'Application Control', 'platform':
        'Windows', 'origin': 'User defined', 'rules': 12}.
        """
        return {'name': self.get_name(),
                'type': TYPE_LABELS.get(self.get_type(), self.get_type()),
                'platform': PLATFORM_LABELS.get(self.get_platform(), self.get_platform()),
                'origin': 'Predefined by Trellix (read-only)' if self.is_read_only()
                          else 'User defined',
                'rules': sum(1 for _ in self._iter_rules())}

    def md_properties(self, users=None):
        """
        Returns the "Property | Value" rows of the Rule Group (type,
        platform, origin, number of rules and, when users is given, the
        policies using it).

        :param: users: The result of rule_group_users() (None: not shown).
        """
        info = self.get_info()
        rows = [['Rule Group type', info['type']], ['Platform', info['platform']],
                ['Origin', info['origin']], ['Rules', str(info['rules'])]]
        if users is not None:
            used = users.get((self.get_type(), self.get_platform(), self.get_name()), [])
            rows.append(['Used by policies', ', '.join(used) or 'None'])
        return rows

    def md_sections(self, users=None):
        """
        Returns the sections of the Rule Group document: its properties,
        then its rules as the tabs of the console (see md_tabs() of the
        rules classes, the same tables as in the policies).
        """
        return [('Rule Group', Policy.md_table(['Property', 'Value'], self.md_properties(users))),
                ('Rules', self.md_tabs())]

    def to_markdown(self, policies=None, author='', reviewers=None):
        """
        Returns a Markdown document of the Rule Group, laid out as the policy
        documents (header, contents, sections, document control).

        Example: groups.get_rule_group('Docker').to_markdown(
        epo.export_policies('SOLIDCORE_META')).

        :param: policies: A Solidcore policy export (SCPolicies) or a list of
                          SCPolicy, to list the policies using the Rule Group.
        :param: author: The name written in the document control section.
        :param: reviewers: The names of the review/approval table.
        """
        info = self.get_info()
        users = rule_group_users(policies) if policies is not None else None
        return md_document(info['name'], 'Solidcore - {} Rule Group ({})'.format(
            info['type'], info['platform']), [
                ['Product', 'Solidcore'], ['Rule Group type', info['type']],
                ['Platform', info['platform']], ['Rule Group name', info['name']]],
            self.md_sections(users), author, reviewers)

    def save_markdown(self, file_path, policies=None, author='', reviewers=None):
        """
        Writes the Markdown document of the Rule Group (see to_markdown()).
        """
        with open(file_path, 'w', encoding='utf-8') as output:
            output.write(self.to_markdown(policies, author, reviewers))

    def get_name(self):
        """
        Returns the name of the Rule Group.
        """
        return self.root.get('name')

    def get_type(self):
        """
        Returns the type of the Rule Group: 'application_control', 'change_control'
        or 'mon' (Integrity Monitor).
        """
        return self.root.get('type')

    def get_platform(self):
        """
        Returns the platform of the Rule Group: 'WIN' or 'UNIX'.
        """
        return self.root.get('platform')

    def is_read_only(self):
        """
        Returns True for a Rule Group predefined by Trellix (not editable in the
        console), False for a user defined Rule Group.
        """
        return self.root.get('is-read-only') == 'true'

    def is_unix(self):
        """
        Returns True for a Unix Rule Group.
        """
        return self.get_platform() == 'UNIX'

    # ------------------------------ Rules storage (see SCRules) ------------------------------
    def _iter_rules(self, all_groups=False):
        for rule_obj in self.root.findall('Rule'):
            yield rule_obj, {c.get('name'): c.get('value') for c in rule_obj.findall('Content')}

    def _append_rule(self, rule):
        rule_obj = et.SubElement(self.root, 'Rule')
        # ePO exports the type first.
        for key in ['type'] + sorted(k for k in rule if k != 'type'):
            et.SubElement(rule_obj, 'Content', {'name': key, 'value': rule[key]})
        return True

    def _update_rule(self, handle, values):
        for key, value in values.items():
            content_obj = handle.find('Content[@name="{}"]'.format(key))
            if content_obj is None:
                et.SubElement(handle, 'Content', {'name': key, 'value': value})
            else:
                content_obj.set('value', value)

    def _remove_rule(self, handle):
        self.root.remove(handle)


class SCAWLRuleGroup(SCAWLRules, SCRuleGroup):
    """
    The SCAWLRuleGroup class can be used to edit a Solidcore Application Control
    Rule Group, with the same methods as the Application Control Rules policy
    tabs (see SCAWLRules).
    """


class SCCCRuleGroup(SCCCRules, SCRuleGroup):
    """
    The SCCCRuleGroup class can be used to edit a Solidcore Change Control Rule
    Group, with the same methods as the Change Control Rules policy tabs (see
    SCCCRules).
    """


class SCFIMRuleGroup(SCFIMRules, SCRuleGroup):
    """
    The SCFIMRuleGroup class can be used to edit a Solidcore Integrity Monitor
    Rule Group, with the same methods as the Integrity Monitoring Rules policy
    tabs (see SCFIMRules).
    """


class SCRuleGroups(XmlObject):
    """
    SCRuleGroups is a class object containing Solidcore Rule Groups, as exported by
    the ePO API (scor.rulegroup.export) and imported with scor.rulegroup.import.
    """

    # Rule Group types (the "type" attribute) and platforms.
    APPLICATION_CONTROL = 'application_control'
    CHANGE_CONTROL = 'change_control'
    INTEGRITY_MONITOR = 'mon'
    WINDOWS = 'WIN'
    UNIX = 'UNIX'

    __CLASSES = {APPLICATION_CONTROL: SCAWLRuleGroup, CHANGE_CONTROL: SCCCRuleGroup,
                 INTEGRITY_MONITOR: SCFIMRuleGroup}

    def __init__(self, xml_rule_groups=None):
        """
        :param: xml_rule_groups: The XML returned by scor.rulegroup.export, or None
                                 to start an empty file (e.g. to create new Rule Groups).
        """
        super(SCRuleGroups, self).__init__()
        if xml_rule_groups is not None:
            self.set_xml_content(xml_rule_groups)
            if self.root.tag != 'Rule-Groups':
                raise ValueError('Not a Solidcore Rule Groups export (root must be "Rule-Groups").')
        else:
            self.root = et.Element('Rule-Groups')
            et.SubElement(self.root, 'Active-Directories')

    def __repr__(self):
        """
        Shows the number of Rule Groups, e.g. <SCRuleGroups: 5 rule groups>.
        """
        number = len(self.root.findall('Rule-Group'))
        return '<SCRuleGroups: {} rule group{}>'.format(number, '' if number == 1 else 's')

    def get_info(self):
        """
        Returns the number of Rule Groups by type and platform, e.g.
        {'rule_groups': 5, 'types': {'Application Control (Windows)': 5}}.
        """
        types = {}
        for group in self.root.findall('Rule-Group'):
            key = '{} ({})'.format(TYPE_LABELS.get(group.get('type'), group.get('type')),
                                   PLATFORM_LABELS.get(group.get('platform'), group.get('platform')))
            types[key] = types.get(key, 0) + 1
        return {'rule_groups': sum(types.values()), 'types': types}

    def to_markdown(self, policies=None, title='Solidcore Rule Groups', author='', reviewers=None):
        """
        Returns a Markdown document of all the Rule Groups of the export: a
        summary table (Menu > Configuration > Solidcore Rules), then one
        section per Rule Group with its properties and its rules.

        Example: SCRuleGroups(epo.export_rule_group(SCRuleGroups.WINDOWS,
        SCRuleGroups.APPLICATION_CONTROL)).to_markdown(epo.export_policies('SOLIDCORE_META')).

        :param: policies: A Solidcore policy export (SCPolicies) or a list of
                          SCPolicy, to list the policies using each group.
        """
        users = rule_group_users(policies) if policies is not None else None
        groups = [self.get_rule_group(row['name']) for row in self.list()]
        summary = Policy.md_table(
            ['Rule Group', 'Type', 'Platform', 'Origin', 'Rules'] +
            (['Used by policies'] if users is not None else []),
            [[info['name'], info['type'], info['platform'], info['origin'], str(info['rules'])] +
             ([', '.join(users.get((group.get_type(), group.get_platform(), group.get_name()),
                                   [])) or 'None'] if users is not None else [])
             for group, info in ((group, group.get_info()) for group in groups)],
            numbered=True)
        sections = [('Rule Groups', summary)]
        for group in groups:
            body = Policy.md_table(['Property', 'Value'], group.md_properties(users))
            sections.append((group.get_name(), body + '\n' + group.md_tabs()))
        info = self.get_info()
        return md_document(title, 'Solidcore - Rule Groups', [
            ['Product', 'Solidcore'], ['Rule Groups', str(info['rule_groups'])]] +
            [[label, str(number)] for label, number in sorted(info['types'].items())],
            sections, author, reviewers)

    def save_markdown(self, file_path, policies=None, title='Solidcore Rule Groups', author='',
                      reviewers=None):
        """
        Writes the Markdown document of the Rule Groups (see to_markdown()).
        """
        with open(file_path, 'w', encoding='utf-8') as output:
            output.write(self.to_markdown(policies, title, author, reviewers))

    def __find(self, name):
        for rule_group_obj in self.root.findall('Rule-Group'):
            if rule_group_obj.get('name') == name:
                return rule_group_obj
        return None

    def __wrap(self, rule_group_obj):
        return self.__CLASSES.get(rule_group_obj.get('type'), SCRuleGroup)(rule_group_obj)

    def __insert(self, rule_group_obj):
        # Keep the Active-Directories element at the end, as ePO does.
        index = len(self.root)
        for i, child in enumerate(self.root):
            if child.tag != 'Rule-Group':
                index = i
                break
        self.root.insert(index, rule_group_obj)

    def list(self):
        """
        Returns the list of Rule Groups, as dicts {'name', 'type', 'platform',
        'read_only'}, sorted by name.
        """
        rule_groups = [{'name': g.get('name'), 'type': g.get('type'),
                        'platform': g.get('platform'),
                        'read_only': g.get('is-read-only') == 'true'}
                       for g in self.root.findall('Rule-Group')]
        return sorted(rule_groups, key=lambda g: g['name'])

    def contain(self, name):
        """
        Returns True if the export contains a Rule Group with this name.
        """
        return self.__find(name) is not None

    def get_rule_group(self, name):
        """
        Returns a Rule Group (SCAWLRuleGroup, SCCCRuleGroup or SCFIMRuleGroup,
        according to its type), or None. Changes made to it are saved with
        this SCRuleGroups object.
        """
        rule_group_obj = self.__find(name)
        return self.__wrap(rule_group_obj) if rule_group_obj is not None else None

    def new_rule_group(self, name, group_type, platform):
        """
        Adds a new, empty, user defined Rule Group, as the "Add Rule Group" button
        of the ePO console does.

        :param: group_type: APPLICATION_CONTROL, CHANGE_CONTROL or INTEGRITY_MONITOR.
        :param: platform: WINDOWS or UNIX.
        :return: The new Rule Group.
        """
        if group_type not in self.__CLASSES:
            raise ValueError('Rule Group type must be "{}".'.format('", "'.join(self.__CLASSES)))
        if platform not in (self.WINDOWS, self.UNIX):
            raise ValueError('Rule Group platform must be "WIN" or "UNIX".')
        check_rule_group_name(name)
        if self.contain(name):
            raise ValueError('A Rule Group named "{}" already exists.'.format(name))
        rule_group_obj = et.Element('Rule-Group', {'is-read-only': 'false', 'name': name,
                                                   'platform': platform, 'type': group_type})
        self.__insert(rule_group_obj)
        return self.__wrap(rule_group_obj)

    def copy_rule_group(self, rule_group, new_name):
        """
        Adds a user defined copy of a Rule Group (e.g. of a Rule Group predefined
        by Trellix), as the "Duplicate" action of the ePO console does.

        :param: rule_group: The name of a Rule Group of this export, or a
                            SCRuleGroup (possibly from another SCRuleGroups export).
        :param: new_name: The name of the copy.
        :return: The new Rule Group, or None if rule_group doesn't exist.
        """
        if isinstance(rule_group, SCRuleGroup):
            rule_group_obj = rule_group.root
        else:
            rule_group_obj = self.__find(rule_group)
        if rule_group_obj is None:
            return None
        check_rule_group_name(new_name)
        if self.contain(new_name):
            raise ValueError('A Rule Group named "{}" already exists.'.format(new_name))
        new_obj = copy.deepcopy(rule_group_obj)
        new_obj.set('name', new_name)
        new_obj.set('is-read-only', 'false')
        self.__insert(new_obj)
        return self.__wrap(new_obj)

    def add_rule_group(self, rule_group):
        """
        Adds a copy of a Rule Group of another export as it is (name, type,
        platform, predefined or user defined), e.g. to gather in one object
        the Rule Groups exported one by one (scor.rulegroup.export with a
        name, the only way to export the predefined ones). Use
        copy_rule_group() for a user defined copy under another name.

        :param: rule_group: A SCRuleGroup.
        :return: The added Rule Group.
        :raise: ValueError: A Rule Group of this name is in the export.

        >>> groups = SCRuleGroups()
        >>> other = SCRuleGroups().new_rule_group('Apps', SCRuleGroups.APPLICATION_CONTROL,
        ...                                       SCRuleGroups.WINDOWS)
        >>> groups.add_rule_group(other)
        <SCAWLRuleGroup 'Apps' (Application Control, Windows): 0 rules>
        """
        if self.contain(rule_group.get_name()):
            raise ValueError('A Rule Group named "{}" already exists.'.format(rule_group.get_name()))
        new_obj = copy.deepcopy(rule_group.root)
        self.__insert(new_obj)
        return self.__wrap(new_obj)

    def rename_rule_group(self, name, new_name):
        """
        Renames a user defined Rule Group of the export (the Rule Groups
        predefined by Trellix can't be renamed).

        Note: importing the renamed export creates a new Rule Group in ePO
        (Rule Groups are identified by their name). To rename a Rule Group in
        ePO, use the API: scor.rulegroup.rename <WIN|UNIX>
        <APPLICATION_CONTROL|CHANGE_CONTROL|INTEGRITY_MONITOR> <name> <new_name>;
        ePO then renames it in the policies using it too (checked on the ePO
        5.10 lab), see SCPolicy.rename_rule_group() for older policy exports.

        :return: The renamed Rule Group, or None if name doesn't exist.
        """
        rule_group_obj = self.__find(name)
        if rule_group_obj is None:
            return None
        if rule_group_obj.get('is-read-only') == 'true':
            raise ValueError('Rule Group "{}" is predefined by Trellix and can\'t be '
                             'renamed.'.format(name))
        check_rule_group_name(new_name)
        if new_name != name and self.contain(new_name):
            raise ValueError('A Rule Group named "{}" already exists.'.format(new_name))
        rule_group_obj.set('name', new_name)
        return self.__wrap(rule_group_obj)

    def remove_rule_group(self, name):
        """
        Removes a Rule Group from the export (to leave it out of the next import;
        it is not deleted from ePO).
        """
        rule_group_obj = self.__find(name)
        if rule_group_obj is None:
            return False
        self.root.remove(rule_group_obj)
        return True
