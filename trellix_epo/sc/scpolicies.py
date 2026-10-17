# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the Class objects SCPolicies and SCPolicy.

SCPolicies can be used to store Solidcore (Trellix Application and Change
Control) policies exported from ePolicy Orchestrator manually or through the
API (policy.export productId=SOLIDCORE_META).

SCPolicy is the base Class object for every Solidcore policy. Unlike the other
products of this package, Solidcore doesn't store its settings under named
Sections: every setting is a "rule", stored in a Section named
"General_Rule_<n>" (or "General_<n>", kept by the Solidcore 8.4 console for
the trusted directories of some policies) whose number is meaningless
(numbering can have gaps). A
rule is identified by its content instead - its "type" Setting plus, for most
types, a "name" or "pattern" Setting. SCPolicy therefore exposes rules as
plain dicts ({setting name: value}) and finds them by content.

A Solidcore policy is also made of one or more "rule groups" (one
EPOPolicySettings each, described by a "scor_info" Section):
  - the policy's own rules ("My Rules"), the only group edited by this
    package;
  - shared Rule Groups (readOnly="true"), managed in the ePO console under
    Menu > Configuration > Solidcore Rules, and only referenced by the policy.
Note: the Exception Rules policies flag their own rules (group "Attributes",
group_type "attr") as readOnly="true" too, so they are not considered shared.
"""

import re
import uuid
import xml.etree.ElementTree as et
from ..policies import Policies, Policy
from .rules import SCRules

class SCPolicies(Policies):
    """
    SCPolicies is a class object containing the Solidcore policies returned by the ePO API.
    """

    def __init__(self, xml_policies=None):
        super(SCPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if not self.get_product().startswith('SCOR_'):
                raise ValueError('Wrong McAfee Product. Policies must come from "SOLIDCORE_META".')

    def new_policy(self, type_id, name, template='My Default'):
        """
        Returns a new Policy with a policy name (name) for a specific type (type_id),
        inherited from a template.

        Only the policy's own rules settings are renamed: the shared Rule
        Groups it references keep their name, so that the new
        policy still references the same Rule Groups once imported into ePO.
        """
        policy = self.get_policy(type_id, template)
        if policy is not None:
            policy_obj = policy.find('EPOPolicyObject')
            policy_obj.set('name', name)
            for policy_set in policy_obj.findall('PolicySettings'):
                settings_obj = policy.find('EPOPolicySettings[@name="{}"]'.format(policy_set.text))
                if settings_obj is None or SCPolicy.is_shared_group(settings_obj):
                    continue
                policy_ref = '{}::Settings ({})'.format(name, str(uuid.uuid4()).upper())
                policy_set.text = policy_ref
                settings_obj.set('name', policy_ref)
        return policy

    def new_empty_policy(self, type_id, name):
        """
        Returns a new, empty policy (no rule, no Rule Group) with a policy name
        (name) for a Rules policy type (e.g. 'AWL Rules (Windows)', 'CC Rules
        (Unix)', 'Mon Rules (Windows)', 'Attr Rules (Windows)'), like a copy of
        the ePO "Blank Template" policy - which can't be exported, as ePO
        doesn't export read-only policies.

        Any policy of the same type of the export is used as a template.

        :return: The new policy, or None if the export has no policy of this type.
        """
        names = [row['name'] for row in self.list() if row['typeid'] == type_id]
        if not names:
            return None
        policy = self.new_policy(type_id, name, template=names[0])
        rules = SCPolicy(policy)
        for group_name in rules.get_rule_group_names():
            rules.remove_rule_group(group_name)
        for rule_type in set(rule['type'] for rule in rules.get_rules()):
            rules.remove_rules(rule_type)
        description_obj = policy.find('EPOPolicyObject/description')
        if description_obj is not None:
            description_obj.text = None
        return policy

class SCPolicy(SCRules, Policy):
    """
    SCPolicy is the base class object for all Solidcore policies. It gives access to
    the policy's rules, stored as dicts {setting name: value} (see SCRules), and
    to the shared Rule Groups referenced by the policy.
    """

    # The ePO policy type(s) (typeid) accepted by the subclass.
    TYPE_IDS = ()

    def __init__(self, policy_from_scpolicies):
        super(SCPolicy, self).__init__(policy_from_scpolicies)
        if self.TYPE_IDS and self.get_type() not in self.TYPE_IDS:
            raise ValueError('Wrong Solidcore policy. Policy type must be {}.'.format(
                ' or '.join('"{}"'.format(t) for t in self.TYPE_IDS)))

    def _info_counts(self):
        """
        The counts of get_info() and of the representation: the rules and the Rule Groups used.
        """
        return {'rules': len(self.get_rules()), 'rule_groups': len(self.get_rule_group_names())}

    # ------------------------------ Markdown export ------------------------------
    # Product name of the ePO Policy Catalog ("Solidcore 8.4.5", without its
    # version). Each class sets MD_CATEGORY and md_sections() (console labels).
    MD_PRODUCT = 'Solidcore'

    @staticmethod
    def md_flag(value):
        """
        Returns the label of a Solidcore checkbox stored as '1'/'0' or
        'true'/'false' ('Yes'/'No'), None if missing.
        """
        if value is None:
            return None
        return 'Yes' if str(value).lower() in ['1', 'true'] else 'No'

    def md_group(self, title, rows):
        """
        Returns a "###" group box with its "Setting | Value" table.
        """
        return '### {}\n\n{}'.format(title, self.md_settings(rows))

    def md_rule_group_sections(self, tabs):
        """
        Returns the sections of a rules policy: the Rule Groups list of the
        console (My Rules, then the shared Rule Groups), then one section per
        rule group with its tabs (tabs: method returning the tabs of the
        rules currently read, see md_tabs() of the rules classes).
        """
        groups = self.get_rule_groups()
        own = [g for g in groups if not g['shared']]
        shared = [g for g in groups if g['shared']]
        text = 'The policy rules are the rules of all its rule groups: its own rules ' \
               '(My Rules) and the shared Rule Groups (Menu > Configuration > Solidcore ' \
               'Rules), listed below.\n\n'
        text += self.md_table(['Rule Group', 'Kind'],
                              [['My Rules', 'Policy rules']] +
                              [[g['group_name'], 'Shared Rule Group'] for g in shared],
                              numbered=True)
        sections = [('Rule Groups', text)]
        by_name = {settings_obj.get('name'): settings_obj for settings_obj in self.__settings_list()}
        for group in own + shared:
            self._md_view = by_name[group['settings']]
            try:
                body = tabs()
            finally:
                self._md_view = None
            heading = 'My Rules' if not group['shared'] else 'Rule Group: {}'.format(
                group['group_name'])
            sections.append((heading, body))
        return sections

    # ------------------------------ Rule groups ------------------------------
    # group_type values of the policy's own rules flagged as readOnly="true".
    OWN_READ_ONLY_GROUP_TYPES = ('attr',)

    @staticmethod
    def is_shared_group(settings_obj):
        """
        Returns True if an EPOPolicySettings element is a shared Rule Group
        (only referenced by the policy, not editable from it).
        """
        info = {s.get('name'): s.get('value')
                for s in settings_obj.findall('Section[@name="scor_info"]/Setting')}
        return (info.get('readOnly') == 'true' and
                info.get('group_type') not in SCPolicy.OWN_READ_ONLY_GROUP_TYPES)

    def __settings_list(self):
        policy_obj = self.root.find('EPOPolicyObject')
        names = [p.text for p in policy_obj.findall('PolicySettings')]
        return [s for s in self.root.findall('EPOPolicySettings') if s.get('name') in names]

    def __my_rules(self):
        for settings_obj in self.__settings_list():
            if not self.is_shared_group(settings_obj):
                return settings_obj
        return None

    def get_rule_groups(self):
        """
        Returns the list of rule groups used by the policy, as dicts with the keys:
        'settings' (EPOPolicySettings name), 'group_name', 'group_type', 'platforms'
        and 'shared' (True for a shared Rule Group, False for the policy's own rules).
        """
        groups = []
        for settings_obj in self.__settings_list():
            info = self.__section_to_dict(settings_obj.find('Section[@name="scor_info"]'))
            groups.append({'settings': settings_obj.get('name'),
                           'group_name': info.get('group_name'),
                           'group_type': info.get('group_type'),
                           'platforms': info.get('platforms'),
                           'shared': self.is_shared_group(settings_obj)})
        return groups

    def get_rule_group_names(self):
        """
        Returns the names of the shared Rule Groups referenced by the policy.
        """
        return [g['group_name'] for g in self.get_rule_groups() if g['shared']]

    def remove_rule_group(self, group_name):
        """
        Removes the reference to a shared Rule Group from the policy. The Rule Group
        itself is not deleted from ePO.

        :param: group_name: The name of the Rule Group (as shown in the console).
        :return: True if the Rule Group was found and removed.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        for settings_obj in self.__settings_list():
            info = self.__section_to_dict(settings_obj.find('Section[@name="scor_info"]'))
            if self.is_shared_group(settings_obj) and info.get('group_name') == group_name:
                for policy_set in policy_obj.findall('PolicySettings'):
                    if policy_set.text == settings_obj.get('name'):
                        policy_obj.remove(policy_set)
                self.root.remove(settings_obj)
                return True
        return False

    def rename_rule_group(self, group_name, new_name):
        """
        Renames the reference to a shared Rule Group in the policy (scor_info
        group_name, by which ePO links the policy to the Rule Group).

        A Rule Group renamed in ePO (scor.rulegroup.rename) is renamed by ePO
        in the policies using it too (checked on the ePO 5.10 lab): this method
        is only needed to keep a policy export taken before the rename
        consistent, e.g. before importing it again.

        :return: True if the Rule Group was found and renamed.
        """
        if new_name != group_name and new_name in self.get_rule_group_names():
            raise ValueError('The policy already references a Rule Group named "{}".'.format(
                new_name))
        for settings_obj in self.__settings_list():
            setting_obj = settings_obj.find('Section[@name="scor_info"]/Setting[@name="group_name"]')
            if self.is_shared_group(settings_obj) and setting_obj is not None and \
                    setting_obj.get('value') == group_name:
                setting_obj.set('value', new_name)
                return True
        return False

    # Policy type -> (rule group type, platform) of the Rule Groups it can use.
    RULE_GROUP_TYPES = {
        'AWL Rules (Windows)': ('application_control', 'WIN'),
        'AWL Rules (Unix)': ('application_control', 'UNIX'),
        'CC Rules (Windows)': ('change_control', 'WIN'),
        'CC Rules (Unix)': ('change_control', 'UNIX'),
        'Mon Rules (Windows)': ('mon', 'WIN'),
        'Mon Rules (Unix)': ('mon', 'UNIX'),
    }

    def add_rule_group(self, rule_group):
        """
        Adds a reference to a shared Rule Group to the policy, as the "Add" button
        of the Rule Groups panel of the ePO console does.

        ePO links a policy to a Rule Group by the Rule Group name: the Rule Group
        must already exist in ePO (created in the console, or imported with
        scor.rulegroup.import) when the policy is imported, and the policy then
        follows its later changes. The rules of rule_group are copied into the
        policy, as ePO does in its exports.

        :param: rule_group: A SCRuleGroup (from a SCRuleGroups export) of the same
                            type and platform as the policy.
        :return: True, or False if the policy already references this Rule Group.
        """
        expected = self.RULE_GROUP_TYPES.get(self.get_type())
        if expected is None:
            raise ValueError('Policy type "{}" has no Rule Groups.'.format(self.get_type()))
        if (rule_group.get_type(), rule_group.get_platform()) != expected:
            raise ValueError('Rule Group "{}" ({}, {}) doesn\'t match a "{}" policy.'.format(
                rule_group.get_name(), rule_group.get_type(), rule_group.get_platform(),
                self.get_type()))
        if rule_group.get_name() in self.get_rule_group_names():
            return False
        policy_obj = self.root.find('EPOPolicyObject')
        settings_name = '{}{}'.format(rule_group.get_name(), uuid.uuid4())
        settings_obj = et.Element('EPOPolicySettings', {
            'name': settings_name, 'featureid': policy_obj.get('featureid'),
            'categoryid': self.get_type(), 'typeid': self.get_type(),
            'param_int': '', 'param_str': ''})
        info_obj = et.SubElement(settings_obj, 'Section', {'name': 'scor_info'})
        for key, value in (('group_name', rule_group.get_name()), ('group_type', expected[0]),
                           ('platforms', expected[1]), ('readOnly', 'true')):
            et.SubElement(info_obj, 'Setting', {'name': key, 'value': value})
        for rule in rule_group.get_rules():
            self.__append_section(settings_obj, rule)
        self.root.append(settings_obj)
        et.SubElement(policy_obj, 'PolicySettings').text = settings_name
        return True

    # ------------------------------ Policy metadata ------------------------------
    #   The "scor_meta" Section of the policy's own rules (Options policies only).
    def get_meta(self, name):
        """
        Returns the value of a "scor_meta" setting, or None if it doesn't exist.
        """
        settings_obj = self.__my_rules()
        if settings_obj is None:
            return None
        setting_obj = settings_obj.find('Section[@name="scor_meta"]/Setting[@name="{}"]'.format(name))
        return setting_obj.get('value') if setting_obj is not None else None

    def set_meta(self, name, value):
        """
        Sets the value of an existing "scor_meta" setting.
        """
        settings_obj = self.__my_rules()
        if settings_obj is None:
            return False
        setting_obj = settings_obj.find('Section[@name="scor_meta"]/Setting[@name="{}"]'.format(name))
        if setting_obj is None:
            return False
        setting_obj.set('value', value)
        return True

    # ------------------------------ Rules storage (see SCRules) ------------------------------
    @staticmethod
    def __section_to_dict(section_obj):
        if section_obj is None:
            return {}
        return {s.get('name'): s.get('value') for s in section_obj.findall('Setting')}

    @staticmethod
    def __is_rule_section(section_obj):
        # The rules are "General_Rule_<n>" sections; the Solidcore 8.4 console
        # also keeps (and adds the trusted directories of) "General_<n>"
        # sections when a policy already has some (seen on the lab).
        return re.match(r'^General_(Rule_)?\d+$', section_obj.get('name')) is not None

    def is_unix(self):
        """
        Returns True for a Unix policy.
        """
        return self.get_type().endswith('(Unix)')

    def _iter_rules(self, all_groups=False):
        # md_rule_group_sections() reads the rules of one group at a time.
        view = getattr(self, '_md_view', None)
        settings_list = self.__settings_list() if all_groups else \
            [view if view is not None else self.__my_rules()]
        for settings_obj in settings_list:
            if settings_obj is None:
                continue
            for section_obj in settings_obj.findall('Section'):
                if self.__is_rule_section(section_obj):
                    yield (settings_obj, section_obj), self.__section_to_dict(section_obj)

    def _append_rule(self, rule):
        settings_obj = self.__my_rules()
        if settings_obj is None:
            return False
        self.__append_section(settings_obj, rule)
        return True

    def __append_section(self, settings_obj, rule):
        numbers = [int(m.group(1)) for m in
                   (re.match(r'^General_Rule_(\d+)$', s.get('name'))
                    for s in settings_obj.findall('Section')) if m]
        number = max(numbers) + 1 if numbers else 0
        section_obj = et.Element('Section', {'name': 'General_Rule_{}'.format(number)})
        for key in sorted(rule):
            et.SubElement(section_obj, 'Setting', {'name': key, 'value': rule[key]})
        # Keep the scor_info / scor_meta sections at the end, as ePO does.
        sections = settings_obj.findall('Section')
        index = len(sections)
        for i, existing in enumerate(sections):
            if not self.__is_rule_section(existing):
                index = i
                break
        settings_obj.insert(index, section_obj)

    def _update_rule(self, handle, values):
        section_obj = handle[1]
        for key, value in values.items():
            setting_obj = section_obj.find('Setting[@name="{}"]'.format(key))
            if setting_obj is None:
                et.SubElement(section_obj, 'Setting', {'name': key, 'value': value})
            else:
                setting_obj.set('value', value)

    def _remove_rule(self, handle):
        handle[0].remove(handle[1])

    # ------------------------------ Typed rule helpers ------------------------------
    #   'config' rules: {'type': 'config', 'name': <name>, 'value': <value>}
    def get_config(self, name):
        """
        Returns the value of a 'config' rule, or None if it doesn't exist.
        """
        rule = self.get_rule('config', {'name': name})
        return rule.get('value') if rule is not None else None

    def set_config(self, name, value):
        """
        Sets the value of a 'config' rule. The rule is created if it doesn't exist.
        """
        if self.update_rules('config', {'name': name}, {'value': value}) == 0:
            return self.add_rule({'type': 'config', 'name': name, 'value': value})
        return True

    #   'features' rules: {'type': 'features', 'name': <name>, 'status': '1'|'0',
    #   'enforce': 'true'|'false'}
    def get_feature(self, name):
        """
        Returns the status ('1' or '0') of a 'features' rule, or None if it doesn't exist.
        """
        rule = self.get_rule('features', {'name': name})
        return rule.get('status') if rule is not None else None

    def set_feature(self, name, status):
        """
        Sets the status ('1' or '0') of a 'features' rule. The rule is created
        (enforced) if it doesn't exist.
        """
        if self.update_rules('features', {'name': name}, {'status': status}) == 0:
            return self.add_rule({'type': 'features', 'name': name, 'status': status,
                                  'enforce': 'true'})
        return True
