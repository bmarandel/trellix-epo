# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines two Class object: Policies and Policy.
Those classes will be used as the base Class object to create other modules for each
product policy managed by ePolicy Orchestrator.
"""

import re
import uuid
import copy
import datetime
import xml.etree.ElementTree as et

from .validators import check_setting_length

class XmlObject():
    """
    XmlObject is a common class object for Policies and Policy.
    """

    def __init__(self):
        self.root = None

    def is_empty(self):
        """
        Returns True if the object is empty, other else False.

        :return: True or False.
        """
        return self.root is None

    def get_xml_content(self):
        """
        Returns the current XML content, UTF-8 encoded (binary). The
        characters out of ASCII are written as XML character references
        (é as &#233;): the policy import of the ePO Web API
        (policy.importPolicy) reads a UTF-8 file as ISO-8859-1 whatever the
        charset sent (é imported as Ã©; the Policy Catalog import of the
        console reads it right; checked on ePO 5.10 Update 7), the
        references are imported unchanged by both.
        """
        return et.tostring(self.root, encoding='us-ascii', method='xml')

    def set_xml_content(self, xml_data):
        """
        Set the data of the XML object.
        """
        self.root = et.fromstring(xml_data)

    def get_xml_content_str(self):
        """
        Returns the current XML content, UTF-8 decoded (string).
        """
        return et.tostring(self.root, encoding='unicode', method='xml')

    def load_from_file(self, file_path):
        """
        Load a Policy from a previously export policy file from an ePO server.
        """
        tree = et.parse(file_path)
        self.root = tree.getroot()

    def save_to_file(self, file_path):
        """
        Save the current Policy in an XML file. This file can be imported into an ePO server.
        """
        success = False
        if self.root is not None:
            xml_file = open(file_path, 'bw')
            xml_file.write(self.get_xml_content())
            xml_file.close()
            success = True
        return success

    def get_epo_version(self):
        """
        Returns the ePO server version from XML content.
        """
        str_version = ''
        if self.root is not None:
            policy_ver = self.root.find('EPOPolicyVerInfo')
            epo_version = policy_ver.attrib
            str_version = '{vermjr}.{vermin}.{verrel}.{verbld}'.format(**epo_version)
        return str_version

    def get_epo_server(self):
        """
        Returns the ePO Server name which this Policy come from.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['serverid'] if policy_obj is not None else ''

    def get_product(self):
        """
        Returns the product name of which this Policy should apply.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['featureid'] if policy_obj is not None else ''

class Policies(XmlObject):
    """
    Policies is a class object containing the policies returned by the ePO API.
    """

    # The EPOPolicyObject attribute that identifies the policy type. A product
    # whose policy categories share the same typeid (e.g. System Information
    # Reporter) uses the featureid instead.
    TYPE_ATTRIBUTE = 'typeid'

    def __init__(self, xml_policies=None):
        super(Policies, self).__init__()
        if xml_policies is not None:
            self.set_xml_content(xml_policies)

    def contain(self, type_id, name):
        """
        Returns True if the current Policies contains a policy (name) for a specific
        type (type_id).

        :param: type_id: The type of the policy.
        :param: name: The name of the policy.
        :return: True or False.
        """
        policy_obj = self.root.find('./EPOPolicyObject[@name="{}"]'.format(name) +
                                    '[@{}="{}"]'.format(self.TYPE_ATTRIBUTE, type_id))
        return policy_obj is not None

    def list_name(self):
        """
        Returns a list of policy name found in Policies.
        """
        distinct_names = list(set(policy_obj.attrib['name']
                                  for policy_obj in self.root.findall('EPOPolicyObject')))
        sorted_names = sorted(distinct_names)
        return sorted_names

    def list_type(self):
        """
        Returns a list of policy type found in Policies.
        """
        distinct_types = list(set(policy_obj.attrib[self.TYPE_ATTRIBUTE]
                                  for policy_obj in self.root.findall('EPOPolicyObject')))
        sorted_types = sorted(distinct_types)
        return sorted_types

    def list(self):
        """
        Returns a table containing the list of policy name for each policy type found in Policies.
        """
        full_list = [{'typeid': policy_obj.attrib[self.TYPE_ATTRIBUTE],
                      'name': policy_obj.attrib['name']}
                     for policy_obj in self.root.findall('EPOPolicyObject')]
        sorted_list = sorted(full_list, key=lambda x: (x['typeid'], x['name']))
        return sorted_list

    def get_policy(self, type_id, name):
        """
        Returns a Policy content of a policy (name) for a specific type (type_id).
        """
        if self.contain(type_id, name):
            policy = copy.deepcopy(self.root)
            settings = list()
            for policy_obj in policy.findall('EPOPolicyObject'):
                if (policy_obj.attrib[self.TYPE_ATTRIBUTE] == type_id) and \
                        (policy_obj.attrib['name'] == name):
                    for policy_ref in policy_obj.findall('PolicySettings'):
                        settings.append(policy_ref.text)
                else:
                    policy.remove(policy_obj)
            for policy_obj in policy.findall('EPOPolicySettings'):
                if policy_obj.attrib['name'] not in settings:
                    policy.remove(policy_obj)
        else:
            policy = None
        return policy

    def new_policy(self, type_id, name, template='My Default'):
        """
        Returns a new Policy with a policy name (name) for a specific type (type_id).
        herited from a template (default="My Default").
        """
        policy = self.get_policy(type_id, template)
        if policy is not None:
            policy_obj = policy.find('EPOPolicyObject')
            policy_obj.set('name', name)
            for policy_set in policy_obj.findall('PolicySettings'):
                policy_old = policy_set.text
                policy_ref = '{}::Settings ({})'.format(name, str(uuid.uuid4()).upper())
                policy_set.text = policy_ref
                policy_set = policy.find('EPOPolicySettings[@name="{}"]'.format(policy_old))
                policy_set.set('name', policy_ref)
            self.__new_exclusion_ids(policy)
        return policy

    @staticmethod
    def __new_exclusion_ids(policy):
        """
        Give new IDs to the Exploit Prevention exclusions of a copy: the ePO
        console fails to open a policy whose exclusion IDs are already used
        by another policy ("An unexpected error occurred."). The same old ID
        gets the same new ID in every section (current and down-level ones).
        The ENS ATP Dynamic Application Containment exclusions (dacGeneral)
        get new IDs too.
        """
        new_ids = {}
        for section_obj in policy.findall('EPOPolicySettings/Section'):
            name = section_obj.get('name')
            if not (name.startswith('bopExclusions') or name == 'dacGeneral'):
                continue
            for setting in section_obj.findall('Setting'):
                value = setting.get('value')
                if setting.get('name').endswith('_ID') and value:
                    setting.set('value', new_ids.setdefault(value, str(uuid.uuid4())))

class Policy(XmlObject):
    """
    Policy is a class object containing one Policy from Policies.
    """

    # Console labels used by to_markdown(): product and policy category, as
    # displayed in the ePO Policy Catalog. Set by each policy class.
    MD_PRODUCT = ''
    MD_CATEGORY = ''

    def __init__(self, policy_from_policies):
        super(Policy, self).__init__()
        self.root = policy_from_policies

    def get_name(self):
        """
        Returns the name of the Policy.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['name'] if policy_obj is not None else ''

    def get_type(self):
        """
        Returns the type of the Policy.
        """
        policy_obj = self.root.find('EPOPolicyObject')
        return policy_obj.attrib['typeid'] if policy_obj is not None else ''

    def get_setting_value(self, section, setting):
        """
        Returns the current value of a Setting from a specific Section.

        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :return: The value of the setting or None if the setting doesn't exist.
        """
        setting_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        return setting_obj.get('value') if setting_obj is not None else None

    def set_setting_value(self, section, setting, value, force=False):
        """
        Set the value of an existing Setting for a specific Section.

        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :param: force: If True the setting is created even if it doesn't exist.
        :return: True or False.
        """
        check_setting_length(setting, value)
        success = False
        setting_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        if setting_obj is not None:
            setting_obj.set('value', value)
            success = True
        elif force:
            section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
            setting_obj = et.SubElement(section_obj, 'Setting', {"name":setting, "value":value})
            success = True
        return success

    def get_policy_setting_value(self, policy_set, section, setting):
        """
        Returns the current value of a Setting from a specific Section for a PolicySetting.

        :param: policy_set: The EPOPolicySetting where to search for the Section.
        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :return: The value of the setting or None if the setting doesn't exist.
        """
        setting_obj = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_set) +
                                     '/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        return setting_obj.get('value') if setting_obj is not None else None

    def set_policy_setting_value(self, policy_set, section, setting, value, force=False):
        """
        Set the value of an existing Setting for a specific Section and PolicySetting

        :param: policy_set: The EPOPolicySetting where to search for the Section.
        :param: section: The Section where to search for the Setting.
        :param: setting: The Setting where to return the value.
        :param: force: If True the setting is created even if it doesn't exist.
        :return: True or False.
        """
        check_setting_length(setting, value)
        success = False
        setting_obj = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_set) +
                                     '/Section[@name="{}"]'.format(section) +
                                     '/Setting[@name="{}"]'.format(setting))
        if setting_obj is not None:
            setting_obj.set('value', value)
            success = True
        elif force:
            section_obj = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_set) +
                                         '/Section[@name="{}"]'.format(section))
            setting_obj = et.SubElement(section_obj, 'Setting', {"name":setting, "value":value})
            success = True
        return success

    def get_indexed_list(self, section, count_setting, item_template, start=0):
        """
        Read a repeating flat list of scalar values: a Setting named
        `count_setting` holds the row count, and one Setting per row is named
        `item_template.format(row)`, rows numbered from `start`.

        :param: section: The Section holding the list.
        :param: count_setting: The Setting name holding the row count.
        :param: item_template: A format string with one "{}" for the row number.
        :param: start: The row number of the first row (default 0).
        :return: A list of strings, or None if the section doesn't exist.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return None
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        max_rows = int(count_obj.get('value')) if count_obj is not None else 0
        values = []
        for row in range(start, start + max_rows):
            setting_obj = section_obj.find('Setting[@name="{}"]'.format(item_template.format(row)))
            values.append(setting_obj.get('value'))
        return values

    def set_indexed_list(self, section, count_setting, item_template, values, start=0):
        """
        Write a repeating flat list (see get_indexed_list). Only the count
        setting and the row settings matching `item_template` are touched;
        any other Setting already present in the section is left untouched.
        The count setting is always written, even when `values` is empty.

        :param: section: The Section holding the list.
        :param: count_setting: The Setting name holding the row count.
        :param: item_template: A format string with one "{}" for the row number.
        :param: values: The list of string values to write.
        :param: start: The row number of the first row (default 0).
        :return: True if the section exists, False otherwise.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return False
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        if count_obj is not None:
            section_obj.remove(count_obj)
        # ePO sometimes leaves stale row settings behind beyond the declared
        # count (e.g. after a site is removed via the console), so cleanup is
        # done by name pattern rather than by trusting the old count value -
        # otherwise a newly written row can collide with a leftover one and
        # get shadowed by it on the next read.
        prefix, _, suffix = item_template.partition('{}')
        pattern = re.compile('^{}\\d+{}$'.format(re.escape(prefix), re.escape(suffix)))
        for setting_obj in section_obj.findall('Setting'):
            if pattern.match(setting_obj.get('name')):
                section_obj.remove(setting_obj)
        et.SubElement(section_obj, 'Setting', {"name":count_setting, "value":str(len(values))})
        for offset, value in enumerate(values):
            row = start + offset
            et.SubElement(section_obj, 'Setting',
                          {"name":item_template.format(row), "value":value})
        return True

    def get_indexed_table(self, section, count_setting, keys, start=0):
        """
        Read a repeating table: a Setting named `count_setting` holds the row
        count, and for each name in `keys`, one Setting per row is named
        "{key}_{row}", rows numbered from `start`.

        :param: section: The Section holding the table.
        :param: count_setting: The Setting name holding the row count.
        :param: keys: The list of column names.
        :param: start: The row number of the first row (default 0).
        :return: A list of dicts (one per row, columns = keys), or None if
                 the section doesn't exist.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return None
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        max_rows = int(count_obj.get('value')) if count_obj is not None else 0
        table = []
        for row in range(start, start + max_rows):
            row_value = {}
            for key in keys:
                setting_obj = section_obj.find('Setting[@name="{}_{}"]'.format(key, row))
                row_value[key] = setting_obj.get('value')
            table.append(row_value)
        return table

    def set_indexed_table(self, section, count_setting, keys, table, start=0):
        """
        Write a repeating table (see get_indexed_table). Only the count
        setting and the "{key}_{row}" settings for `keys` are touched. The
        count setting is always written, even when `table` is empty.

        :param: section: The Section holding the table.
        :param: count_setting: The Setting name holding the row count.
        :param: keys: The list of column names.
        :param: table: The list of dicts (one per row, columns = keys) to write.
        :param: start: The row number of the first row (default 0).
        :return: True if the section exists, False otherwise.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))
        if section_obj is None:
            return False
        count_obj = section_obj.find('Setting[@name="{}"]'.format(count_setting))
        if count_obj is not None:
            section_obj.remove(count_obj)
        # See set_indexed_list: cleanup by name pattern, not by the old count,
        # since ePO can leave stale row settings behind beyond it.
        patterns = [re.compile('^{}_\\d+$'.format(re.escape(key))) for key in keys]
        for setting_obj in section_obj.findall('Setting'):
            name = setting_obj.get('name')
            if any(pattern.match(name) for pattern in patterns):
                section_obj.remove(setting_obj)
        et.SubElement(section_obj, 'Setting', {"name":count_setting, "value":str(len(table))})
        for offset, row_value in enumerate(table):
            row = start + offset
            for key in keys:
                et.SubElement(section_obj, 'Setting',
                              {"name":'{}_{}'.format(key, row), "value":row_value[key]})
        return True

    # ------------------------------ Markdown export ------------------------------
    # The console tabs/group boxes can't be reproduced in a document: each one
    # becomes a heading (console order and labels), options become
    # "Setting | Value" tables and lists become numbered tables with the
    # console columns. A document control section (review/approval sign-off)
    # ends the document, as expected by auditors (ISO 27001, PCI DSS...).
    @staticmethod
    def md_escape(value):
        """
        Escape a value to be put in a Markdown table cell.
        """
        if value is None:
            return ''
        text = str(value).replace('\\', '\\\\')
        # [ and ] too: a value such as [text](url) or ![x](url) would else be
        # rendered as a link or a remote image (tracking pixel).
        for char in '|*_`[]':
            text = text.replace(char, '\\' + char)
        text = text.replace('<', '&lt;').replace('>', '&gt;')
        return text.replace('\r\n', '<br>').replace('\n', '<br>')

    @staticmethod
    def md_heading(value):
        """
        Escape a value (e.g. a policy or rule name) to be put in a Markdown
        heading or list item: same escaping as md_escape (Markdown and HTML
        characters), line breaks replaced by spaces.
        """
        text = ' '.join(str(value if value is not None else '').split())
        return Policy.md_escape(text)

    @staticmethod
    def md_check(value):
        """
        Returns the label of a checkbox setting ('1' = checked), or None if
        the setting doesn't exist.
        """
        if value is None:
            return None
        return 'Yes' if value == '1' else 'No'

    @staticmethod
    def md_table(headers, rows, numbered=False):
        """
        Returns a Markdown table.

        :param: headers: The list of column names.
        :param: rows: A list of rows (lists of values).
        :param: numbered: If True, a first "#" column numbers the rows.
        :return: The Markdown table, or "*None*" if rows is empty.
        """
        if not rows:
            return '*None*\n'
        if numbered:
            headers = ['#'] + list(headers)
            rows = [[index] + list(row) for index, row in enumerate(rows, 1)]
        lines = ['| ' + ' | '.join(Policy.md_escape(h) for h in headers) + ' |',
                 '|' + '|'.join('---' for _ in headers) + '|']
        for row in rows:
            lines.append('| ' + ' | '.join(Policy.md_escape(v) for v in row) + ' |')
        return '\n'.join(lines) + '\n'

    def md_settings(self, rows):
        """
        Returns a "Setting | Value" Markdown table. Rows with a None value
        (setting missing from the export, e.g. older product version) are
        left out.

        :param: rows: A list of (label, value) tuples.
        """
        return self.md_table(['Setting', 'Value'], [row for row in rows if row[1] is not None])

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab/group box. Must be defined by each policy class;
        sub-headings in markdown must start at level 3 ("###").
        """
        raise NotImplementedError('Markdown export is not available for {}.'
                                  .format(type(self).__name__))

    def to_markdown(self, author='', reviewers=None):
        """
        Returns a Markdown document of the policy: metadata header, table of
        contents, one section per console tab and a document control section.

        :param: author: The name written in the document control section.
        :param: reviewers: A list of names for the review/approval table
                           (empty lines are left to be filled in by hand).
        :return: The Markdown text.
        """
        from . import __version__
        sections = self.md_sections()
        name = self.get_name()
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
        text = '# {}\n\n'.format(self.md_heading(name))
        text += '{} - {} policy\n\n'.format(self.MD_PRODUCT, self.MD_CATEGORY)
        text += self.md_table(['Property', 'Value'], [
            ['Product', self.MD_PRODUCT],
            ['Policy category', self.MD_CATEGORY],
            ['Policy name', name],
            ['ePO server', self.get_epo_server()],
            ['ePO version', self.get_epo_version()],
            ['Document generated on', now],
            ['Generated by', 'mcafee_epo_policies {}'.format(__version__)]])
        text += '\n## Contents\n\n'
        for index, (heading, _) in enumerate(sections, 1):
            text += '{}. {}\n'.format(index, self.md_heading(heading))
        text += '{}. Document control\n'.format(len(sections) + 1)
        for index, (heading, body) in enumerate(sections, 1):
            text += '\n## {}. {}\n\n{}'.format(index, self.md_heading(heading), body)
        text += '\n## {}. Document control\n\n'.format(len(sections) + 1)
        text += '### Review and approval\n\n'
        names = list(reviewers) if reviewers else ['', '']
        text += self.md_table(['Role', 'Name', 'Date', 'Signature'],
                              [['Prepared by', author, now[:10], '']] +
                              [['Reviewed/Approved by', reviewer, '', ''] for reviewer in names])
        text += '\n### Change history\n\n'
        text += self.md_table(['Version', 'Date', 'Author', 'Change description'],
                              [['1.0', now[:10], author, 'Initial version']])
        return text

    def save_markdown(self, file_path, author='', reviewers=None):
        """
        Save the Markdown document of the policy (see to_markdown) in a file.
        """
        with open(file_path, 'w', encoding='utf-8') as md_file:
            md_file.write(self.to_markdown(author, reviewers))
        return True
