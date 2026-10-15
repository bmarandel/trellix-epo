# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes ESATPPolicyDAC (Endpoint Security Adaptive
Threat Protection: Dynamic Application Containment) and DACExclusion.

Storage learnt from a test policy changed in the ePO 5.10 console:

- Containment rules: one EPOPolicySettings per rule, Section DACRule with
  RuleID (e.g. DAC_BLOCK_PROCESS_TERMINATE), RuleName (a resource key),
  RuleType "Canned", Block and Report ('1'/'0', both '0' = rule disabled)
  and Note.
- Exclusions: Section dacGeneral, ExecutableCount and for each one
  Executable#<n>_ID (GUID), _IncludeStatus "exclude", _Name, _Notes and 3
  parameters (_ParameterCount, _Parameter#<p>_Name/_Value): OBJECT_NAME
  (file name or path), MD5 and CERT_NAME (signer: '' = no digital signature
  check, '**' = Allow any signature, else the "Signed by" distinguished
  name).
"""

import re
import uuid
import xml.etree.ElementTree as et

from ...policies import Policy
from ...validators import check_length, is_ens_executable_path


class DACExclusion():
    """
    An exclusion of a Dynamic Application Containment policy (console "Add
    Exclusion" page): executables never contained.

    :param: name: Name (required, 256 characters max).
    :param: path: File name or path (can include * or ? wildcards, 256
                  characters max).
    :param: md5: MD5 hash (32 hexadecimal digits).
    :param: signer: None = no digital signature check, ANY_SIGNATURE = Allow
                    any signature, else the "Signed by" distinguished name,
                    e.g. 'C=US, O=Example Corp, CN=Example Corp'.
    :param: notes: Notes.
    At least a path, an MD5 hash or a signer is required.
    """
    ANY_SIGNATURE = '**'
    PARAMETERS = ['OBJECT_NAME', 'MD5', 'CERT_NAME']

    def __init__(self, name, path='', md5='', signer=None, notes='', exclusion_id=None):
        self.name = name
        self.path = path or ''
        self.md5 = md5 or ''
        self.signer = None if signer in (None, '') else signer
        self.notes = notes or ''
        self.id = exclusion_id or str(uuid.uuid4())

    def __repr__(self):
        return 'DACExclusion({!r}, path={!r}, md5={!r}, signer={!r}, notes={!r})'.format(
            self.name, self.path, self.md5, self.signer, self.notes)

    def __key(self):
        return (self.name, self.path, self.md5.lower(), self.signer, self.notes)

    def __eq__(self, other):
        return isinstance(other, DACExclusion) and self.__key() == other.__key()

    def check(self):
        """
        Raise ValueError if the console would refuse the exclusion (checks of
        the "Add Exclusion" page of ENS ATP 26.8, compared on the lab): name
        required (256 characters), file name or path (256, Windows path or
        file name, wildcards allowed - same rule as the Access Protection
        executables, see is_ens_executable_path), MD5 hash (32 hexadecimal
        digits), signer (1024; any text is accepted by the server check of
        ATP, unlike Threat Prevention and Firewall, but not blanks), notes
        (256). At least a path, an MD5 hash or a signer is required.
        """
        check_length('Name', self.name, 256, required=True)
        check_length('File name or path', self.path, 256)
        check_length('MD5 hash', self.md5, 32)
        check_length('Signed by', self.signer or '', 1024)
        check_length('Notes', self.notes, 256)
        if not (self.path.strip() or self.md5.strip() or self.signer):
            raise ValueError('File name or path, MD5 hash, or signer must be specified.')
        if self.path and not is_ens_executable_path(self.path):
            raise ValueError('Invalid file name or path: {!r}'.format(self.path))
        if self.md5 and not re.fullmatch('[0-9a-fA-F]{32}', self.md5):
            raise ValueError('The MD5 hash must be 32 hexadecimal digits: {}'.format(self.md5))
        if self.signer is not None and not self.signer.strip():
            raise ValueError('Enter the "Signed by" distinguished name.')

    @property
    def signer_label(self):
        """
        The signer for a document: '' (no digital signature check), 'Any
        signature' (console "Allow any signature", shown as ** in the
        exclusion list) or the distinguished name.
        """
        if not self.signer:
            return ''
        return 'Any signature' if self.signer == self.ANY_SIGNATURE else self.signer


class ESATPPolicyDAC(Policy):
    """
    The ESATPPolicyDAC class can be used to edit the Endpoint Security
    Adaptive Threat Protection policy: Dynamic Application Containment
    (Containment Rules and Exclusions).
    """

    MD_PRODUCT = 'Endpoint Security Adaptive Threat Protection'
    MD_CATEGORY = 'Dynamic Application Containment'
    TYPE = 'TIE_DynamicApplicationContainment_Policies'

    # Containment rules: RuleID -> console label (ePO 5.10, ENS ATP 10.7).
    RULES = {
        'DAC_BLOCK_MODIFY_CACHED_PASSWORDS': 'Accessing insecure password LM hashes',
        'DAC_BLOCK_ACCESSING_USER_COOKIES': 'Accessing user cookie locations',
        'DAC_BLOCK_PROCESS_VM_OPERATION': 'Allocating memory in another process',
        'DAC_BLOCK_PROCESS_CREATE_THREAD': 'Creating a thread in another process',
        'DAC_BLOCK_CREATE_NETWORK': 'Creating files on any network location',
        'DAC_BLOCK_CREATE_REMOVABLE': 'Creating files on CD, floppy, and removable drives',
        'DAC_BLOCK_CREATE_BATCH': 'Creating files with the .bat extension',
        'DAC_BLOCK_CREATE_EXE': 'Creating files with the .exe extension',
        'DAC_BLOCK_CREATE_PICTURE': 'Creating files with the .html, .jpg, or .bmp extension',
        'DAC_BLOCK_CREATE_TASKS': 'Creating files with the .job extension',
        'DAC_BLOCK_CREATE_VBSCRIPT': 'Creating files with the .vbs extension',
        'DAC_BLOCK_CREATE_CLSID_APPID_TYPELIB': 'Creating new CLSIDs, APPIDs, and TYPELIBs',
        'DAC_BLOCK_DELETE_TARGETED_EXTENSIONS': 'Deleting files commonly targeted by '
                                                'ransomware-class malware',
        'DAC_BLOCK_CRITICAL_OS_EXE_DISABLEMENT': 'Disabling critical operating system '
                                                 'executables',
        'DAC_BLOCK_CHILD_PROC_EXEC': 'Executing any child process',
        'DAC_BLOCK_MODIFY_APPINIT': 'Modifying appinit DLL registry entries',
        'DAC_BLOCK_MODIFY_APPCOMPAT_SHIMS': 'Modifying application compatibility shims',
        'DAC_BLOCK_MODIFY_CRITICAL_FILES_REGISTRY': 'Modifying critical Windows files and '
                                                    'registry locations',
        'DAC_BLOCK_MODIFY_WALLPAPER': 'Modifying desktop background settings',
        'DAC_BLOCK_MODIFY_FILE_EXTENSION_ASSOCIATION': 'Modifying file extension associations',
        'DAC_BLOCK_MODIFY_BATCH': 'Modifying files with the .bat extension',
        'DAC_BLOCK_MODIFY_VBSCRIPT': 'Modifying files with the .vbs extension',
        'DAC_BLOCK_MODIFY_IMG_FILE_EXECUTION': 'Modifying Image File Execution Options '
                                               'registry entries',
        'DAC_BLOCK_MODIFY_PE': 'Modifying portable executable files',
        'DAC_BLOCK_MODIFY_SCREENSAVER': 'Modifying screen saver settings',
        'DAC_BLOCK_MODIFY_STARTUP': 'Modifying startup registry locations',
        'DAC_BLOCK_MODIFY_AEDEBUG': 'Modifying the automatic debugger',
        'DAC_BLOCK_MODIFY_HIDDEN': 'Modifying the hidden attribute bit',
        'DAC_BLOCK_MODIFY_READ_ONLY': 'Modifying the read-only attribute bit',
        'DAC_BLOCK_MODIFY_SERVICES_LOCATION': 'Modifying the Services registry location',
        'DAC_BLOCK_MODIFY_FIREWALL': 'Modifying the Windows Firewall policy',
        'DAC_BLOCK_MODIFY_TASKS': 'Modifying the Windows Tasks folder',
        'DAC_BLOCK_MODIFY_USER_POLICIES': 'Modifying user policies',
        'DAC_BLOCK_MODIFY_USER_DATA': "Modifying users' data folders",
        'DAC_BLOCK_READ_TARGETED_EXTENSIONS': 'Reading files commonly targeted by '
                                              'ransomware-class malware',
        'DAC_BLOCK_PROCESS_READMEMORY': "Reading from another process's memory",
        'DAC_BLOCK_MODIFY_NETWORK': 'Reading or modifying files on any network location',
        'DAC_BLOCK_MODIFY_REMOVABLE': 'Reading or modifying files on CD, floppy, and '
                                      'removable drives',
        'DAC_BLOCK_PROCESS_SUSPEND_RESUME': 'Suspending a process',
        'DAC_BLOCK_PROCESS_TERMINATE': 'Terminating another process',
        'DAC_BLOCK_PROCESS_WRITEMEMORY': "Writing to another process's memory",
        'DAC_BLOCK_WRITE_TARGETED_EXTENSIONS': 'Writing to files commonly targeted by '
                                               'ransomware-class malware',
    }

    def __init__(self, policy_from_esatppolicies=None):
        super(ESATPPolicyDAC, self).__init__(policy_from_esatppolicies)
        if policy_from_esatppolicies is not None:
            if self.get_type() != self.TYPE:
                raise ValueError('Wrong policy! Policy type must be "{}".'.format(self.TYPE))

    def __repr__(self):
        return 'ESATPPolicyDAC()'

    # ------------------------------ Containment Rules ------------------------------
    def __rule_sections(self):
        return self.root.findall('./EPOPolicySettings/Section[@name="DACRule"]')

    @staticmethod
    def __value(section, setting):
        setting_obj = section.find('Setting[@name="{}"]'.format(setting))
        return setting_obj.get('value') if setting_obj is not None else None

    def __rule_section(self, rule):
        """
        Returns the DACRule Section of a rule given by its RuleID or console label.
        """
        for section in self.__rule_sections():
            rule_id = self.__value(section, 'RuleID') or ''
            if rule in (rule_id, self.RULES.get(rule_id)):
                return section
        raise ValueError('Unknown containment rule: {}'.format(rule))

    def __rule(self, section):
        rule_id = self.__value(section, 'RuleID') or ''
        return {'id': rule_id, 'name': self.RULES.get(rule_id, rule_id),
                'block': self.__value(section, 'Block'), 'report': self.__value(section, 'Report'),
                'note': self.__value(section, 'Note') or ''}

    def get_rules(self):
        """
        Get the containment rules in the console order (sorted by name): a
        list of dicts {'id', 'name' (console label), 'block', 'report' ('1'
        or '0'; both '0' = rule disabled), 'note'}.
        """
        rules = [self.__rule(section) for section in self.__rule_sections()]
        return sorted(rules, key=lambda rule: rule['name'].lower())

    def get_rule(self, rule):
        """
        Get a containment rule (see get_rules) by its RuleID (e.g.
        'DAC_BLOCK_PROCESS_TERMINATE') or console label.
        """
        return self.__rule(self.__rule_section(rule))

    def set_rule(self, rule, block=None, report=None):
        """
        Set Block and/or Report ('1' or '0', None = keep) of a containment
        rule given by its RuleID or console label. Deselecting both Block and
        Report disables the rule.
        """
        section = self.__rule_section(rule)
        for setting, mode in [('Block', block), ('Report', report)]:
            if mode is None:
                continue
            if str(mode) not in ['0', '1']:
                raise ValueError('{} must be "1" or "0".'.format(setting))
            section.find('Setting[@name="{}"]'.format(setting)).set('value', str(mode))
        return True

    def set_all_rules(self, block=None, report=None):
        """
        Set Block and/or Report of all the containment rules (console "Block
        All" / "Report All").
        """
        for rule in self.get_rules():
            self.set_rule(rule['id'], block, report)
        return True

    # ------------------------------ Exclusions ------------------------------
    def __general(self):
        return self.root.find('./EPOPolicySettings/Section[@name="dacGeneral"]')

    def get_exclusions(self):
        """
        Get the exclusions (list of DACExclusion) in the policy order (the
        console sorts them by name, descending).
        """
        section = self.__general()
        if section is None:
            return []
        value = lambda setting: self.__value(section, setting) or ''
        exclusions = []
        for row in range(int(value('ExecutableCount') or 0)):
            prefix = 'Executable#{}_'.format(row)
            parameters = {}
            for index in range(int(value(prefix + 'ParameterCount') or 0)):
                parameters[value('{}Parameter#{}_Name'.format(prefix, index))] = \
                    value('{}Parameter#{}_Value'.format(prefix, index))
            exclusions.append(DACExclusion(value(prefix + 'Name'),
                                           parameters.get('OBJECT_NAME', ''),
                                           parameters.get('MD5', ''),
                                           parameters.get('CERT_NAME') or None,
                                           value(prefix + 'Notes'), value(prefix + 'ID')))
        return exclusions

    def set_exclusions(self, exclusions):
        """
        Set the exclusions (list of DACExclusion).
        """
        names = set()
        for exclusion in exclusions:
            exclusion.check()
            name = exclusion.name.strip().upper()
            if name in names:
                raise ValueError('An exclusion named {!r} already exists.'.format(exclusion.name))
            names.add(name)
        section = self.__general()
        if section is None:
            raise ValueError('No dacGeneral section in this policy.')
        for setting_obj in section.findall('Setting'):
            if setting_obj.get('name').startswith('Executable'):
                section.remove(setting_obj)
        add = lambda name, value: et.SubElement(section, 'Setting', {'name': name,
                                                                     'value': value})
        for row, exclusion in enumerate(exclusions):
            prefix = 'Executable#{}_'.format(row)
            add(prefix + 'ID', exclusion.id)
            add(prefix + 'IncludeStatus', 'exclude')
            add(prefix + 'Name', exclusion.name)
            add(prefix + 'Notes', exclusion.notes)
            values = [exclusion.path, exclusion.md5, exclusion.signer or '']
            for index, (name, value) in enumerate(zip(DACExclusion.PARAMETERS, values)):
                add('{}Parameter#{}_Name'.format(prefix, index), name)
                add('{}Parameter#{}_Value'.format(prefix, index), value)
            add(prefix + 'ParameterCount', str(len(values)))
        add('ExecutableCount', str(len(exclusions)))
        return True

    exclusions = property(get_exclusions, set_exclusions)

    def add_exclusion(self, exclusion):
        """
        Add an exclusion (DACExclusion) if not already in the list.
        """
        exclusion.check()
        exclusions = self.get_exclusions()
        if exclusion in exclusions:
            return False
        return self.set_exclusions(exclusions + [exclusion])

    def remove_exclusion(self, exclusion):
        """
        Remove an exclusion given as a DACExclusion or by its name (all the
        exclusions with this name).
        """
        exclusions = self.get_exclusions()
        if isinstance(exclusion, DACExclusion):
            kept = [known for known in exclusions if known != exclusion]
        else:
            kept = [known for known in exclusions if known.name != exclusion]
        if len(kept) == len(exclusions):
            return False
        return self.set_exclusions(kept)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        rules = self.get_rules()
        with_notes = any(rule['note'] for rule in rules)
        headers = ['Rule', 'Block', 'Report', 'Status'] + (['Note'] if with_notes else [])
        rows = []
        for rule in rules:
            row = [rule['name'], self.md_check(rule['block']), self.md_check(rule['report']),
                   'Disabled' if rule['block'] != '1' and rule['report'] != '1' else 'Enabled']
            rows.append(row + ([rule['note']] if with_notes else []))
        text = 'Deselecting both Block and Report will disable the Rule.\n\n'
        text += self.md_table(headers, rows, numbered=True)
        sections = [('Containment Rules', text)]
        sections.append(('Exclusions', self.md_table(
            ['Name', 'File Name or Path', 'MD5 Hash', 'Signer', 'Notes'],
            [[exclusion.name, exclusion.path, exclusion.md5, exclusion.signer_label,
              exclusion.notes] for exclusion in self.get_exclusions()], numbered=True)))
        return sections
