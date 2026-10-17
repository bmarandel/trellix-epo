# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESTPPolicyAccessProtection and the objects of
an Access Protection rule, following the workflow of the ePO console:

    APRule (Name, Block/Report, Executables, User Names, Subrules, Notes)
     +- APExecutable (Name, Inclusion status, File name or path, MD5, Signer, Notes)
     +- APUserName (Name, Inclusion status)
     +- APSubRule (Name, Subrule type, Operations, Targets)
         +- APTarget (Inclusion status, Name, Value)
         +- APExecutable (targets of a Processes subrule)

Storage (checked against ePO 5.10 exports of rules created in the console):
each rule has its own policy settings, Section "APRule"/"APRule102" (Windows)
or "APLinuxRule" (Linux); the module state and the exclusions are in
Section "BehaviorBlockAP".
"""

import re
import uuid
import xml.etree.ElementTree as et
from ...policies import Policy
from ...validators import (check_length, is_x500_name, is_ens_executable_path,
                           is_ens_parameter_path, ENS_USER_NAME)

def _new_id():
    return str(uuid.uuid4())

def _check_unique(label, names):
    """
    The console refuses two items with the same name (case and surrounding
    spaces ignored).
    """
    seen = set()
    for name in names:
        key = name.strip().upper()
        if key in seen:
            raise ValueError('{}: duplicate name {!r}.'.format(label, name))
        seen.add(key)


def _check_inclusion(inclusion):
    if inclusion not in ['include', 'exclude']:
        raise ValueError('Inclusion status must be "include" or "exclude".')
    return inclusion


class APExecutable():
    """
    An executable of an Access Protection rule, subrule (Processes) or
    exclusion. At least one of path, md5 or signer must be set.

    :param name: The name.
    :param path: File name or path (can include * or ? wildcards).
    :param md5: MD5 hash (Windows only).
    :param signer: Signer (Windows only): '' (no digital signature check),
                   APExecutable.ANY_SIGNATURE or the distinguished name of the
                   signer (e.g. 'CN=..., O=..., C=US').
    :param inclusion: 'include' or 'exclude'.
    :param notes: Notes.
    """
    ANY_SIGNATURE = '**'

    def __init__(self, name, path='', md5='', signer='', inclusion='include', notes='',
                 exe_id=None):
        if not name:
            raise ValueError('The executable name is required.')
        if not (path or md5 or signer):
            raise ValueError('File name or path, MD5 hash or signer must be specified.')
        self.name = name
        self.path = path
        self.md5 = md5
        self.signer = signer
        self.inclusion = _check_inclusion(inclusion)
        self.notes = notes
        self.id = exe_id or _new_id()

    def check(self, linux=False):
        """
        Raise ValueError if the console refuses the executable (Threat
        Prevention 26.8, checked on the lab): name 256 characters; Windows:
        file name or path of 256 characters (see
        trellix_epo.validators.is_ens_executable_path), MD5 of 32
        hexadecimal digits, signer of 1024 characters (APExecutable.ANY_SIGNATURE
        or a distinguished name, see is_x500_name), notes 256 characters;
        Linux: path of 256 characters, no MD5 nor signer.
        """
        check_length('Executable name', self.name, 256, required=True)
        check_length('File name or path', self.path, 256)
        check_length('Notes', self.notes, 256)
        if linux:
            if self.md5 or self.signer:
                raise ValueError('A Linux executable has no MD5 hash nor signer.')
            return self
        if self.path and not is_ens_executable_path(self.path):
            raise ValueError('Invalid file name or path: {!r}'.format(self.path))
        if self.md5 and not re.fullmatch(r'[a-fA-F0-9]{32}', self.md5):
            raise ValueError('The MD5 hash is 32 hexadecimal digits: {!r}'.format(self.md5))
        check_length('Signer', self.signer, 1024)
        if self.signer and self.signer != self.ANY_SIGNATURE and not is_x500_name(self.signer):
            raise ValueError('Invalid signer distinguished name: {!r}'.format(self.signer))
        return self

    def __repr__(self):
        return 'APExecutable({!r}, path={!r}, inclusion={!r})'.format(
            self.name, self.path, self.inclusion)

    def __eq__(self, other):
        return isinstance(other, APExecutable) and vars(self) == vars(other)

    @classmethod
    def from_values(cls, values, prefix):
        """
        Returns the executables stored as "<prefix>Executable#<n>_...".
        """
        executables = []
        for row in range(int(values.get(prefix + 'ExecutableCount') or 0)):
            exe = '{}Executable#{}_'.format(prefix, row)
            params = {}
            for param in range(int(values.get(exe + 'ParameterCount') or 0)):
                params[values.get('{}Parameter#{}_Name'.format(exe, param))] = \
                    values.get('{}Parameter#{}_Value'.format(exe, param)) or ''
            executable = cls.__new__(cls)
            executable.name = values.get(exe + 'Name') or ''
            executable.path = params.get('OBJECT_NAME', '')
            executable.md5 = params.get('MD5', '')
            executable.signer = params.get('CERT_NAME', '')
            executable.inclusion = values.get(exe + 'IncludeStatus') or 'include'
            executable.notes = values.get(exe + 'Notes') or ''
            executable.id = values.get(exe + 'ID') or _new_id()
            executables.append(executable)
        return executables

    @staticmethod
    def to_values(executables, prefix, linux=False):
        """
        Returns the settings of a list of executables. Linux executables only
        have a file name or path.
        """
        values = {prefix + 'ExecutableCount': str(len(executables))}
        for row, executable in enumerate(executables):
            exe = '{}Executable#{}_'.format(prefix, row)
            values[exe + 'ID'] = executable.id
            values[exe + 'IncludeStatus'] = executable.inclusion
            values[exe + 'Name'] = executable.name
            values[exe + 'Notes'] = executable.notes
            params = [('OBJECT_NAME', executable.path)]
            if not linux:
                params += [('MD5', executable.md5), ('CERT_NAME', executable.signer)]
            for param, (name, value) in enumerate(params):
                values['{}Parameter#{}_Name'.format(exe, param)] = name
                values['{}Parameter#{}_Value'.format(exe, param)] = value
            values[exe + 'ParameterCount'] = str(len(params))
        return values


class APUserName():
    """
    A user name of an Access Protection rule: 'machine\\user',
    'domain\\user' or 'Local\\System'.
    """

    def __init__(self, name, inclusion='include', user_id=None):
        if not name:
            raise ValueError('The user name is required.')
        self.name = name
        self.inclusion = _check_inclusion(inclusion)
        self.id = user_id or _new_id()

    def check(self, linux=False):
        """
        Raise ValueError if the console refuses the user name: 100
        characters; Windows: domain\\user (see
        trellix_epo.validators.ENS_USER_NAME).
        """
        check_length('User name', self.name, 100, required=True)
        if not linux and not ENS_USER_NAME.match(self.name):
            raise ValueError('Invalid user name (domain\\user): {!r}'.format(self.name))
        return self

    def __repr__(self):
        return 'APUserName({!r}, inclusion={!r})'.format(self.name, self.inclusion)

    def __eq__(self, other):
        return isinstance(other, APUserName) and vars(self) == vars(other)


class APTarget():
    """
    A target of an Access Protection subrule.

    :param value: The value (path, registry key, drive type, service name...).
    :param name: The target type, see the constants (default: FILE_PATH,
                 which is also the registry key path, the registry value and
                 the service registered name).
    :param inclusion: 'include' or 'exclude'.
    """
    FILE_PATH = 'OBJECT_NAME'
    DESTINATION_FILE = 'TARGET_OBJECT_NAME'
    DRIVE_TYPE = 'EXP_DRIVE_TYPE'
    REGISTRY_KEY = 'OBJECT_NAME'
    REGISTRY_VALUE = 'OBJECT_NAME'
    SERVICE_NAME = 'OBJECT_NAME'
    SERVICE_DISPLAY_NAME = 'TARGET_OBJECT_NAME'
    # Values of a DRIVE_TYPE target.
    DRIVE_REMOVABLE, DRIVE_NETWORK, DRIVE_FIXED, DRIVE_CD_DVD, DRIVE_FLOPPY = \
        'DT_REMOVABLE', 'DT_NETWORK', 'DT_FIXED', 'DT_CD_DVD', 'DT_FLOPPY'

    def __init__(self, value, name=FILE_PATH, inclusion='include', target_id=None):
        if not value:
            raise ValueError('The target value is required.')
        self.value = value
        self.name = name
        self.inclusion = _check_inclusion(inclusion)
        self.id = target_id or _new_id()

    # Maximum length of a target value, per subrule type (EditSubruleParameter.jsp).
    MAX_LENGTHS = {'FILE': 256, 'KEY': 255, 'VALUE': 3070, 'PROCESS': 3070, 'SERVICE': 3070}

    def check(self, subrule_type, linux=False):
        """
        Raise ValueError if the console refuses the target of a subrule:
        length per subrule type (MAX_LENGTHS); Windows files: a drive type of
        APSubRule.DRIVE_TYPES, or a path accepted by
        trellix_epo.validators.is_ens_parameter_path.
        """
        check_length('Target value', self.value, self.MAX_LENGTHS.get(subrule_type, 3070),
                     required=True)
        if subrule_type == 'FILE' and not linux:
            if self.name == self.DRIVE_TYPE:
                if self.value not in APSubRule.DRIVE_TYPES:
                    raise ValueError('Drive type must be within {}.'.format(
                        list(APSubRule.DRIVE_TYPES)))
            elif not is_ens_parameter_path(self.value):
                raise ValueError('Invalid file, folder name, or file path: {!r}'.format(self.value))
        return self

    def __repr__(self):
        return 'APTarget({!r}, name={!r}, inclusion={!r})'.format(
            self.value, self.name, self.inclusion)

    def __eq__(self, other):
        return isinstance(other, APTarget) and vars(self) == vars(other)


class APSubRule():
    """
    A subrule of a user-defined Access Protection rule.

    :param name: The name.
    :param subrule_type: FILES, REGISTRY_KEY, REGISTRY_VALUE, PROCESSES or
                         SERVICES (Linux: FILES or PROCESSES).
    :param operations: A list of operation codes, see OPERATIONS (e.g.
                       ['create', 'write'] for FILES).
    :param targets: A list of APTarget (not for PROCESSES).
    :param executables: A list of APExecutable, the targets of a PROCESSES subrule.
    :param linux: True for a subrule of a Linux rule.
    """
    FILES, REGISTRY_KEY, REGISTRY_VALUE, PROCESSES, SERVICES = \
        'FILE', 'KEY', 'VALUE', 'PROCESS', 'SERVICE'
    TYPES = {'FILE': 'Files', 'KEY': 'Registry key', 'VALUE': 'Registry value',
             'PROCESS': 'Processes', 'SERVICE': 'Services'}
    # Operation codes and console labels, per subrule type.
    OPERATIONS = {
        'FILE': {'write_attribute': 'Change read-only or hidden attributes', 'create': 'Create',
                 'delete': 'Delete', 'execute': 'Execute', 'set_security': 'Change permissions',
                 'read': 'Read', 'rename': 'Rename', 'write': 'Write'},
        'KEY': {'write': 'Write', 'create': 'Create', 'delete': 'Delete', 'read': 'Read',
                'enum': 'Enumerate', 'load_key': 'Load', 'replace_key': 'Replace',
                'restore_key': 'Restore', 'set_security': 'Change permissions'},
        'VALUE': {'write': 'Write', 'create': 'Create', 'delete': 'Delete', 'read': 'Read'},
        'PROCESS': {'ex_proc_open_any': 'Any access', 'ex_proc_open_thread': 'Create thread',
                    'ex_proc_open_modify': 'Change', 'ex_proc_open_terminate': 'Terminate',
                    'ex_proc_run_target': 'Run'},
        'SERVICE': {'srv_start': 'Start', 'srv_stop': 'Stop', 'srv_pause': 'Pause',
                    'srv_continue': 'Continue', 'srv_create': 'Create', 'srv_delete': 'Delete',
                    'srv_profile_enable': 'Enable hardware profile',
                    'srv_profile_disable': 'Disable hardware profile',
                    'srv_startup': 'Change startup mode',
                    'srv_logon': 'Change logon information'},
    }
    LINUX_OPERATIONS = {
        'FILE': {'create': 'Create', 'delete': 'Delete', 'execute': 'Execute',
                 'set_security': 'Change permissions', 'read': 'Read', 'rename': 'Rename',
                 'write': 'Write', 'hardlink': 'Hard Link', 'symlink': 'Symlink',
                 'chown': 'Change owner'},
        'PROCESS': {'ex_proc_open_terminate': 'Terminate', 'ex_proc_run_target': 'Run'},
    }
    # Target labels (subrule "Targets" Name column), per subrule type.
    TARGET_NAMES = {('FILE', 'OBJECT_NAME'): 'File, folder name, or file path',
                    ('FILE', 'TARGET_OBJECT_NAME'): 'Destination file',
                    ('FILE', 'EXP_DRIVE_TYPE'): 'Drive type',
                    ('KEY', 'OBJECT_NAME'): 'Registry key path',
                    ('VALUE', 'OBJECT_NAME'): 'Registry value',
                    ('SERVICE', 'OBJECT_NAME'): 'Service registered name',
                    ('SERVICE', 'TARGET_OBJECT_NAME'): 'Service display name'}
    TARGET_TYPES = {'FILE': ['OBJECT_NAME', 'TARGET_OBJECT_NAME', 'EXP_DRIVE_TYPE'],
                    'KEY': ['OBJECT_NAME'], 'VALUE': ['OBJECT_NAME'],
                    'SERVICE': ['OBJECT_NAME', 'TARGET_OBJECT_NAME']}
    LINUX_TARGET_TYPES = {'FILE': ['OBJECT_NAME', 'TARGET_OBJECT_NAME']}
    DRIVE_TYPES = {'DT_REMOVABLE': 'Removable', 'DT_NETWORK': 'Network', 'DT_FIXED': 'Fixed',
                   'DT_CD_DVD': 'CD/DVD', 'DT_FLOPPY': 'Floppy'}
    # Operations of the original subrule format ("SubRule#n"): a subrule
    # using anything else is stored as "SubRule102#n" (ENS 10.2 format),
    # Services subrules as "SubRule105#n".
    __BASIC_OPERATIONS = {'FILE': {'create', 'delete', 'execute', 'read', 'rename', 'write'},
                          'KEY': {'create', 'delete', 'read', 'write'},
                          'VALUE': {'create', 'delete', 'read', 'write'}}

    def __init__(self, name, subrule_type, operations, targets=None, executables=None,
                 linux=False, subrule_id=None):
        if not name:
            raise ValueError('The subrule name is required.')
        types = self.LINUX_OPERATIONS if linux else self.OPERATIONS
        if subrule_type not in types:
            raise ValueError('Subrule type must be within {}.'.format(list(types)))
        if not operations:
            raise ValueError('Select at least one operation to apply to the subrule.')
        unknown = [op for op in operations if op not in types[subrule_type]]
        if unknown:
            raise ValueError('Unknown operation(s) for {}: {}.'.format(subrule_type, unknown))
        self.name = name
        self.type = subrule_type
        self.operations = list(operations)
        self.targets = []
        self.executables = []
        self.linux = linux
        self.id = subrule_id or _new_id()
        self.kind = None
        for target in targets or []:
            self.add_target(target)
        for executable in executables or []:
            self.add_executable(executable)

    def __repr__(self):
        return 'APSubRule({!r}, {!r}, {!r})'.format(self.name, self.type, self.operations)

    def __eq__(self, other):
        return isinstance(other, APSubRule) and vars(self) == vars(other)

    def check(self):
        """
        Raise ValueError if the console refuses the subrule: name of 100
        characters, valid targets and target executables (no duplicate
        executable name).
        """
        check_length('Subrule name', self.name, 100, required=True)
        for target in self.targets:
            target.check(self.type, self.linux)
        for executable in self.executables:
            executable.check(self.linux)
        _check_unique('Target executables', [executable.name for executable in self.executables])
        return self

    def add_target(self, target):
        """
        Add a target (APTarget). Not available for a PROCESSES subrule: use
        add_executable().
        """
        allowed = (self.LINUX_TARGET_TYPES if self.linux else self.TARGET_TYPES).get(self.type, [])
        if target.name not in allowed:
            raise ValueError('Target type {} is not valid for a {} subrule.'.format(
                target.name, self.type))
        if target.name == APTarget.DESTINATION_FILE and self.type == self.FILES and \
                self.operations != ['rename']:
            raise ValueError('Only the Rename operation is valid when a Destination file '
                             'parameter is set.')
        self.targets.append(target)
        return True

    def add_executable(self, executable):
        """
        Add a target executable (APExecutable) to a PROCESSES subrule.
        """
        if self.type != self.PROCESSES:
            raise ValueError('Only a Processes subrule has target executables.')
        self.executables.append(executable)
        return True

    def get_kind(self):
        """
        Returns the storage prefix: "SubRule", "SubRule102" or "SubRule105".
        A subrule read from a policy keeps its own.
        """
        if self.kind:
            return self.kind
        if self.type == self.SERVICES:
            return 'SubRule105'
        if self.linux:
            return 'SubRule'
        basic = self.__BASIC_OPERATIONS.get(self.type)
        if basic and set(self.operations) <= basic and \
                all(target.name == 'OBJECT_NAME' for target in self.targets):
            return 'SubRule'
        return 'SubRule102'

    @classmethod
    def from_values(cls, values, linux=False):
        subrules = []
        for kind in ['SubRule', 'SubRule102', 'SubRule105']:
            for row in range(int(values.get(kind + 'Count') or 0)):
                prefix = '{}#{}_'.format(kind, row)
                subrule = cls.__new__(cls)
                subrule.name = values.get(prefix + 'Name') or ''
                subrule.type = values.get(prefix + 'Class') or ''
                subrule.operations = (values.get(prefix + 'Operations') or '').split()
                subrule.linux = linux
                subrule.id = values.get(prefix + 'ID') or _new_id()
                subrule.kind = kind
                subrule.targets = []
                for param in range(int(values.get(prefix + 'ParameterCount') or 0)):
                    param_prefix = '{}Parameter#{}_'.format(prefix, param)
                    target = APTarget.__new__(APTarget)
                    target.value = values.get(param_prefix + 'Value') or ''
                    target.name = values.get(param_prefix + 'Name') or ''
                    target.inclusion = values.get(param_prefix + 'IncludeStatus') or 'include'
                    target.id = values.get(param_prefix + 'ID') or _new_id()
                    subrule.targets.append(target)
                subrule.executables = APExecutable.from_values(values, prefix)
                subrules.append(subrule)
        return subrules

    @staticmethod
    def to_values(subrules):
        """
        Returns the settings of a list of subrules (with the counts).
        """
        values = {}
        kinds = {'SubRule': [], 'SubRule102': [], 'SubRule105': []}
        for subrule in subrules:
            kinds[subrule.get_kind()].append(subrule)
        linux = any(subrule.linux for subrule in subrules)
        for kind, rows in kinds.items():
            # Windows rules always have the three counts, Linux rules one.
            if kind == 'SubRule' or not linux:
                values[kind + 'Count'] = str(len(rows))
            for row, subrule in enumerate(rows):
                prefix = '{}#{}_'.format(kind, row)
                values[prefix + 'Class'] = subrule.type
                values[prefix + 'ID'] = subrule.id
                values[prefix + 'Name'] = subrule.name
                values[prefix + 'Operations'] = ' '.join(sorted(subrule.operations))
                for param, target in enumerate(subrule.targets):
                    param_prefix = '{}Parameter#{}_'.format(prefix, param)
                    values[param_prefix + 'ID'] = target.id
                    values[param_prefix + 'IncludeStatus'] = target.inclusion
                    values[param_prefix + 'Name'] = target.name
                    values[param_prefix + 'Value'] = target.value
                values[prefix + 'ParameterCount'] = str(len(subrule.targets))
                values.update(APExecutable.to_values(subrule.executables, prefix, subrule.linux))
        return values


class APRule():
    """
    An Access Protection rule. User-defined rules can be created; for a
    Trellix-defined rule (origin TRELLIX), only block, report, executables
    and notes can be changed, as in the console.

    :param name: The name.
    :param block: True to block.
    :param report: True to report (deselecting both disables the rule).
    :param notes: Notes.
    :param linux: True for a Linux rule.
    """
    TRELLIX, USER = 'Trellix-defined', 'User-defined'

    def __init__(self, name, block=False, report=False, notes='', linux=False, rule_id=None):
        if not name:
            raise ValueError('The rule name is required.')
        self.id = rule_id or _new_id()
        self.name = name
        self.block = bool(block)
        self.report = bool(report)
        self.notes = notes
        self.linux = linux
        self.origin = self.USER
        self.executables = []
        self.user_names = []
        self.subrules = []
        self._raw_name = name
        self._extra = {}
        self._section = None

    def __repr__(self):
        return 'APRule({!r}, origin={!r}, os={!r})'.format(self.name, self.origin, self.os)

    @property
    def os(self):
        """
        'WINDOWS' or 'LINUX'.
        """
        return 'LINUX' if self.linux else 'WINDOWS'

    def is_enabled(self):
        """
        Returns False when both Block and Report are deselected.
        """
        return self.block or self.report

    def check(self, other_names=()):
        """
        Raise ValueError if the console refuses the rule: name of 128
        characters not used by another rule (other_names; case ignored),
        notes of 256 characters, valid executables (no duplicate name), user
        names and subrules.
        """
        check_length('Rule name', self.name, 128, required=True)
        _check_unique('Rule name', [self.name] + list(other_names))
        check_length('Notes', self.notes, 256)
        for executable in self.executables:
            executable.check(self.linux)
        _check_unique('Executables', [executable.name for executable in self.executables])
        for user_name in self.user_names:
            user_name.check(self.linux)
        for subrule in self.subrules:
            subrule.check()
        return self

    def add_executable(self, executable):
        """
        Add an executable (APExecutable).
        """
        self.executables.append(executable)
        return True

    def add_user_name(self, user_name):
        """
        Add a user name (APUserName). Not available for Trellix-defined rules.
        """
        if self.origin == self.TRELLIX:
            raise ValueError('User names cannot be added to a Trellix-defined rule.')
        self.user_names.append(user_name)
        return True

    def add_subrule(self, subrule):
        """
        Add a subrule (APSubRule). Not available for Trellix-defined rules.
        """
        if self.origin == self.TRELLIX:
            raise ValueError('Subrules cannot be added to a Trellix-defined rule.')
        if subrule.linux != self.linux:
            raise ValueError('The subrule and the rule must be for the same operating system.')
        self.subrules.append(subrule)
        return True

    def section_name(self):
        """
        Returns the Section name used to store the rule.
        """
        if self.linux:
            return 'APLinuxRule'
        # A rule read from a policy keeps its Section (ePO also has "APRule"
        # rules with ENS 10.2 subrules).
        if getattr(self, '_section', None):
            return self._section
        if any(subrule.get_kind() != 'SubRule' for subrule in self.subrules):
            return 'APRule102'
        return 'APRule'

    @classmethod
    def from_section(cls, section_obj, rule_names=None):
        values = {setting.get('name'): setting.get('value')
                  for setting in section_obj.findall('Setting')}
        rule = cls.__new__(cls)
        rule.id = values.get('RuleID') or ''
        rule.linux = section_obj.get('name') == 'APLinuxRule'
        rule.origin = cls.TRELLIX if values.get('RuleType') == 'Canned' else cls.USER
        rule._raw_name = values.get('RuleName') or ''
        rule._section = section_obj.get('name')
        if rule.origin == cls.TRELLIX:
            rule.name = (rule_names or {}).get(rule.id,
                                               rule._raw_name.replace('IDS_AP_RULE_', ''))
        else:
            rule.name = rule._raw_name
        rule.block = values.get('Block') == '1'
        rule.report = values.get('Report') == '1'
        rule.notes = values.get('Note') or ''
        rule.executables = APExecutable.from_values(values, '')
        rule.user_names = []
        for param in range(int(values.get('ParameterCount') or 0)):
            prefix = 'Parameter#{}_'.format(param)
            if values.get(prefix + 'Name') == 'EXP_USER_NAME':
                user = APUserName.__new__(APUserName)
                user.name = values.get(prefix + 'Value') or ''
                user.inclusion = values.get(prefix + 'IncludeStatus') or 'include'
                user.id = values.get(prefix + 'ID') or _new_id()
                rule.user_names.append(user)
        rule.subrules = APSubRule.from_values(values, rule.linux)
        # Settings not managed by this class are kept as they are (e.g. the
        # "SubRuleCount" = 0 of some Trellix-defined rules).
        rule._extra = {name: value for name, value in values.items()
                       if not rule.__managed(name)}
        return rule

    def __managed(self, name):
        managed = name in ['Block', 'Report', 'Note', 'RuleID', 'RuleName', 'RuleType'] or \
            name.startswith('Executable')
        if self.origin == self.USER:
            managed = managed or name.startswith(('Parameter', 'SubRule'))
        return managed

    def to_values(self):
        """
        Returns the settings of the rule, as stored by ePO.
        """
        values = dict(self._extra)
        values.update({'Block': '1' if self.block else '0', 'Report': '1' if self.report else '0',
                  'Note': self.notes, 'RuleID': self.id, 'RuleName': self._raw_name
                  if self.origin == self.TRELLIX else self.name,
                  'RuleType': 'Canned' if self.origin == self.TRELLIX else 'Custom'})
        values.update(APExecutable.to_values(self.executables, '', self.linux))
        if self.origin == self.USER:
            values['ParameterCount'] = str(len(self.user_names))
            for param, user in enumerate(self.user_names):
                prefix = 'Parameter#{}_'.format(param)
                values[prefix + 'ID'] = user.id
                values[prefix + 'IncludeStatus'] = user.inclusion
                values[prefix + 'Name'] = 'EXP_USER_NAME'
                values[prefix + 'Value'] = user.name
            values.update(APSubRule.to_values(self.subrules))
        return values


class ESTPPolicyAccessProtection(Policy):
    """
    The ESTPPolicyAccessProtection class can be used to edit the Endpoint
    Security Threat Prevention policy: Access Protection - module state,
    exclusions and rules (see APRule), checked against the ePO 5.10 console.
    """

    MD_PRODUCT = 'Endpoint Security Threat Prevention'
    MD_CATEGORY = 'Access Protection'

    # Console names of the Trellix-defined rules (RuleName holds a resource
    # ID such as IDS_AP_RULE_ALTER_USERRIGHTPOLICY), read from the ePO 5.10
    # console.
    RULE_NAMES = {
        'ALTER_USERRIGHTPOLICY': 'Altering user rights policies',
        'PREVENT_LAUNCHING_PROGRAMFILES': 'Browsers launching files from the Downloaded '
                                          'Program Files folder',
        'ALTER_FILE_EXT': 'Changing any file extension registrations',
        'PREVENT_CREATION_PROGRAMFILES': 'Creating new executable files in the Program Files '
                                         'folder',
        'PREVENT_CREATION_WINDOWS': 'Creating new executable files in the Windows folder',
        'PREVENT_CREATION_LINK_SYSTEMFILES_LINUX': 'Creation of a link to critical system files',
        'DISABLE_REGTASK': 'Disabling Registry Editor and Task Manager',
        'PREVENT_PROCESS_DOPPELGANGING_ATTACK': 'Doppelganging attacks on processes',
        'PREVENT_MIMIKATZ_CREATION': 'Executing Mimikatz malware',
        'PREVENT_WSL_EXECUTION': 'Executing Windows Subsystem for Linux',
        'HIJACK_EXE': 'Hijacking .EXE and other executable extensions',
        'INSTALL_BHO': 'Installing Browser Helper Objects or Shell Extensions',
        'INSTALL_NEWCLSIDS': 'Installing new CLSIDs, APPIDs, and TYPELIBs',
        'PREVENT_MODIFICATION_PASSWORDFILES_LINUX': 'Modify or remove the "passwd" or "shadow" '
                                                    'files by a process other than passwd',
        'SPOOF_WIN_PROCESS': 'Modifying core Windows Processes',
        'PROTECT_IE_SETTINGS': 'Modifying Internet Explorer settings',
        'PROTECT_NETWORK_SETTINGS': 'Modifying network settings',
        'PREVENT_CREATE_DELETE_RENAME_HARDLINK_STARTUPFILES_LINUX':
            'Prevent create, delete, link or rename operations for Startup files',
        'EXE_SCRIPT_TEMP': 'Prevent CScript.exe or WScript.exe from creating files in windows '
                           'temp directory, its subfolders, and common user folders',
        'PREVENT_PERMISSION_OWNERSHIP_STARTUPFILES_LINUX':
            'Prevent Modification of the attributes, permissions or ownership for Startup files',
        'PREVENT_READ_WRITE_DELETE_RENAME_HARDLINK_PERMISSION_OWNERSHIP_VMWARE_DEVICES_LINUX':
            'Prevent non-VMware processes from accessing VMware devices',
        'PREVENT_WRITE_STARTUPFILES_LINUX': 'Prevent write operation for Startup files',
        'PROTECT_ENS_LOG_FOLDER': 'Protect Endpoint Security logs folder',
        'PREVENT_WRITE_DELETE_RENAME_HARDLINK_PERMISSION_OWNERSHIP_VMWARE_CONFIGFILES_LINUX':
            'Protection for VMware configuration files',
        'PREVENT_PROGRAMS_AUTORUN': 'Registering of programs to autorun',
        'ENABLE_SHARES_RW': 'Remotely accessing local files or folders',
        'CREATE_AUTORUN': 'Remotely creating autorun files',
        'MAKE_SHARES_RO': 'Remotely creating or modifying files or folders',
        'REMOTE_MODIFY': 'Remotely creating or modifying Portable Executable, .INI, .PIF file '
                         'types, and core system locations',
        'EXE_FILES_TEMP': 'Running files from common user folders',
        'PREVENT_FILES_TEMP': 'Running files from common user folders by common programs',
        'PREVENT_PROCESS_LAUNCH_ESCONFIGTOOL': 'Unauthorized execution of EsConfigTool',
    }
    # Kept for compatibility: see APSubRule.
    SUBRULE_TYPES = APSubRule.TYPES
    OPERATIONS = APSubRule.OPERATIONS
    TARGET_NAMES = APSubRule.TARGET_NAMES

    __RULE_SECTIONS = ['APRule', 'APRule102', 'APLinuxRule']
    # Bitmask of the legacy "APRules" section (Rule_<n> = "<RuleID>|<mask>|...").
    __BLOCK, __REPORT = 1, 2

    def __init__(self, policy_from_estppolicies=None):
        super(ESTPPolicyAccessProtection, self).__init__(policy_from_estppolicies)
        if policy_from_estppolicies is not None:
            if self.get_type() != 'EAM_BehaviorBlock_Policies':
                raise ValueError('Wrong policy! Policy type must be "EAM_BehaviorBlock_Policies".')

    def _info_counts(self):
        """
        The counts of get_info() and of the representation: the rules and exclusions.
        """
        return {'rules': len(self.get_rules()), 'exclusions': len(self.get_exclusions())}

    def __rule_sections(self):
        for settings_obj in self.root.findall('EPOPolicySettings'):
            section_obj = settings_obj.find('Section')
            if section_obj is not None and section_obj.get('name') in self.__RULE_SECTIONS:
                yield settings_obj, section_obj

    def __find_rule(self, rule_id):
        for settings_obj, section_obj in self.__rule_sections():
            setting = section_obj.find('Setting[@name="RuleID"]')
            if setting is not None and setting.get('value') == rule_id:
                return settings_obj, section_obj
        return None, None

    @staticmethod
    def __write_section(section_obj, values):
        for setting in list(section_obj):
            section_obj.remove(setting)
        for name in sorted(values):
            et.SubElement(section_obj, 'Setting', {'name': name, 'value': values[name]})

    # ------------------------------ Access Protection Policy ------------------------------
    # Access Protection: Enable Access Protection
    def get_access_protection(self):
        """
        Get the Enable Access Protection state
        """
        return self.get_setting_value('BehaviorBlockAP', 'APEnabled')

    def set_access_protection(self, mode):
        """
        Set the Enable Access Protection state
        """
        return self.set_setting_value('BehaviorBlockAP', 'APEnabled', mode)

    access_protection = property(get_access_protection, set_access_protection)

    # Exclusions: Name, File Name or Path, MD5 Hash, Signer, Notes, Operating System
    def get_exclusions(self):
        """
        Get the exclusions (Windows): a list of APExecutable.
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="BehaviorBlockAP"]')
        if section_obj is None:
            return None
        values = {setting.get('name'): setting.get('value')
                  for setting in section_obj.findall('Setting')}
        return APExecutable.from_values(values, '')

    def set_exclusions(self, executables):
        """
        Set the exclusions (Windows) from a list of APExecutable (their
        inclusion status is forced to 'exclude').
        """
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="BehaviorBlockAP"]')
        if section_obj is None:
            return False
        for executable in executables:
            executable.check()
            executable.inclusion = 'exclude'
        _check_unique('Exclusions', [executable.name for executable in executables])
        had_count = section_obj.find('Setting[@name="ExecutableCount"]') is not None
        values = {setting.get('name'): setting.get('value')
                  for setting in section_obj.findall('Setting')
                  if not setting.get('name').startswith('Executable')}
        if executables or had_count:
            values.update(APExecutable.to_values(executables, ''))
        # Also kept by ePO as a comma separated list of the paths.
        values['szGlobalExcludedProcesses'] = ','.join(executable.path for executable in executables
                                                       if executable.path)
        self.__write_section(section_obj, values)
        return True

    def add_exclusion(self, executable):
        """
        Add an exclusion (APExecutable).
        """
        return self.set_exclusions((self.get_exclusions() or []) + [executable])

    # Rules: Block, Report, Rule, Notes, Origin, Operating System
    def get_rules(self):
        """
        Get the rules (list of APRule), sorted as in the console:
        User-defined first, then by name.
        """
        rules = [APRule.from_section(section_obj, self.RULE_NAMES)
                 for _, section_obj in self.__rule_sections()]
        return sorted(rules, key=lambda rule: (rule.origin != APRule.USER, rule.name.lower()))

    def get_rule(self, name_or_id):
        """
        Get a rule (APRule) by RuleID or by name, or None.
        """
        for rule in self.get_rules():
            if name_or_id in [rule.id, rule.name]:
                return rule
        return None

    def add_rule(self, rule):
        """
        Add a user-defined rule (APRule). It must have at least one subrule,
        and each subrule at least one target (or target executable).
        """
        if rule.origin != APRule.USER:
            raise ValueError('Only user-defined rules can be added.')
        if self.__find_rule(rule.id)[0] is not None:
            raise ValueError('A rule with the ID {} already exists.'.format(rule.id))
        self.__check_rule(rule)
        rule.check(self.__other_rule_names(rule))
        policy_obj = self.root.find('EPOPolicyObject')
        settings_name = 'AccessProtectionSettings_Rule_{} ({})'.format(
            rule.id, str(uuid.uuid4()).upper())
        attrib = {'name': settings_name, 'featureid': policy_obj.get('featureid'),
                  'categoryid': policy_obj.get('categoryid'), 'typeid': policy_obj.get('typeid'),
                  'param_int': '', 'param_str': ''}
        settings_obj = et.Element('EPOPolicySettings', attrib)
        section_obj = et.SubElement(settings_obj, 'Section', {'name': rule.section_name()})
        self.__write_section(section_obj, rule.to_values())
        # The settings are listed before the EPOPolicyObject, as in exports.
        self.root.insert(list(self.root).index(policy_obj), settings_obj)
        et.SubElement(policy_obj, 'PolicySettings').text = settings_name
        return True

    def update_rule(self, rule):
        """
        Save a rule (APRule) read with get_rules()/get_rule() and changed.
        """
        _, section_obj = self.__find_rule(rule.id)
        if section_obj is None:
            return False
        if rule.origin == APRule.USER:
            self.__check_rule(rule)
            rule.check(self.__other_rule_names(rule))
            section_obj.set('name', rule.section_name())
        else:
            # Trellix-defined: only block, report, executables and notes change.
            check_length('Notes', rule.notes, 256)
            for executable in rule.executables:
                executable.check(rule.linux)
            _check_unique('Executables', [executable.name for executable in rule.executables])
        self.__write_section(section_obj, rule.to_values())
        self.__update_legacy_rules(rule)
        return True

    def remove_rule(self, rule_id):
        """
        Remove a user-defined rule by RuleID.
        """
        settings_obj, section_obj = self.__find_rule(rule_id)
        if settings_obj is None:
            return False
        if APRule.from_section(section_obj).origin != APRule.USER:
            raise ValueError('Trellix-defined rules cannot be removed.')
        self.root.remove(settings_obj)
        policy_obj = self.root.find('EPOPolicyObject')
        for reference in policy_obj.findall('PolicySettings'):
            if reference.text == settings_obj.get('name'):
                policy_obj.remove(reference)
        return True

    def __other_rule_names(self, rule):
        return [other.name for other in self.get_rules() if other.id != rule.id]

    @staticmethod
    def __check_rule(rule):
        if not rule.subrules:
            raise ValueError('Add at least one subrule to the rule "{}".'.format(rule.name))
        for subrule in rule.subrules:
            if not subrule.targets and not subrule.executables:
                raise ValueError('Add at least one target to the subrule "{}".'.format(
                    subrule.name))

    def __update_legacy_rules(self, rule):
        # The console keeps the Block/Report mask of "APRules" in sync.
        section_obj = self.root.find('./EPOPolicySettings/Section[@name="APRules"]')
        if section_obj is None:
            return
        for setting in section_obj.findall('Setting'):
            fields = (setting.get('value') or '').split('|')
            if setting.get('name').startswith('Rule_') and fields[0] == rule.id and \
                    len(fields) >= 2:
                fields[1] = str((self.__BLOCK if rule.block else 0) +
                                (self.__REPORT if rule.report else 0))
                setting.set('value', '|'.join(fields))

    def set_rule_block(self, rule_id, mode):
        """
        Set the Block action of a rule (RuleID, e.g. 'PREVENT_MIMIKATZ_CREATION').
        Deselecting both Block and Report disables the rule.
        """
        rule = self.get_rule(rule_id)
        if rule is None:
            return False
        rule.block = mode == '1'
        return self.update_rule(rule)

    def set_rule_report(self, rule_id, mode):
        """
        Set the Report action of a rule (RuleID).
        """
        rule = self.get_rule(rule_id)
        if rule is None:
            return False
        rule.report = mode == '1'
        return self.update_rule(rule)

    # ------------------------------ Markdown export ------------------------------
    def __md_executables(self, executables, inclusion=True):
        headers = ['Name', 'File Name or Path', 'MD5 Hash', 'Signer']
        headers += ['Inclusion Status'] if inclusion else []
        rows = [[exe.name, exe.path, exe.md5,
                 'Any' if exe.signer == APExecutable.ANY_SIGNATURE else exe.signer] +
                ([exe.inclusion.capitalize()] if inclusion else []) + [exe.notes]
                for exe in executables]
        return self.md_table(headers + ['Notes'], rows, numbered=True)

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        check = self.md_check
        yes_no = lambda flag: 'Yes' if flag else 'No'
        sections = [('Access Protection', self.md_settings([
            ['Enable Access Protection', check(self.get_access_protection())]]))]
        sections.append(('Exclusions', self.md_table(
            ['Name', 'File Name or Path', 'MD5 Hash', 'Signer', 'Notes', 'Operating System'],
            [[exe.name, exe.path, exe.md5,
              'Any' if exe.signer == APExecutable.ANY_SIGNATURE else exe.signer, exe.notes,
              'WINDOWS'] for exe in self.get_exclusions() or []], numbered=True)))
        rules = self.get_rules()
        text = 'Deselecting both Block and Report will disable the Rule.\n\n'
        text += self.md_table(['Block', 'Report', 'Rule', 'Notes', 'Origin', 'Operating System'],
                              [[yes_no(rule.block), yes_no(rule.report), rule.name, rule.notes,
                                rule.origin, rule.os] for rule in rules], numbered=True)
        sections.append(('Rules', text))
        details = ''
        for index, rule in enumerate(rules, 1):
            if not (rule.executables or rule.user_names or rule.subrules):
                continue
            details += '\n### {}. {}\n\n'.format(index, self.md_heading(rule.name))
            details += self.md_settings([
                ['Action: Block', yes_no(rule.block)], ['Action: Report', yes_no(rule.report)],
                ['Origin', rule.origin], ['Operating System', rule.os], ['Notes', rule.notes]])
            details += '\nExecutables:\n\n' + self.__md_executables(rule.executables)
            if rule.origin == APRule.USER:
                details += '\nUser Names:\n\n' + self.md_table(
                    ['Name', 'Inclusion Status'],
                    [[user.name, user.inclusion.capitalize()] for user in rule.user_names],
                    numbered=True)
            for subrule in rule.subrules:
                typ = subrule.type
                operations = (APSubRule.LINUX_OPERATIONS if subrule.linux
                              else APSubRule.OPERATIONS).get(typ, {})
                details += '\n#### Subrule: {}\n\n'.format(self.md_heading(subrule.name))
                details += self.md_settings([
                    ['Subrule type', APSubRule.TYPES.get(typ, typ)],
                    ['Operations', ', '.join(operations.get(op, op)
                                             for op in subrule.operations)]])
                if subrule.targets:
                    details += '\nTargets:\n\n' + self.md_table(
                        ['Inclusion status', 'Name', 'Value'],
                        [[target.inclusion.capitalize(),
                          APSubRule.TARGET_NAMES.get((typ, target.name), target.name),
                          APSubRule.DRIVE_TYPES.get(target.value, target.value)
                          if target.name == APTarget.DRIVE_TYPE else target.value]
                         for target in subrule.targets], numbered=True)
                if subrule.executables:
                    details += '\nTargets (executables):\n\n' + \
                        self.__md_executables(subrule.executables)
        if details:
            sections.append(('Rule details', 'Rules with executables, user names or subrules, '
                                             'numbered as in the rule list.\n' + details))
        return sections
