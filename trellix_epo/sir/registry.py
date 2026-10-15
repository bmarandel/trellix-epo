# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes SIRPolicySetRegistry (System Information
Reporter: Set Registry > Registry General) and SIRRegistryValue.

Storage learnt from a test policy changed in the ePO 5.10 console (section
SetRegistry):

- Registry values: dwSetRegistryCount and for each one (numbered from 1)
  RegName_<n>, RegKey_<n> (Key\\Value; a key ending with \\ has no type nor
  data), RegType_<n>, RegValue_<n>, action_name_<n> (0 = Create, 1 =
  Delete) and flag_<n> (Create: 0 = Only if (does not exist), 1 = Overwrite
  existing; Delete: Key 1 + Value 2 + Data 4).
- The console requires a registry backup file name to save registry
  values; at each save it records RegistryBackupFile and appends
  ";<name>" to RegistryBackupFileList, ";<date>" to
  RegistryBackupFileDateList and ";<keys>" to szBackupKeyList (the parent
  key of each value, backslashes doubled, each followed by ", "), and
  renews the PolicyChangeVersion GUID. The library does the same.
- Registry Restore: RegRestoreFile, a backup file name ('' = Do not restore
  any file).
"""

import datetime
import re
import uuid

from ..policies import Policy
from .collect import check_registry_path, check_characters


class SIRRegistryValue():
    """
    A registry value set or deleted by the policy.

    :param: name: Name.
    :param: key: Key\\Value, e.g. '[HKLM]\\SOFTWARE\\Example\\Value' (ending
                 with \\ for a key without value).
    :param: reg_type: REG_DWORD, REG_SZ, REG_MULTI_SZ, REG_BINARY or REG_EXPAND_SZ.
    :param: data: Data.
    :param: action: CREATE ('0') or DELETE ('1').
    :param: flag: Create: ONLY_IF_NEW (0) or OVERWRITE (1); Delete: a sum of
                  DELETE_KEY (1), DELETE_VALUE (2) and DELETE_DATA (4).
    """
    CREATE, DELETE = '0', '1'
    ONLY_IF_NEW, OVERWRITE = 0, 1
    DELETE_KEY, DELETE_VALUE, DELETE_DATA = 1, 2, 4
    TYPES = ['REG_DWORD', 'REG_SZ', 'REG_MULTI_SZ', 'REG_BINARY', 'REG_EXPAND_SZ']

    def __init__(self, name, key, reg_type='REG_SZ', data='', action=CREATE, flag=ONLY_IF_NEW):
        self.name = name
        self.key = key
        self.reg_type = reg_type
        self.data = str(data)
        if reg_type == 'REG_BINARY' and len(self.data) % 2:
            self.data += '0'    # the console completes an odd number of digits
        self.action = str(action)
        self.flag = int(flag)

    def __repr__(self):
        return 'SIRRegistryValue({!r}, {!r}, {!r}, {!r}, action={!r}, flag={!r})'.format(
            self.name, self.key, self.reg_type, self.data, self.action, self.flag)

    def __eq__(self, other):
        return isinstance(other, SIRRegistryValue) and vars(self) == vars(other)

    @classmethod
    def create(cls, name, key, reg_type, data, overwrite=False):
        """
        A value to create (overwrite: Overwrite existing, else Only if (does
        not exist)).
        """
        return cls(name, key, reg_type, data, cls.CREATE,
                   cls.OVERWRITE if overwrite else cls.ONLY_IF_NEW)

    @classmethod
    def delete(cls, name, key, what=DELETE_VALUE):
        """
        A key/value/data to delete. As in the console, deleting the key also
        deletes the value and the data, deleting the value also the data.
        """
        if what & cls.DELETE_KEY:
            what = 7
        elif what & cls.DELETE_VALUE:
            what = 6
        return cls(name, key, 'REG_SZ', '', cls.DELETE, what or cls.DELETE_DATA)

    def check(self):
        """
        Raise ValueError if the console would refuse the value (Set Registry
        page of SIR 1.0.x, compared on the lab): name 255 and key 1000
        characters, data 400 (textarea), none of them with " or ;; a key
        starting with a hive ([HKLM]\\...); REG_DWORD data of digits, at most
        4294967295; REG_BINARY data of hexadecimal digits; REG_SZ and
        REG_EXPAND_SZ data on one line; a key ending with \\ (key creation)
        has no data and the REG_SZ type.
        """
        if not self.key:
            raise ValueError('The Key\\Value is required.')
        check_registry_path(self.key)
        for text in (self.name, self.data):
            check_characters(text)
        if len(self.key) > 1000 or len(self.name) > 255 or len(self.data) > 400:
            raise ValueError('Name, Key\\Value and Data are limited to 255, 1000 and 400 '
                             'characters.')
        if self.reg_type not in self.TYPES:
            raise ValueError('The type must be within {}.'.format(self.TYPES))
        if self.key.endswith('\\') and (self.data or self.reg_type != 'REG_SZ'):
            raise ValueError('A key (ending with \\) has no type nor data.')
        if self.reg_type == 'REG_DWORD' and self.data and \
                not (self.data.isdigit() and self.data.isascii() and int(self.data) < 2 ** 32):
            raise ValueError('Not a valid Decimal DWORD number: {!r}'.format(self.data))
        if self.reg_type == 'REG_BINARY' and not all(c in '0123456789abcdefABCDEF'
                                                     for c in self.data):
            raise ValueError('Not a valid Hexadecimal number: {!r}'.format(self.data))
        if self.reg_type in ('REG_SZ', 'REG_EXPAND_SZ') and '\n' in self.data:
            raise ValueError('Multiline strings are not allowed.')
        if self.action == self.CREATE and self.flag not in (self.ONLY_IF_NEW, self.OVERWRITE):
            raise ValueError('Create flag must be 0 (only if new) or 1 (overwrite).')
        if self.action == self.DELETE and self.flag not in (0, 4, 6, 7):
            raise ValueError('Delete flag must be 4 (data), 6 (value and data) or 7 (key, '
                             'value and data).')
        if self.action not in (self.CREATE, self.DELETE):
            raise ValueError('The action must be "0" (Create) or "1" (Delete).')

    @property
    def action_label(self):
        """
        The action as described in the console.
        """
        if self.action == self.CREATE:
            return 'Create: ' + ('Overwrite existing' if self.flag == self.OVERWRITE
                                 else 'Only if (does not exist)')
        parts = [label for bit, label in [(self.DELETE_KEY, 'Key'), (self.DELETE_VALUE, 'Value'),
                                          (self.DELETE_DATA, 'Data')] if self.flag & bit]
        return 'Delete: ' + ', '.join(parts)


class SIRPolicySetRegistry(Policy):
    """
    The SIRPolicySetRegistry class can be used to edit the System Information
    Reporter policy: Set Registry > Registry General (tabs Set Registry and
    Registry Restore).
    """
    FEATURE = 'SIR_____1000_SET_REGISTRY'
    MD_PRODUCT = 'System Information Reporter'
    MD_CATEGORY = 'Set Registry - Registry General'
    SECTION = 'SetRegistry'
    WARNING = ('Using System Information Reporter(SIR) incorrectly can cause serious, '
               'system-wide problems that may require you to re-install Windows to correct them. '
               'Trellix cannot guarantee that any problems resulting from the use of SIR can be '
               'solved. Use this tool at your own risk.')

    def __init__(self, policy_from_sirpolicies=None):
        super(SIRPolicySetRegistry, self).__init__(policy_from_sirpolicies)
        if policy_from_sirpolicies is not None and self.get_product() != self.FEATURE:
            raise ValueError('Wrong policy! Policy feature must be "{}".'.format(self.FEATURE))

    def __repr__(self):
        return 'SIRPolicySetRegistry()'

    def __get(self, setting):
        return self.get_setting_value(self.SECTION, setting) or ''

    def __set(self, setting, value):
        return self.set_setting_value(self.SECTION, setting, str(value), True)

    # ------------------------------ Set Registry ------------------------------
    def get_values(self):
        """
        Get the registry values (list of SIRRegistryValue).
        """
        values = []
        for row in range(1, int(self.__get('dwSetRegistryCount') or 0) + 1):
            values.append(SIRRegistryValue(
                self.__get('RegName_{}'.format(row)), self.__get('RegKey_{}'.format(row)),
                self.__get('RegType_{}'.format(row)) or 'REG_SZ',
                self.__get('RegValue_{}'.format(row)),
                self.__get('action_name_{}'.format(row)) or SIRRegistryValue.CREATE,
                int(self.__get('flag_{}'.format(row)) or 0)))
        return values

    def get_backup_file(self):
        """
        Get the Registry Backup File Name of the last change.
        """
        return self.__get('RegistryBackupFile')

    def set_values(self, values, backup_file, date=None):
        """
        Set the registry values (list of SIRRegistryValue). As in the
        console, a new registry backup file name (20 characters max) is
        required: it is added to the backups that Registry Restore offers.

        :param: date: The backup date (datetime, default now).
        """
        for value in values:
            value.check()
        backup_file = str(backup_file or '').strip()
        if not backup_file or len(backup_file) > 20 or \
                not re.fullmatch(r'[A-Za-z0-9 _.]+', backup_file):
            raise ValueError('A registry backup file name (1-20 letters, digits, spaces, _ or '
                             '.) is required: {!r}'.format(backup_file))
        if backup_file.lower() in [backup['name'].lower() for backup in self.get_backups()]:
            raise ValueError('The backup file {!r} already exists.'.format(backup_file))
        section = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(self.SECTION))
        for setting_obj in section.findall('Setting'):
            if setting_obj.get('name').split('_')[0] in ('RegName', 'RegKey', 'RegType',
                                                          'RegValue', 'action', 'flag'):
                section.remove(setting_obj)
        for row, value in enumerate(values, 1):
            for setting, data in [('RegKey', value.key), ('RegName', value.name),
                                  ('RegType', value.reg_type), ('RegValue', value.data),
                                  ('action_name', value.action), ('flag', value.flag)]:
                self.__set('{}_{}'.format(setting, row), data)
        self.__set('dwSetRegistryCount', len(values))
        keys = []
        for value in values:
            parent = value.key.rsplit('\\', 1)[0] + '\\'
            if parent not in keys:
                keys.append(parent)
        stamp = (date or datetime.datetime.now()).strftime('%d %b %Y, %I:%M %p')
        self.__set('RegistryBackupFile', backup_file)
        self.__set('RegistryBackupFileList', self.__get('RegistryBackupFileList') + ';' + backup_file)
        self.__set('RegistryBackupFileDateList',
                   self.__get('RegistryBackupFileDateList') + ';' + stamp)
        self.__set('szBackupKeyList', self.__get('szBackupKeyList') + ';' +
                   ''.join(key.replace('\\', '\\\\') + ', ' for key in keys))
        return self.__set('PolicyChangeVersion', str(uuid.uuid4()))

    # ------------------------------ Registry Restore ------------------------------
    def get_backups(self):
        """
        Get the registry backups offered by Registry Restore: a list of
        dicts {'name', 'keys', 'date'}.
        """
        split = lambda setting: self.__get(setting).split(';')[1:]
        names, dates = split('RegistryBackupFileList'), split('RegistryBackupFileDateList')
        keys = split('szBackupKeyList')
        return [{'name': name,
                 'keys': (keys[index] if index < len(keys) else '').replace('\\\\', '\\'),
                 'date': dates[index] if index < len(dates) else ''}
                for index, name in enumerate(names)]

    def get_restore_file(self):
        """
        Get the backup file to restore ('' = Do not restore any file).
        """
        return self.__get('RegRestoreFile')

    def set_restore_file(self, name):
        """
        Set the backup file to restore ('' = Do not restore any file).
        """
        if name and name not in [backup['name'] for backup in self.get_backups()]:
            raise ValueError('Unknown registry backup file: {!r}'.format(name))
        self.__set('RegRestoreFile', name or '')
        return self.__set('PolicyChangeVersion', str(uuid.uuid4()))

    restore_file = property(get_restore_file, set_restore_file)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        text = '**Warning:** ' + self.WARNING + '\n\n'
        text += self.md_settings([['Registry Backup File Name', self.get_backup_file()]])
        text += '\n### Set Registry Values\n\n' + self.md_table(
            ['Name', 'Key\\Value', 'Type', 'Data', 'Action'],
            [[value.name, value.key, value.reg_type if value.action == SIRRegistryValue.CREATE
              else '', value.data if value.action == SIRRegistryValue.CREATE else '',
              value.action_label] for value in self.get_values()], numbered=True)
        restore = self.md_settings([['Select the file to restore',
                                     self.get_restore_file() or 'Do not restore any file']])
        restore += '\n### Registry backup files\n\n' + self.md_table(
            ['File', 'Keys', 'Date'],
            [[backup['name'], backup['keys'].rstrip(', '), backup['date']]
             for backup in self.get_backups()], numbered=True)
        return [('Set Registry', text), ('Registry Restore', restore)]
