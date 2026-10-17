# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class SIRPolicyCollectData (System Information
Reporter: Collect Data > General).

Storage learnt from a test policy changed in the ePO 5.10 console:

- General.CollectionFlags: one bit per "Collect data for" checkbox, in the
  console order (bit 0 USB devices ... bit 11 Installed Patches).
- Custom: dwHourlyInterval, dwOnPolicyChangeGetProps, szPolicyStartDateTime
  ("YYYY-MM-DD HH:MM:SS"), dwDebugLog and PolicyChangeVersionGetProps, a
  GUID the console renews at each save (the library renews it too). The
  first three are missing until set in the console.
- SpecialEnvironment.CustomEnvVar; List.Branch<n> (dwItemCount): registry
  values to query; FindFile.SearchPattern<n> (FileCount), FolderPattern<n>
  (FolderCount) and dwSearchDepth.
- The console only accepts registry paths starting with a hive ([HKLM]\\,
  [HKCU]\\, [HKCR]\\, [HKU]\\, [HKCC]\\) and file or folder paths starting with
  [SYSTEMDRIVE]\\, [SystemRoot]\\, [PROGRAMFILES]\\, [COMMONPROGRAMFILES]\\ or a
  drive {A}\\ to {Z}\\ (a file not ending with \\).
"""

import datetime
import uuid

from ..policies import Policy
from ..validators import check_int, check_length

HIVES = ('[HKLM]\\', '[HKCU]\\', '[HKCR]\\', '[HKU]\\', '[HKCC]\\')


def check_registry_path(path):
    """
    Raise ValueError if the console would refuse the registry path (hive
    prefix, any case but the console's, without " or ;).
    """
    if not str(path).startswith(HIVES):
        raise ValueError('A registry path must start with {}: {!r}'.format(
            ', '.join(HIVES), path))
    check_characters(path)


def check_characters(text):
    """
    Raise ValueError if the text holds a double quote or a semicolon
    (charexist of the console pages).
    """
    if '"' in str(text) or ';' in str(text):
        raise ValueError('Double quote (") and semicolon (;) are not allowed: {!r}'.format(text))
    return text


def check_unique(values, label):
    """
    Raise ValueError if a value is in the list twice (case ignored, as the
    console Add buttons do).
    """
    seen = set()
    for value in values:
        if str(value).lower() in seen:
            raise ValueError('{} already in the list: {!r}'.format(label, value))
        seen.add(str(value).lower())


class SIRPolicyCollectData(Policy):
    """
    The SIRPolicyCollectData class can be used to edit the System
    Information Reporter policy: Collect Data > General (tabs General,
    Custom and Find File).
    """
    FEATURE = 'SIR_____1000_COLLECT_DATA'
    MD_PRODUCT = 'System Information Reporter'
    MD_CATEGORY = 'Collect Data - General'

    # "Collect data for" checkboxes, in the console (and bit) order.
    ITEMS = [('usb', 'USB devices'),
             ('environment', 'Environment Variables (in SYSTEM context)'),
             ('network_cards', 'Installed Network cards'),
             ('shares', 'Shares'),
             ('msi', 'MSI Version'),
             ('services', 'Services installed (stating status at property collection)'),
             ('software', 'Installed Software'),
             ('path', 'Path (in SYSTEM context)'),
             ('ie', 'Internet Explorer version'),
             ('null_sessions', 'NullSession shares and pipes'),
             ('processes', 'Running processes at property collection'),
             ('patches', 'Installed Patches')]
    FILE_PREFIXES = ('[SYSTEMDRIVE]\\', '[SystemRoot]\\', '[PROGRAMFILES]\\',
                     '[COMMONPROGRAMFILES]\\') + tuple('{%s}\\' % chr(c)
                                                     for c in range(ord('A'), ord('Z') + 1))

    def __init__(self, policy_from_sirpolicies=None):
        super(SIRPolicyCollectData, self).__init__(policy_from_sirpolicies)
        if policy_from_sirpolicies is not None and self.get_product() != self.FEATURE:
            raise ValueError('Wrong policy! Policy feature must be "{}".'.format(self.FEATURE))

    def _info_counts(self):
        """
        The counts of get_info() and of the representation: the registry queries, files and folders.
        """
        return {'registry_queries': len(self.get_registry_queries()), 'files': len(self.get_files()),
                'folders': len(self.get_folders())}

    def __set(self, section, setting, value):
        """
        Set a setting (created if missing) and renew the policy change
        version, as the console does at each save.
        """
        self.set_setting_value(section, setting, str(value), True)
        self.set_setting_value('Custom', 'PolicyChangeVersionGetProps', str(uuid.uuid4()), True)
        return True

    def __set_list(self, section, count, template, values):
        self.set_indexed_list(section, count, template, [str(value) for value in values])
        self.set_setting_value('Custom', 'PolicyChangeVersionGetProps', str(uuid.uuid4()), True)
        return True

    @staticmethod
    def __check_mode(mode):
        if str(mode) not in ['0', '1']:
            raise ValueError('The state must be "1" or "0".')
        return str(mode)

    # ------------------------------ General ------------------------------
    def __flags(self):
        return int(self.get_setting_value('General', 'CollectionFlags') or 0)

    def get_collect(self, item):
        """
        Get state of a "Collect data for" item ('1' or '0'), e.g.
        get_collect('usb'). See SIRPolicyCollectData.ITEMS.
        """
        bit = [key for key, _ in self.ITEMS].index(item)
        return '1' if self.__flags() >> bit & 1 else '0'

    def set_collect(self, item, mode):
        """
        Set state of a "Collect data for" item ('1' or '0'), e.g.
        set_collect('processes', '1').
        """
        bit = [key for key, _ in self.ITEMS].index(item)
        flags = self.__flags() & ~(1 << bit)
        if self.__check_mode(mode) == '1':
            flags |= 1 << bit
        return self.__set('General', 'CollectionFlags', flags)

    def set_collect_all(self, mode):
        """
        Select/Deselect all the "Collect data for" items ('1' or '0').
        """
        flags = (1 << len(self.ITEMS)) - 1 if self.__check_mode(mode) == '1' else 0
        return self.__set('General', 'CollectionFlags', flags)

    # ------------------------------ Custom ------------------------------
    def get_environment_variable(self):
        """
        Get the custom environment variable to get the value of (needs to be
        set in System context).
        """
        return self.get_setting_value('SpecialEnvironment', 'CustomEnvVar') or ''

    def set_environment_variable(self, name):
        """
        Set the custom environment variable to get the value of (255
        characters max, '' = none).
        """
        if len(name or '') > 255:
            raise ValueError('The environment variable name is limited to 255 characters.')
        return self.__set('SpecialEnvironment', 'CustomEnvVar', name or '')

    environment_variable = property(get_environment_variable, set_environment_variable)

    def get_registry_queries(self):
        """
        Get the registry values to query (Registry Key\\Value), e.g.
        '[HKLM]\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ProgramFilesDir'.
        """
        return self.get_indexed_list('List', 'dwItemCount', 'Branch{}') or []

    def set_registry_queries(self, paths):
        """
        Set the registry values to query (1000 characters max each, 255 for
        each \\ separated element, no duplicate - case ignored).
        """
        for path in paths:
            check_registry_path(path)
            check_length('Registry Key\\Value', path, 1000)
            if any(len(element) > 255 for element in str(path).split('\\')):
                raise ValueError('The Registry Key\\Value elements are limited to 255 '
                                 'characters: {!r}'.format(path))
        check_unique(paths, 'Registry Key\\Value')
        return self.__set_list('List', 'dwItemCount', 'Branch{}', paths)

    registry_queries = property(get_registry_queries, set_registry_queries)

    def get_collection_interval(self):
        """
        Get the Hours between Property Collection (None if not set).
        """
        value = self.get_setting_value('Custom', 'dwHourlyInterval')
        return int(value) if value else None

    def set_collection_interval(self, hours):
        """
        Set the Hours between Property Collection (0-999).
        """
        hours = check_int('Hours between Property Collection', hours, 0, 999)
        return self.__set('Custom', 'dwHourlyInterval', hours)

    collection_interval = property(get_collection_interval, set_collection_interval)

    def get_on_policy_change(self):
        """
        Get state of Only send properties when the policy changes ('1' or '0').
        """
        return self.get_setting_value('Custom', 'dwOnPolicyChangeGetProps') or '0'

    def set_on_policy_change(self, mode):
        """
        Set state of Only send properties when the policy changes ('1' or '0').
        """
        return self.__set('Custom', 'dwOnPolicyChangeGetProps', self.__check_mode(mode))

    on_policy_change = property(get_on_policy_change, set_on_policy_change)

    def get_start_datetime(self):
        """
        Get the date and time on endpoint when the policy is in effect
        (datetime, None if not set).
        """
        value = self.get_setting_value('Custom', 'szPolicyStartDateTime')
        return datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S') if value else None

    def set_start_datetime(self, start):
        """
        Set the date and time on endpoint when the policy is in effect
        (datetime; the console sets minutes, not seconds).
        """
        return self.__set('Custom', 'szPolicyStartDateTime',
                          start.replace(second=0, microsecond=0).strftime('%Y-%m-%d %H:%M:%S'))

    start_datetime = property(get_start_datetime, set_start_datetime)

    def get_debug_logging(self):
        """
        Get state of Debug Logging: Enable logging ('1' or '0').
        """
        return self.get_setting_value('Custom', 'dwDebugLog')

    def set_debug_logging(self, mode):
        """
        Set state of Debug Logging: Enable logging ('1' or '0').
        """
        return self.__set('Custom', 'dwDebugLog', self.__check_mode(mode))

    debug_logging = property(get_debug_logging, set_debug_logging)

    # ------------------------------ Find File ------------------------------
    def __check_paths(self, paths, kind):
        """
        The checks of the Find File tab (console 1.0.x on the lab, checked
        again on 1.0.7.70 on 2026-10-17: same rules in generalPolicy.js): trailing
        blanks removed; a file starts with a FILE_PREFIXES item and does not
        end with \\, a folder starts with a drive {A}\\ to {Z}\\; 240
        characters, no " nor ;, no duplicate (case ignored).
        """
        paths = [str(path).rstrip() for path in paths]
        prefixes = self.FILE_PREFIXES if kind == 'File' else self.FILE_PREFIXES[4:]
        for path in paths:
            check_characters(path)
            if not path.startswith(prefixes):
                raise ValueError('Not a valid format of {} search (start with {}): {!r}'.format(
                    kind, '[SYSTEMDRIVE]\\, [SystemRoot]\\, [PROGRAMFILES]\\, '
                    '[COMMONPROGRAMFILES]\\ or {A}\\ to {Z}\\' if kind == 'File' else
                    '{A}\\ to {Z}\\', path))
            if kind == 'File' and str(path).endswith('\\'):
                raise ValueError('A file search cannot end with \\: {!r}'.format(path))
            if len(path) > 240:
                raise ValueError('A {} search is limited to 240 characters.'.format(kind))
        check_unique(paths, kind)
        return paths

    def get_files(self):
        """
        Get the files to search for, e.g. '[SystemRoot]\\psexec.exe'.
        """
        return self.get_indexed_list('FindFile', 'FileCount', 'SearchPattern{}') or []

    def set_files(self, paths):
        """
        Set the files to search for.
        """
        paths = self.__check_paths(paths, 'File')
        return self.__set_list('FindFile', 'FileCount', 'SearchPattern{}', paths)

    files = property(get_files, set_files)

    def get_folders(self):
        """
        Get the folder structures to search for (Folder Structure Discovery).
        """
        return self.get_indexed_list('FindFile', 'FolderCount', 'FolderPattern{}') or []

    def set_folders(self, paths):
        """
        Set the folder structures to search for (Folder Structure Discovery).
        """
        paths = self.__check_paths(paths, 'Folder')
        return self.__set_list('FindFile', 'FolderCount', 'FolderPattern{}', paths)

    folders = property(get_folders, set_folders)

    def get_search_depth(self):
        """
        Get the Search Depth of the Folder Structure Discovery (None if not set).
        """
        value = self.get_setting_value('FindFile', 'dwSearchDepth')
        return int(value) if value else None

    def set_search_depth(self, depth):
        """
        Set the Search Depth of the Folder Structure Discovery (0-9).
        """
        depth = check_int('Search Depth', depth, 0, 9)
        return self.__set('FindFile', 'dwSearchDepth', int(depth))

    search_depth = property(get_search_depth, set_search_depth)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        general = '### Collect data for\n\n' + self.md_settings(
            [[label, self.md_check(self.get_collect(key))] for key, label in self.ITEMS])
        start = self.get_start_datetime()
        custom = '### Get value of custom environment variable\n\n' + self.md_settings([
            ['Name of environment variable (needs to be set in System context)',
             self.get_environment_variable()]])
        custom += '\n### Query Registry Values\n\n' + self.md_table(
            ['Registry Key\\Value'], [[path] for path in self.get_registry_queries()],
            numbered=True)
        custom += '\n### Property collection\n\n' + self.md_settings([
            ['Hours between Property Collection', self.get_collection_interval() or ''],
            ['Send Properties on Policy Change: Only send properties when the policy changes',
             self.md_check(self.get_on_policy_change())],
            ['Date on endpoint when the policy is in effect',
             start.strftime('%Y-%m-%d') if start else ''],
            ['Time on endpoint when the policy is in effect',
             start.strftime('%I:%M %p') if start else ''],
            ['Debug Logging: Enable logging', self.md_check(self.get_debug_logging())]])
        find = '### Find a file\n\n' + self.md_table(
            ['File to search for'], [[path] for path in self.get_files()], numbered=True)
        find += '\n### Folder Structure Discovery\n\n' + self.md_table(
            ['Folder Structure to search for'], [[path] for path in self.get_folders()],
            numbered=True)
        find += '\n' + self.md_settings([['Search Depth', self.get_search_depth() or '']])
        return [('General', general), ('Custom', custom), ('Find File', find)]
