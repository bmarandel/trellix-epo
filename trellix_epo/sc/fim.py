# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class for the Solidcore "Integrity Monitor" policies
(SCOR_FIM): SCFIMPolicyRules.
"""

import re
import uuid

from ..policies import Policy
from .scpolicies import SCPolicy
from .rules import SCRules
from ..validators import (check_length, is_sc_fim_pattern, is_sc_fim_user, is_sc_path,
                          is_sc_registry_key, is_sc_top_level_path)

class SCFIMRules(SCRules):
    """
    SCFIMRules gives the methods of the Integrity Monitoring Rules tabs of the
    ePO console, for Integrity Monitoring Rules policies (SCFIMPolicyRules) and
    Integrity Monitor Rule Groups (SCFIMRuleGroup).
    """

    # File encoding values (Content Change Tracking).
    ENCODINGS = ('AutoDetect', 'ASCII', 'UTF8', 'UTF-16')

    def __get_patterns(self, rule_type):
        return [{'pattern': r.get('pattern'), 'action': r.get('action')}
                for r in self.get_rules(rule_type)]

    def __add_pattern(self, rule_type, pattern, include):
        if self.get_rules(rule_type, {'pattern': pattern}):
            return False
        return self.add_rule({'type': rule_type, 'pattern': pattern,
                              'action': 'Include' if include else 'Exclude'})

    def __os(self):
        return 'UNIX' if self.is_unix() else 'WIN'

    def __check_value(self, label, value, check=None):
        value = check_length(label, str(value).strip(), 3072, required=True)
        if check is not None and not check(value):
            raise ValueError('Invalid {}: {!r}'.format(label, value))
        return value

    def __check_tracked_path(self, path):
        """
        The Content Change Tracking checks of the console (validatePathForFD,
        enableDisableFDElements): not a network path, not a top-level path
        (is_sc_top_level_path), no * folder.
        """
        bad = r'.:\\\*\\|.\\\*\\|^\*' if self.__os() == 'WIN' else r'./\*/|^/\*/|^\*'
        if path.startswith('\\\\') or is_sc_top_level_path(path) or re.search(bad, path):
            raise ValueError('Content Change Tracking is not available for {!r} (network, '
                             'top-level or wildcard folder path).'.format(path))

    def __remove_pattern(self, rule_type, pattern):
        return self.remove_rules(rule_type, {'pattern': pattern}) > 0

    def __check_encoding(self, encoding):
        if encoding not in self.ENCODINGS:
            raise ValueError('File encoding must be one of {}.'.format(', '.join(self.ENCODINGS)))

    # ------------------------------ FILE TAB ------------------------------
    #   Columns: Filter, Path, Change Tracking Settings, Include Patterns,
    #   Exclude Patterns.
    #   A file (or a directory without content tracking) is a 'mon-file' rule,
    #   with file-diff/file-encoding when Enable Content Change Tracking is
    #   checked. A directory with content change tracking (Is Directory) is a
    #   'file-diff-dir' rule, with Recurse Directory and Include/Exclude Patterns.
    def get_file_list(self):
        """
        Get the list of monitored files and directories, as dicts {'pattern',
        'action', 'change_tracking' (bool), 'encoding', 'is_directory' (bool),
        'recurse' (bool), 'include_patterns' (list), 'exclude_patterns' (list)}.
        """
        files = []
        for rule in self.get_rules('mon-file'):
            files.append({'pattern': rule.get('pattern'), 'action': rule.get('action'),
                          'change_tracking': rule.get('file-diff') == 'true',
                          'encoding': rule.get('file-encoding'), 'is_directory': False,
                          'recurse': False, 'include_patterns': [], 'exclude_patterns': []})
        for rule in self.get_rules('file-diff-dir'):
            patterns = {}
            for kind in ('include', 'exclude'):
                count = int(rule.get('{}-pattern-count'.format(kind), '0'))
                patterns[kind] = [rule.get('{}-pattern_{}'.format(kind, i))
                                  for i in range(1, count + 1)]
            files.append({'pattern': rule.get('pattern'), 'action': 'Include',
                          'change_tracking': True, 'encoding': rule.get('file-encoding'),
                          'is_directory': True, 'recurse': rule.get('recurse-dir') == 'true',
                          'include_patterns': patterns['include'],
                          'exclude_patterns': patterns['exclude']})
        return files

    def add_file(self, path, include=True, change_tracking=False, encoding='AutoDetect'):
        """
        Add a monitored file or directory (Include), or exclude it (Exclude).

        :param: change_tracking: Enable Content Change Tracking (files only).
        :param: encoding: File encoding (see ENCODINGS) when change_tracking is True.
        As in the console, the path is trimmed and checked by is_sc_path;
        Content Change Tracking needs Include and a path accepted by the
        console (no network, top-level or wildcard folder path).

        :return: True, or False if the path is already in the list.
        """
        path = self.__check_value('File', path, lambda value: is_sc_path(value, self.__os()))
        if change_tracking:
            if not include:
                raise ValueError('Content Change Tracking needs Include.')
            self.__check_tracked_path(path)
        if self.get_rules('mon-file', {'pattern': path}):
            return False
        rule = {'type': 'mon-file', 'pattern': path, 'action': 'Include' if include else 'Exclude'}
        if change_tracking:
            self.__check_encoding(encoding)
            rule.update({'file-diff': 'true', 'file-encoding': encoding})
        return self.add_rule(rule)

    def add_directory_change_tracking(self, path, recurse=True, include_patterns=('*',),
                                      exclude_patterns=(), encoding='AutoDetect'):
        """
        Add a directory with Content Change Tracking (Is Directory checked).

        :param: recurse: Recurse Directory checkbox.
        :param: include_patterns: Include Patterns (e.g. ['*.cfg']).
        :param: exclude_patterns: Exclude Patterns (e.g. ['*.tmp']).
        As in the console, the path is trimmed and checked like a tracked
        file (see add_file), the patterns by is_sc_fim_pattern.

        :return: True, or False if the directory is already in the list.
        """
        path = self.__check_value('File', path, lambda value: is_sc_path(value, self.__os()))
        self.__check_tracked_path(path)
        for pattern in list(include_patterns) + list(exclude_patterns):
            if not str(pattern).strip() or not is_sc_fim_pattern(pattern):
                raise ValueError('Invalid pattern (see is_sc_fim_pattern): {!r}'.format(pattern))
        if self.get_rules('file-diff-dir', {'pattern': path}):
            return False
        self.__check_encoding(encoding)
        rule = {'type': 'file-diff-dir', 'pattern': path, 'file-encoding': encoding,
                'recurse-dir': 'true' if recurse else 'false',
                'include-pattern-count': str(len(include_patterns)),
                'exclude-pattern-count': str(len(exclude_patterns))}
        for kind, patterns in (('include', include_patterns), ('exclude', exclude_patterns)):
            for index, pattern in enumerate(patterns, 1):
                rule['{}-pattern_{}'.format(kind, index)] = pattern
        return self.add_rule(rule)

    def remove_file(self, path):
        """
        Remove a file or directory from the File list.
        """
        count = self.remove_rules('mon-file', {'pattern': path})
        count += self.remove_rules('file-diff-dir', {'pattern': path})
        return count > 0

    # ------------------------------ REGISTRY TAB ------------------------------
    #   Columns: Filter, Registry (a registry key). Windows only.
    def get_registry_list(self):
        """
        Get the list of monitored registry keys ('mon-reg' rules).
        """
        return self.__get_patterns('mon-reg')

    def add_registry(self, key, include=True):
        """
        Add a monitored registry key (Include), or exclude it (Exclude). The
        key is trimmed and checked by is_sc_registry_key.
        """
        return self.__add_pattern('mon-reg', self.__check_value('Registry', key,
                                                                is_sc_registry_key), include)

    def remove_registry(self, key):
        """
        Remove a registry key from the Registry list.
        """
        return self.__remove_pattern('mon-reg', key)

    # ------------------------------ EXTENSION TAB ------------------------------
    #   Columns: Filter, Extension (e.g. 'log', without the dot).
    def get_extension_list(self):
        """
        Get the list of file extensions ('mon-extn' rules).
        """
        return self.__get_patterns('mon-extn')

    def add_extension(self, extension, include=False):
        """
        Add a file extension, excluded by default (Exclude) or included
        (Include). The extension is trimmed and cannot contain -.
        """
        return self.__add_pattern('mon-extn', self.__check_value(
            'Extension', extension, lambda value: '-' not in value), include)

    def remove_extension(self, extension):
        """
        Remove a file extension from the Extension list.
        """
        return self.__remove_pattern('mon-extn', extension)

    # ------------------------------ PROGRAM TAB ------------------------------
    #   Columns: Filter, Program (the changes made by a program).
    def get_program_list(self):
        """
        Get the list of programs ('mon-proc' rules).
        """
        return self.__get_patterns('mon-proc')

    def add_program(self, program, include=False):
        """
        Add a program, excluded by default (Exclude) or included (Include).
        The program is required and trimmed.
        """
        return self.__add_pattern('mon-proc', self.__check_value('Program', program), include)

    def remove_program(self, program):
        """
        Remove a program from the Program list.
        """
        return self.__remove_pattern('mon-proc', program)

    # ------------------------------ USER TAB ------------------------------
    #   Columns: Filter, User (the changes made by a user). Windows only.
    def get_user_list(self):
        """
        Get the list of users ('mon-user' rules).
        """
        return self.__get_patterns('mon-user')

    def add_user(self, user, include=False):
        """
        Add a user, excluded by default (Exclude) or included (Include). The
        user is trimmed and checked by is_sc_fim_user.
        """
        return self.__add_pattern('mon-user', self.__check_value(
            'User', user, lambda value: is_sc_fim_user(value, self.__os())), include)

    def remove_user(self, user):
        """
        Remove a user from the User list.
        """
        return self.__remove_pattern('mon-user', user)

    # ------------------------------ FILTERS TAB ------------------------------
    #   Advanced filters excluding events: lists of conditions (AND), as dicts
    #   {'condition', 'match', 'pattern'} (see SCPolicy.get_conditions()).
    #   Conditions: File, Event, Process (Program), Reg (Registry), User; match:
    #   equals, begins, ends, contains, doesnt_contain (always equals for Event).
    #   Event names are in upper case, e.g. 'FILE_MODIFIED' (console "File
    #   Modified"). Stored as 'mon-advanced' rules (older Trellix rule groups
    #   have no rule-uuid).
    def get_filters(self):
        """
        Get the list of filters, as dicts {'uuid', 'conditions'}.
        """
        return [{'uuid': r.get('rule-uuid'), 'conditions': self.get_conditions(r)}
                for r in self.get_rules('mon-advanced')]

    def add_filter(self, conditions):
        """
        Add a filter.

        :param: conditions: A list of (condition, match, pattern) tuples or dicts,
                            e.g. [('Event', 'equals', 'FILE_MODIFIED'),
                                  ('Process', 'equals', 'backup.exe')].
        :return: The rule-uuid of the new filter.
        """
        rule_uuid = str(uuid.uuid4())
        rule = {'type': 'mon-advanced', 'action': 'exclude', 'rule-uuid': rule_uuid}
        rule.update(self.make_conditions(conditions))
        self.add_rule(rule)
        return rule_uuid

    def remove_filter(self, rule_uuid):
        """
        Remove a filter by its rule-uuid.
        """
        return self.remove_rules('mon-advanced', {'rule-uuid': rule_uuid}) > 0


    # ------------------------------ Markdown export ------------------------------
    # Tabs of the console (Integrity Monitoring Rules, ePO 5.10): File,
    # Registry (Windows only), Extension, Program, User, Filters.
    ENCODING_LABELS = {'AutoDetect': 'Auto Detect', 'ASCII': 'ASCII', 'UTF8': 'UTF-8',
                       'UTF-16': 'UTF-16'}

    def md_change_tracking(self, item):
        """
        Returns the "Change Tracking Settings" column of the File tab, as the
        console shows it (e.g. "Tracking:Enabled, Encoding:UTF-8, Directory:No").
        """
        if not item['change_tracking']:
            return 'Tracking:Disabled'
        text = 'Tracking:Enabled, Encoding:{}, Directory:{}'.format(
            self.ENCODING_LABELS.get(item['encoding'], item['encoding']),
            'Yes' if item['is_directory'] else 'No')
        if item['is_directory']:
            text += ', Recurse:{}'.format('Yes' if item['recurse'] else 'No')
        return text

    def md_tabs(self):
        """
        Returns the console tabs of the rules as Markdown ("###" per tab).
        """
        table = Policy.md_table
        patterns = lambda items: ', '.join('{{{}}}'.format(item) for item in items)
        simple = lambda items, column: table(['Filter', column], [
            [(item['action'] or '').capitalize(), item['pattern']] for item in items])
        tabs = [('File', table(
            ['Filter', 'Path', 'Change Tracking Settings', 'Include Patterns', 'Exclude Patterns'],
            [[(item['action'] or '').capitalize(), item['pattern'], self.md_change_tracking(item),
              patterns(item['include_patterns']), patterns(item['exclude_patterns'])]
             for item in self.get_file_list()]))]
        if not self.is_unix():
            tabs.append(('Registry', simple(self.get_registry_list(), 'Registry')))
        tabs += [('Extension', simple(self.get_extension_list(), 'Extension')),
                 ('Program', simple(self.get_program_list(), 'Program')),
                 ('User', simple(self.get_user_list(), 'User')),
                 ('Filters', 'Define filters by using a combination of conditions to exclude '
                             'events that are not relevant for your setup.\n\n' + table(
                                 ['Conditions'], [[self.md_conditions(f['conditions'])]
                                                  for f in self.get_filters()], numbered=True))]
        return '\n'.join('### {}\n\n{}'.format(title, body) for title, body in tabs)

class SCFIMPolicyRules(SCFIMRules, SCPolicy):
    """
    The SCFIMPolicyRules class can be used to edit the Solidcore policies:
    Integrity Monitor > Integrity Monitoring Rules (Windows) and (Unix).

    Note: ePO stores these policies under the internal types "Mon Rules (Windows)"
    and "Mon Rules (Unix)". Only the policy's own rules ("My Rules") are edited;
    see SCPolicy for the shared Rule Groups (e.g. the "Base Filters" groups).
    The File, Registry, Extension, Program and User tabs are lists of
    {'pattern', 'action'} rules, where action is 'Include' or 'Exclude' (the
    Filter column; older Trellix rule groups store it in lower case). The
    longest pathname takes precedence.
    """

    TYPE_IDS = ('Mon Rules (Windows)', 'Mon Rules (Unix)')

    @property
    def MD_CATEGORY(self):
        return 'Integrity Monitoring Rules ({})'.format('Unix' if self.is_unix() else 'Windows')

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples:
        the Rule Groups, then the tabs of each rule group (see
        Policy.to_markdown).
        """
        return self.md_rule_group_sections(self.md_tabs)
