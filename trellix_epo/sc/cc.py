# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class for the Solidcore "Change Control" policies
(SCOR_CC): SCCCPolicyRules.
"""

from ..policies import Policy
from .scpolicies import SCPolicy
from .rules import SCUpdaterRules
from ..validators import check_length, is_sc_cc_path, is_sc_registry_key

class SCCCRules(SCUpdaterRules):
    """
    SCCCRules gives the methods of the Change Control Rules tabs of the ePO
    console, for Change Control Rules policies (SCCCPolicyRules) and Change
    Control Rule Groups (SCCCRuleGroup).
    """

    def __get_patterns(self, rule_type):
        return [{'pattern': r.get('pattern'), 'action': r.get('action')}
                for r in self.get_rules(rule_type)]

    def __add_pattern(self, rule_type, pattern, include):
        if self.get_rules(rule_type, {'pattern': pattern}):
            return False
        return self.add_rule({'type': rule_type, 'pattern': pattern,
                              'action': 'Include' if include else 'Exclude'})

    def __check_path(self, path):
        path = check_length('File', str(path).strip(), 3072, required=True)
        if not is_sc_cc_path(path, 'UNIX' if self.is_unix() else 'WIN'):
            raise ValueError('Invalid file or directory (see is_sc_cc_path): {!r}'.format(path))
        return path

    def __remove_pattern(self, rule_type, pattern):
        return self.remove_rules(rule_type, {'pattern': pattern}) > 0

    # ------------------------------ READ-PROTECT TAB ------------------------------
    #   Columns: Filter (Include/Exclude), File (a file or a directory).
    def get_read_protect_list(self):
        """
        Get the list of read-protected files and directories ('rp-file' rules).
        """
        return self.__get_patterns('rp-file')

    def add_read_protect(self, path, include=True):
        """
        Add a read-protected file or directory (Include), or exclude it (Exclude).

        As in the console, the path is required and trimmed, and checked on
        Windows by is_sc_cc_path (wildcards accepted).

        :return: True, or False if the path is already in the list.
        """
        return self.__add_pattern('rp-file', self.__check_path(path), include)

    def remove_read_protect(self, path):
        """
        Remove a file or directory from the Read-Protect list.
        """
        return self.__remove_pattern('rp-file', path)

    # ------------------------------ WRITE-PROTECT FILE TAB ------------------------------
    #   Columns: Filter (Include/Exclude), File (a file or a directory).
    def get_write_protect_file_list(self):
        """
        Get the list of write-protected files and directories ('wp-file' rules).
        """
        return self.__get_patterns('wp-file')

    def add_write_protect_file(self, path, include=True):
        """
        Add a write-protected file or directory (Include), or exclude it (Exclude).

        As in the console, the path is required and trimmed, and checked on
        Windows by is_sc_cc_path (wildcards accepted).

        :return: True, or False if the path is already in the list.
        """
        return self.__add_pattern('wp-file', self.__check_path(path), include)

    def remove_write_protect_file(self, path):
        """
        Remove a file or directory from the Write-Protect File list.
        """
        return self.__remove_pattern('wp-file', path)

    # ------------------------------ WRITE-PROTECT REGISTRY TAB ------------------------------
    #   Columns: Filter (Include/Exclude), Registry (a registry key). Windows only.
    def get_write_protect_registry_list(self):
        """
        Get the list of write-protected registry keys ('wp-reg' rules).
        """
        return self.__get_patterns('wp-reg')

    def add_write_protect_registry(self, key, include=True):
        """
        Add a write-protected registry key (Include), or exclude it (Exclude).

        As in the console, the key is required and trimmed, and checked by
        is_sc_registry_key.

        :return: True, or False if the key is already in the list.
        """
        key = check_length('Registry', str(key).strip(), 3072, required=True)
        if not is_sc_registry_key(key):
            raise ValueError('Invalid registry key (see is_sc_registry_key): {!r}'.format(key))
        return self.__add_pattern('wp-reg', key, include)

    def remove_write_protect_registry(self, key):
        """
        Remove a registry key from the Write-Protect Registry list.
        """
        return self.__remove_pattern('wp-reg', key)

    # ------------------------------ UPDATER PROCESSES AND USERS TABS ------------------------------
    #   See SCUpdaterRules (get_updaters, add_updater, add_updater_by_checksum,
    #   remove_updater, get_trusted_users, add_trusted_user, remove_trusted_user).


    # ------------------------------ Markdown export ------------------------------
    # Tabs of the console (Change Control Rules, ePO 5.10): Read-Protect,
    # Write-Protect File, Write-Protect Registry, Updater Processes, Users
    # (Unix: Read-Protect, Write-Protect File, Updater Processes).
    def md_tabs(self):
        """
        Returns the console tabs of the rules as Markdown ("###" per tab).
        """
        table = Policy.md_table
        protect = lambda items, column: table(['Filter', column], [
            [(item['action'] or '').capitalize(), item['pattern']] for item in items])
        tabs = [('Read-Protect', protect(self.get_read_protect_list(), 'File')),
                ('Write-Protect File', protect(self.get_write_protect_file_list(), 'File'))]
        if not self.is_unix():
            tabs.append(('Write-Protect Registry',
                         protect(self.get_write_protect_registry_list(), 'Registry')))
        tabs.append(('Updater Processes', self.md_updaters_table(table)))
        if not self.is_unix():
            tabs.append(('Users', self.md_users_table(table)))
        return '\n'.join('### {}\n\n{}'.format(title, body) for title, body in tabs)

class SCCCPolicyRules(SCCCRules, SCPolicy):
    """
    The SCCCPolicyRules class can be used to edit the Solidcore policies:
    Change Control > Change Control Rules (Windows) and (Unix).

    Note: ePO stores these policies under the internal types "CC Rules (Windows)"
    and "CC Rules (Unix)". Only the policy's own rules ("My Rules") are edited;
    see SCPolicy for the shared Rule Groups. The Unix policy only has the
    Read-Protect, Write-Protect File and Updater Processes tabs.
    Each protection tab is a list of {'pattern', 'action'} rules, where action is
    'Include' or 'Exclude' (the Filter column). The longest pathname (or registry
    key) takes precedence: if C:\\temp is excluded and C:\\temp\\foo.cfg is
    included, foo.cfg is considered as included.
    """

    TYPE_IDS = ('CC Rules (Windows)', 'CC Rules (Unix)')

    @property
    def MD_CATEGORY(self):
        return 'Change Control Rules ({})'.format('Unix' if self.is_unix() else 'Windows')

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples:
        the Rule Groups, then the tabs of each rule group (see
        Policy.to_markdown).
        """
        return self.md_rule_group_sections(self.md_tabs)
