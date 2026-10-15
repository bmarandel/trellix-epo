# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes ESSPPolicyNetApp (Endpoint Security Storage
Protection: NetApp Policies) and SPExclusion.

Storage learnt from a test policy changed in the ePO 5.10 console:

- Filers list: NetAppGeneral.szFiler_<n> (from 0), count dwFilerCount.
- Exclusions: NetAppExclusions.ExcludedItem_<n> (from 0), count
  dwExclusionCount, each "<type>|<flags>|<value>": type 3 = pattern (flags
  4 = also exclude subfolders, 0 = not), 4 = file type, 0/1/2 = file age
  Modified/Accessed/Created (value = minimum age in days). "Overwrite client
  exclusions" is stored inverted: bAppendExclusions 0 = checked.
- Administrator account common to all filers: szFilerUsername,
  szFilerDomainName and the password encrypted by the ePO server with its own
  key ("EPOAES128:<64 hex digits>", same value in szFilerPassword and
  szFilerPasswordConfirm). The library can't decrypt nor produce it: the
  account must be defined in the console, the library keeps it and can only
  enable/disable it. It is never written by the Markdown export.
"""

import re

from .common import ESSPPolicy
from ...validators import (check_int, check_length, is_sp_exclusion_file_type,
                           is_sp_exclusion_pattern, is_sp_filer)


class SPExclusion():
    """
    An exclusion of a NetApp policy (console "Add/Edit Exclusion Item"
    dialog): by pattern, by file type or by file age.
    """
    MODIFIED, ACCESSED, CREATED, PATTERN, FILE_TYPE = '0', '1', '2', '3', '4'
    ACCESS_TYPES = {MODIFIED: 'Modified', ACCESSED: 'Accessed', CREATED: 'Created'}
    SUBFOLDERS = '4'

    def __init__(self, kind, value, subfolders=False):
        self.kind = kind
        self.value = str(value)
        self.subfolders = subfolders

    def __repr__(self):
        return 'SPExclusion({!r}, {!r}, {!r})'.format(self.kind, self.value, self.subfolders)

    def __eq__(self, other):
        return isinstance(other, SPExclusion) and self.to_value() == other.to_value()

    @classmethod
    def pattern(cls, pattern, subfolders=False):
        """
        By pattern (can include wildcards * or ?), e.g. C:\\Data\\ or *.log.
        """
        return cls(cls.PATTERN, pattern, subfolders)

    @classmethod
    def file_type(cls, extension):
        """
        By file type, e.g. tmp.
        """
        return cls(cls.FILE_TYPE, extension)

    @classmethod
    def file_age(cls, days, access_type=MODIFIED):
        """
        By file age: minimum age in days of the access type (MODIFIED,
        CREATED; ACCESSED is not offered by the console for NetApp).
        """
        return cls(access_type, int(days))

    def check(self):
        """
        Raise ValueError if the console would refuse the exclusion (Add/Edit
        Exclusion Item dialog, validateExclusion of Common.js): pattern of
        100 characters (see is_sp_exclusion_pattern), "Also exclude
        subfolders" only for a pattern ending with \\; file type of 10
        characters (see is_sp_exclusion_file_type, ':::' = no extension);
        minimum age of 1-9999 days (digits only).
        """
        if self.kind not in [self.PATTERN, self.FILE_TYPE] + list(self.ACCESS_TYPES):
            raise ValueError('Unknown exclusion type: {}'.format(self.kind))
        if '|' in self.value:
            raise ValueError('An exclusion cannot contain "|": {}'.format(self.value))
        if self.kind == self.PATTERN:
            check_length('Pattern', self.value, 100, required=True)
            if not is_sp_exclusion_pattern(self.value):
                raise ValueError('Invalid exclusion pattern: {!r}'.format(self.value))
            if self.subfolders and not self.value.endswith('\\'):
                raise ValueError('Also exclude subfolders needs a pattern ending with \\: '
                                 '{!r}'.format(self.value))
        elif self.kind == self.FILE_TYPE:
            if not is_sp_exclusion_file_type(self.value):
                raise ValueError('Invalid exclusion file type: {!r}'.format(self.value))
        else:
            if not re.fullmatch(r'[0-9]+', self.value):
                raise ValueError('The minimum age must be a number of days: {}'.format(
                    self.value))
            check_int('Minimum age', self.value, 1, 9999)

    @classmethod
    def from_value(cls, value):
        kind, flags, item = value.split('|', 2)
        return cls(kind, item, kind == cls.PATTERN and flags == cls.SUBFOLDERS)

    def to_value(self):
        flags = self.SUBFOLDERS if self.kind == self.PATTERN and self.subfolders else '0'
        return '{}|{}|{}'.format(self.kind, flags, self.value)

    @property
    def item(self):
        """
        The text of the console "Item" column.
        """
        if self.kind == self.FILE_TYPE:
            return 'All files of type {}'.format(self.value)
        if self.kind in self.ACCESS_TYPES:
            return '{} {} or more days ago'.format(self.ACCESS_TYPES[self.kind], self.value)
        return self.value


class ESSPPolicyNetApp(ESSPPolicy):
    """
    The ESSPPolicyNetApp class can be used to edit the Endpoint Security
    Storage Protection policy: NetApp Policies (console tabs Filers, Scan
    Items, Exclusions, Performance, Actions, Reports).
    """
    PREFIX = 'NetApp'
    TYPE = 'VSES1000_Netapp_Policies'
    MD_CATEGORY = 'NetApp Policies'

    # ------------------------------ Filers ------------------------------
    def get_overwrite_filer_list(self):
        """
        Get state of Overwrite client filer list ('1' or '0').
        """
        return self._get('General', 'bOverwriteLocalFilerList')

    def set_overwrite_filer_list(self, mode):
        """
        Set state of Overwrite client filer list ('1' or '0').
        """
        return self._set('General', 'bOverwriteLocalFilerList', mode)

    overwrite_filer_list = property(get_overwrite_filer_list, set_overwrite_filer_list)

    def get_filer_list(self):
        """
        Get the filers this scan server protects (names or IP addresses).
        """
        return self.get_indexed_list('NetAppGeneral', 'dwFilerCount', 'szFiler_{}') or []

    def set_filer_list(self, filers):
        """
        Set the filers this scan server protects: names of letters and
        digits or IP addresses (see is_sp_filer), no duplicate.
        """
        filers = [str(filer) for filer in filers]
        for index, filer in enumerate(filers):
            if not is_sp_filer(filer):
                raise ValueError('Invalid filer: {!r}'.format(filer))
            if filer in filers[:index]:
                raise ValueError('Duplicate filer: {!r}'.format(filer))
        return self.set_indexed_list('NetAppGeneral', 'dwFilerCount', 'szFiler_{}', filers)

    filer_list = property(get_filer_list, set_filer_list)

    def get_keep_alive_probes(self):
        """
        Get state of Enable keep-alive probes ('1' or '0').
        """
        return self._get('General', 'bKeepAliveProbes')

    def set_keep_alive_probes(self, mode):
        """
        Set state of Enable keep-alive probes ('1' or '0').
        """
        return self._set('General', 'bKeepAliveProbes', mode)

    keep_alive_probes = property(get_keep_alive_probes, set_keep_alive_probes)

    def get_reset_cache(self):
        """
        Get state of Reset filer's clean file cache after each DAT or Engine
        update ('1' or '0').
        """
        return self._get('General', 'bResetCache')

    def set_reset_cache(self, mode):
        """
        Set state of Reset filer's clean file cache after each DAT or Engine
        update ('1' or '0').
        """
        return self._set('General', 'bResetCache', mode)

    reset_cache = property(get_reset_cache, set_reset_cache)

    def get_filer_account(self):
        """
        Get the administrator account common to all filers: a dict with
        'enabled' ('1' or '0'), 'user', 'domain' and 'password_set' (True
        when the policy holds a password; the password itself is encrypted
        by the ePO server and never returned).
        """
        return {'enabled': self._get('General', 'bUseGroupedFilerAccount'),
                'user': self._get('General', 'szFilerUsername'),
                'domain': self._get('General', 'szFilerDomainName'),
                'password_set': bool(self._get('General', 'szFilerPassword'))}

    def set_filer_account(self, enabled):
        """
        Enable or disable ('1' or '0') the administrator account common to all
        filers ('Use the following account on all filers').

        The account (user name, password, domain) can only be defined in the
        ePO console: the server stores the password encrypted with its own
        key (szFilerPassword "EPOAES128:<hex>", checked on the ePO 5.10 lab),
        which this library can neither decrypt nor produce. The encrypted
        password, the user name and the domain of the policy are kept as is,
        so the account can be enabled only when the policy already holds one.
        """
        if str(enabled) == '1' and not self.get_filer_account()['password_set']:
            raise ValueError('No filer account in this policy: define the user name and the '
                             'password in the ePO console first (the password is encrypted '
                             'by the ePO server).')
        return self._set('General', 'bUseGroupedFilerAccount', enabled)

    # ------------------------------ Exclusions ------------------------------
    def get_exclusions(self):
        """
        Get the exclusions (list of SPExclusion).
        """
        values = self.get_indexed_list('NetAppExclusions', 'dwExclusionCount',
                                       'ExcludedItem_{}') or []
        return [SPExclusion.from_value(value) for value in values]

    def set_exclusions(self, exclusions):
        """
        Set the exclusions (list of SPExclusion).
        """
        for exclusion in exclusions:
            exclusion.check()
        return self.set_indexed_list('NetAppExclusions', 'dwExclusionCount', 'ExcludedItem_{}',
                                     [exclusion.to_value() for exclusion in exclusions])

    exclusions = property(get_exclusions, set_exclusions)

    def add_exclusion(self, exclusion):
        """
        Add an exclusion (SPExclusion) if not already in the list.
        """
        exclusion.check()
        if exclusion.kind == SPExclusion.ACCESSED:
            raise ValueError('The console offers Modified and Created only for NetApp.')
        exclusions = self.get_exclusions()
        if exclusion in exclusions:
            return False
        return self.set_exclusions(exclusions + [exclusion])

    def remove_exclusion(self, exclusion):
        """
        Remove an exclusion (SPExclusion).
        """
        exclusions = self.get_exclusions()
        if exclusion not in exclusions:
            return False
        return self.set_exclusions([known for known in exclusions if known != exclusion])

    def get_overwrite_client_exclusions(self):
        """
        Get state of Overwrite client exclusions (only exclude items
        specified in this policy) ('1' or '0').
        """
        value = self._get('Exclusions', 'bAppendExclusions')
        return None if value is None else ('0' if value == '1' else '1')

    def set_overwrite_client_exclusions(self, mode):
        """
        Set state of Overwrite client exclusions ('1' or '0').
        """
        return self._set('Exclusions', 'bAppendExclusions', '0' if str(mode) == '1' else '1')

    overwrite_client_exclusions = property(get_overwrite_client_exclusions,
                                           set_overwrite_client_exclusions)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        overwrite = self.get_overwrite_filer_list()
        filers = self._md_tab('Specifies which filers this scan server protects', [
            ('Filers list', [['Overwrite client filer list (This scan server processes scan '
                              'requests for these filers)', self.md_check(overwrite)]])])
        if overwrite == '1':
            filers += '\n' + self.md_table(['Filer'], [[filer] for filer in self.get_filer_list()],
                                           numbered=True)
        account = self.get_filer_account()
        rows = [['Use the following account on all filers', self.md_check(account['enabled'])]]
        if account['enabled'] == '1':
            # The password is never written.
            rows += [['User name', account['user']], ['Domain', account['domain']]]
        filers += '\n### These settings apply to all filers\n\n' + self.md_settings([
            ['Enable keep-alive probes', self.md_check(self.get_keep_alive_probes())],
            ["Reset filer's clean file cache after each DAT or Engine update",
             self.md_check(self.get_reset_cache())]])
        filers += '\n### Administrator account common to all filers\n\n' + self.md_settings(rows)
        exclusions = 'Specify what items to exclude from scanning.\n\n### What not to scan\n\n'
        exclusions += self.md_table(['Item', 'Exclude Subfolders'], [
            [exclusion.item, ('Yes' if exclusion.subfolders else 'No')
             if exclusion.kind == SPExclusion.PATTERN else '--']
            for exclusion in self.get_exclusions()], numbered=True)
        exclusions += '\n### How to handle client exclusions\n\n' + self.md_settings([
            ['Overwrite client exclusions (only exclude items specified in this policy)',
             self.md_check(self.get_overwrite_client_exclusions())]])
        return [('Filers', filers),
                ('Scan Items', self._md_scan_items()),
                ('Exclusions', exclusions),
                ('Performance', self._md_performance()),
                ('Actions', self._md_actions_tab()),
                ('Reports', self._md_reports())]
