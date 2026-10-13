# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the Class objects SCRules, SCExclusionRules and SCUpdaterRules.

Solidcore rules are stored the same way in a policy (Sections named
"General_Rule_<n>" of an ePO policy export) and in a Solidcore Rule Group
(<Rule> elements of a "scor.rulegroup.export" file): a list of settings whose
"type" setting gives the kind of rule. SCRules gives a common access to them, as
dicts {setting name: value}, so that the methods editing the tabs of the ePO
console (SCExclusionRules, SCUpdaterRules, and the Application Control, Change
Control and Integrity Monitor classes) work for both policies and rule groups.
"""

import re

from ..validators import check_length, is_sc_exclusion_value, is_sc_updater_name

class SCRules():
    """
    SCRules is the base class object giving access to Solidcore rules. A subclass
    stores the rules and must implement _iter_rules, _append_rule, _update_rule,
    _remove_rule and is_unix.
    """

    # ------------------------------ Storage (implemented by subclasses) ------------------------------
    def _iter_rules(self, all_groups=False):
        """
        Yields (handle, rule) for each rule, rule being a dict {setting name: value}
        and handle what _update_rule and _remove_rule need to find it.
        """
        raise NotImplementedError

    def _append_rule(self, rule):
        """
        Stores a new rule (dict of strings). Returns True or False.
        """
        raise NotImplementedError

    def _update_rule(self, handle, values):
        """
        Updates (or adds) settings of a stored rule.
        """
        raise NotImplementedError

    def _remove_rule(self, handle):
        """
        Removes a stored rule.
        """
        raise NotImplementedError

    def is_unix(self):
        """
        Returns True for a Unix policy or rule group.
        """
        raise NotImplementedError

    # ------------------------------ Rules ------------------------------
    def __select(self, rule_type=None, match=None, all_groups=False):
        for handle, rule in self._iter_rules(all_groups):
            if rule_type is not None and rule.get('type') != rule_type:
                continue
            if match and any(rule.get(k) != v for k, v in match.items()):
                continue
            yield handle, rule

    def get_rules(self, rule_type=None, match=None, all_groups=False):
        """
        Returns the list of rules (dicts {setting name: value}).

        :param: rule_type: Only returns rules of this type (e.g. 'updater-binary').
        :param: match: Only returns rules whose settings match this dict.
        :param: all_groups: For a policy, if True, the rules of the shared Rule
                            Groups are also returned, otherwise only the
                            policy's own "My Rules".
        :return: A list of dicts.
        """
        return [rule for _, rule in self.__select(rule_type, match, all_groups)]

    def get_rule(self, rule_type, match=None):
        """
        Returns the first rule (dict) matching a type and the settings given in
        match, or None if there is none.
        """
        rules = self.get_rules(rule_type, match)
        return rules[0] if rules else None

    def add_rule(self, rule):
        """
        Adds a rule (dict {setting name: value}, which must contain a 'type' key).
        For a policy, the rule is added to its own "My Rules".

        :return: True or False (no 'type', or the policy has no "My Rules").
        """
        if 'type' not in rule:
            return False
        return self._append_rule({key: str(value) for key, value in rule.items()})

    def update_rules(self, rule_type, match, values):
        """
        Updates (or adds) settings of the rules matching a type and match.

        :param: rule_type: The type of the rules to update.
        :param: match: A dict of settings the rules must match.
        :param: values: A dict {setting name: new value}.
        :return: The number of rules updated.
        """
        count = 0
        for handle, _ in list(self.__select(rule_type, match)):
            self._update_rule(handle, {key: str(value) for key, value in values.items()})
            count += 1
        return count

    def remove_rules(self, rule_type, match=None):
        """
        Removes the rules matching a type and match.

        :return: The number of rules removed.
        """
        count = 0
        for handle, _ in list(self.__select(rule_type, match)):
            self._remove_rule(handle)
            count += 1
        return count

    # ------------------------------ Typed rule helpers ------------------------------
    #   Rule types present at most once (e.g. 'local-cli-lock').
    def _get_rule_value(self, rule_type, key):
        """
        Returns the value of a setting of the (single) rule of a type, or None.
        """
        rule = self.get_rule(rule_type)
        return rule.get(key) if rule is not None else None

    def _set_rule_value(self, rule_type, key, value):
        """
        Sets the value of a setting of the (single) rule of a type. The rule is
        created if it doesn't exist.
        """
        if self.update_rules(rule_type, None, {key: value}) == 0:
            return self.add_rule({'type': rule_type, key: value})
        return True

    # ------------------------------ Value helpers ------------------------------
    @staticmethod
    def _checksum_key(checksum):
        """
        Returns the setting name of a checksum ('cksum' for SHA-1, 'cksum256' for
        SHA-256), or raises ValueError.
        """
        if re.match(r'^[0-9a-fA-F]{40}$', checksum):
            return 'cksum'
        if re.match(r'^[0-9a-fA-F]{64}$', checksum):
            return 'cksum256'
        raise ValueError('Checksum must be a SHA-1 (40) or SHA-256 (64) hexadecimal value.')

    @staticmethod
    def _bool(value):
        """
        Returns 'true' or 'false'.
        """
        return 'true' if value else 'false'

    # ------------------------------ Conditions ------------------------------
    #   Advanced rules (execution-control, mon-advanced, ob-exclusion,
    #   advanced-inv-exclusion) store a list of conditions as
    #   condition-type_<i> / match-type_<i> / pattern_<i>.
    @staticmethod
    def get_conditions(rule):
        """
        Returns the conditions of an advanced rule as a list of dicts
        {'condition': ..., 'match': ..., 'pattern': ...}.
        """
        conditions = []
        index = 0
        while 'condition-type_{}'.format(index) in rule:
            conditions.append({'condition': rule['condition-type_{}'.format(index)],
                               'match': rule.get('match-type_{}'.format(index)),
                               'pattern': rule.get('pattern_{}'.format(index))})
            index += 1
        return conditions

    @staticmethod
    def make_conditions(conditions):
        """
        Converts a list of conditions (dicts {'condition', 'match', 'pattern'} or
        tuples (condition, match, pattern)) into rule settings.
        """
        settings = {}
        for index, condition in enumerate(conditions):
            if isinstance(condition, dict):
                condition = (condition['condition'], condition['match'], condition['pattern'])
            settings['condition-type_{}'.format(index)] = condition[0]
            settings['match-type_{}'.format(index)] = condition[1]
            settings['pattern_{}'.format(index)] = condition[2]
        return settings


    # ------------------------------ Markdown export ------------------------------
    # Labels of the condition editors of the ePO 5.10 console (Filters tabs,
    # Execution Control), and of the events of the Event condition.
    CONDITION_LABELS = {'File': 'File', 'Event': 'Event', 'Process': 'Program',
                        'Reg': 'Registry', 'User': 'User', 'Type': 'File type',
                        'app-name': 'Application name', 'app-version': 'Application version',
                        'vendor-name': 'Application vendor',
                        'has-certificate': 'File signed by certificate'}
    MATCH_LABELS = {'equals': 'equals', 'begins': 'begins with', 'ends': 'ends with',
                    'contains': 'contains', 'doesnt_contain': 'does not contain'}
    # Event condition values of the console (lower case codes).
    EVENT_LABELS = {
        'activex_install_allowed': 'ActiveX Installation Allowed',
        'activex_install_prevented': 'ActiveX Installation Prevented',
        'data_stream_created': 'Alternate Data Stream Created',
        'data_stream_deleted': 'Alternate Data Stream Deleted',
        'data_stream_modified': 'Alternate Data Stream Modified',
        'data_stream_renamed': 'Alternate Data Stream Renamed',
        'data_stream_attr_set': 'Attribute Added in Data Stream',
        'data_stream_attr_clear': 'Attribute Cleared in Data Stream',
        'data_stream_attr_modified': 'Attribute Modified in Data Stream',
        'blocked_process_interactive_mode': 'Blocked Interactive Mode of Process',
        'booting_inventory_mode': 'Booting Inventory Mode',
        'clogged_data_deleted': 'Clogged Data Deleted',
        'end_inventory_mode_deferred': 'Closed Inventory Mode',
        'closed_update_mode': 'Closed Update Mode', 'command_executed': 'Command Executed',
        'data_congestion_detected': 'Data Congestion Detected',
        'throttling_cache_full': 'Data Dropped', 'throttling_started': 'Data Throttled',
        'local_cli_access_disabled': 'Disabled Local CLI Access',
        'disabled_on_reboot': 'Disabled Mode deferred',
        'enabled_on_reboot': 'Enabled Mode deferred', 'end_observe': 'End Observe Mode',
        'end_observe_on_reboot': 'End Observe Mode deferred',
        'execution_denied': 'Execution Denied', 'file_acl_modified': 'File ACL Modified',
        'file_attribute_cleared': 'File Attribute Cleared',
        'file_attribute_modified': 'File Attribute Modified',
        'file_attribute_set': 'File Attribute Set', 'file_created': 'File Created',
        'file_deleted': 'File Deleted', 'file_modified': 'File Modified',
        'file_ownership_changed': 'File Ownership Changed',
        'file_read_denied': 'File Read Denied', 'file_read_update': 'File Read in Update mode',
        'file_renamed': 'File Renamed', 'file_solidified': 'File Solidified',
        'file_unsolidified': 'File Unsolidified', 'file_write_denied': 'File Write Denied',
        'initial_scan_task_completed': 'Initial Scan Completed',
        'package_modification_allowed': 'Installation Allowed',
        'package_modification_prevented': 'Installation Denied',
        'inventory_corrupted': 'Inventory Corrupted',
        'inventory_mode_deferred': 'Inventory Mode deferred',
        'malicious_file_found': 'Malicious File Found',
        'malicious_file_is_trusted': 'Malicious File is Trusted',
        'module_loading_failed': 'Module Loading Failed',
        'nx_violation_detected': 'Nx Violation Detected',
        'begin_observe_on_reboot': 'Observe Mode deferred',
        'observed_file_execution': 'Observed File Execution',
        'opened_update_mode': 'Opened Update Mode',
        'prevented_file_execution': 'Prevented File Execution',
        'process_exited': 'Process Exited', 'process_hijacked': 'Process Hijack Attempted',
        'process_started': 'Process Started', 'process_terminated': 'Process Terminated',
        'pull_inventory_ended': 'Pull Inventory Completed',
        'inventory_recovered': 'Recovered Inventory',
        'local_cli_recover_success': 'Recovered Local CLI',
        'registry_created': 'Registry Created', 'registry_deleted': 'Registry Deleted',
        'registry_modified': 'Registry Modified',
        'registry_write_denied': 'Registry Write Denied', 'sc_connected': 'SC Connected',
        'sc_disconnected': 'SC Disconnected', 'sc_divert': 'SC Diverted',
        'begin_observe': 'Start Observe Mode', 'disabled': 'Started Disabled Mode',
        'enabled': 'Started Enabled Mode', 'booting_observe': 'Started Observe mode',
        'booted_in_update_mode': 'Started Update Mode',
        'trial_license_expired': 'Trial license expired',
        'inventory_recovery_failed': 'Unable to Recover Inventory',
        'local_cli_recover_failed': 'Unable to Recover Local CLI',
        'prevented_unauth_api_call': 'Unauthorized API Call Prevented',
        'update_mode_on_reboot': 'Update Mode deferred',
        'user_account_created': 'User Account Created',
        'user_account_deleted': 'User Account Deleted',
        'user_account_modified': 'User Account Modified', 'user_logged_off': 'User Logged Off',
        'user_logged_on': 'User Logged On', 'user_logon_failed': 'User Logon Failed',
        'vasr_violation_detected': 'VASR Violation Detected', 'vtp_trusted': 'VTP Trusted'}
    # Stored event codes shown by the console under another value (checked:
    # a filter stored as WRITE_DENIED is shown "File Write Denied"); the codes
    # neither listed here nor in EVENT_LABELS are written as stored.
    EVENT_ALIASES = {'WRITE_DENIED': 'File Write Denied'}

    @classmethod
    def md_event(cls, code):
        """
        Returns the console label of an event code (the code if unknown).
        """
        return cls.EVENT_ALIASES.get(code) or cls.EVENT_LABELS.get((code or '').lower(), code)

    @classmethod
    def md_conditions(cls, conditions):
        """
        Returns the conditions of a filter as console text, e.g.
        "Program equals e2e.exe AND Event equals File Write Denied".
        """
        texts = []
        for condition in conditions:
            pattern = condition.get('pattern')
            if condition.get('condition') == 'Event':
                pattern = cls.md_event(pattern)
            texts.append('{} {} {}'.format(
                cls.CONDITION_LABELS.get(condition.get('condition'), condition.get('condition')),
                cls.MATCH_LABELS.get(condition.get('match'), condition.get('match')), pattern))
        return ' AND '.join(texts)

class SCExclusionRules(SCRules):
    """
    SCExclusionRules adds the exclusion list methods to the Solidcore policies and
    rule groups which have one, as edited in the "Add exclusion rules" dialog of
    the ePO console: General > Exception Rules, and the Exclusions tab of
    Application Control Rules.

    Each exclusion is one flag set to 'true' on a rule: an 'attr' rule for a
    process/file name, a 'skiplist' rule for a path or a volume. Use the
    SCException constants to select an exclusion.

    "Allow uninstallations" (required) and "Exclude file from write-protection
    rules and allow script execution" (optional) also take a Parent Process
    Name, stored in the 'parent' setting of the rule; "Disable ROP protection
    for a process using Forced Relocation (VASR)" takes an optional Library
    Name, stored in the 'module' setting (all the exclusion types checked on
    the ePO 5.10 lab, Windows).
    """

    # Exclusions with a Parent Process Name (Windows): required or optional.
    PARENT_REQUIRED = ('uninstall_bypass',)
    PARENT_OPTIONAL = ('process_ctx_bypass',)
    # Exclusions with an optional Library Name (Windows).
    LIBRARY_OPTIONAL = ('vasr_force_reloc_bypass',)

    # Exclusions stored as 'skiplist' rules (path), the others are 'attr' rules (file).
    SKIPLIST_EXCLUSIONS = ('skipFileOperation', 'skipFileOperation_f', 'skipDenyWrite',
                           'skipSolidification', 'skipVolume', 'skipRegistry',
                           'skipChangeTracking')
    UNIX_EXCLUSIONS = ('process_ctx_bypass', 'skipSolidification')
    # All the exclusions of the console (the SCException constants).
    EXCLUSIONS = ('casp_bypass', 'dep_bypass', 'vasr_force_reloc_bypass', 'vasr_reloc_bypass',
                  'vasr_rand_bypass', 'uninstall_bypass', 'process_ctx_bypass',
                  'process_ctx_reg_bypass') + SKIPLIST_EXCLUSIONS

    # Settings written by the ePO console for a new rule, all flags 'false'.
    __WINDOWS_ATTR_FLAGS = ('always_auth', 'always_unauth', 'anti_debugging_bypass',
                            'casp_bypass', 'ccv_bypass', 'dep_bypass', 'dep_bypass_inherit',
                            'full_crawl', 'installer_detection_bypass', 'mangling_bypass',
                            'process_ctx_bypass', 'process_ctx_reg_bypass', 'rebase_dll',
                            'relocate_dll', 'uninstall_bypass', 'vasr_force_reloc_bypass',
                            'vasr_rand_bypass', 'vasr_reloc_bypass')
    __WINDOWS_SKIPLIST_FLAGS = ('skipChangeTracking', 'skipDenyWrite', 'skipFileOperation',
                                'skipFileOperation_f', 'skipRegistry', 'skipSolidification',
                                'skipVolume')
    __UNIX_ATTR_FLAGS = ('always_auth', 'always_unauth', 'process_ctx_bypass')
    __UNIX_SKIPLIST_FLAGS = ('skipSolidification',)

    def __rule_kind(self, exclusion):
        if exclusion in self.SKIPLIST_EXCLUSIONS:
            return 'skiplist', 'path'
        return 'attr', 'file'

    # ------------------------------ Exclusion list ------------------------------
    #   Columns: Exclusion Type, Process Name (process, file, path or volume),
    #   Parent Process Name, Library Name
    def get_exclusion_list(self):
        """
        Get the list of exclusions (Exclusion Type, Process Name columns), as dicts
        {'exclusion': <SCException constant>, 'name': <process, file, path or volume>},
        with 'parent' (Parent Process Name) and 'library' (Library Name,
        stored as 'module') keys when the rule has them.
        """
        exclusions = []
        for rule_type, key in (('skiplist', 'path'), ('attr', 'file')):
            for rule in self.get_rules(rule_type):
                for setting, value in sorted(rule.items()):
                    if value == 'true' and setting in self.EXCLUSIONS:
                        exclusion = {'exclusion': setting, 'name': rule.get(key)}
                        if rule.get('parent'):
                            exclusion['parent'] = rule['parent']
                        if rule.get('module'):
                            exclusion['library'] = rule['module']
                        exclusions.append(exclusion)
        return exclusions

    def contains_exclusion(self, exclusion, name, parent=None):
        """
        Returns True if the policy contains an exclusion (SCException) for a
        name (and a Parent Process Name, if given).
        """
        rule_type, key = self.__rule_kind(exclusion)
        match = {key: name, exclusion: 'true'}
        if parent:
            match['parent'] = parent
        return bool(self.get_rules(rule_type, match))

    def add_exclusion(self, exclusion, name, parent=None, library=None):
        """
        Add an exclusion (SCException constant) for a process, file, path,
        volume or registry path.

        :param: parent: Parent Process Name, required by ALLOW_UNINSTALLATIONS
                        and optional for PROCESS_CONTEXT (Windows only).
        :param: library: Library Name, optional for VASR_FORCED_RELOCATION
                         (Windows only).
        The values are trimmed and checked as by the console dialog (255
        characters, see is_sc_exclusion_value).
        :return: True, or False if the exclusion already exists.
        """
        if library and (self.is_unix() or exclusion not in self.LIBRARY_OPTIONAL):
            raise ValueError('Exclusion "{}" has no Library Name.'.format(exclusion))
        if self.is_unix() and exclusion not in self.UNIX_EXCLUSIONS:
            raise ValueError('Exclusion "{}" is not available on Unix.'.format(exclusion))
        if exclusion in self.PARENT_REQUIRED and not parent:
            raise ValueError('Exclusion "{}" needs a Parent Process Name.'.format(exclusion))
        if parent and (self.is_unix() or exclusion not in self.PARENT_REQUIRED +
                       self.PARENT_OPTIONAL):
            raise ValueError('Exclusion "{}" has no Parent Process Name.'.format(exclusion))
        os = 'UNIX' if self.is_unix() else 'WIN'
        name = str(name).strip()
        for field, value in [(exclusion, name), ('parent_' + exclusion, parent),
                             ('library', library)]:
            if field == exclusion or value:
                value = check_length(field, str(value).strip(), 255, required=True)
                if not is_sc_exclusion_value(value, field, os):
                    raise ValueError('Invalid {} value (see is_sc_exclusion_value): {!r}'.format(
                        field, value))
        parent = str(parent).strip() if parent else parent
        library = str(library).strip() if library else library
        if self.contains_exclusion(exclusion, name, parent):
            return False
        rule_type, key = self.__rule_kind(exclusion)
        if rule_type == 'skiplist':
            flags = self.__UNIX_SKIPLIST_FLAGS if self.is_unix() else self.__WINDOWS_SKIPLIST_FLAGS
        else:
            flags = self.__UNIX_ATTR_FLAGS if self.is_unix() else self.__WINDOWS_ATTR_FLAGS
        rule = {flag: 'false' for flag in flags}
        rule.update({'type': rule_type, key: name, exclusion: 'true'})
        if parent:
            rule['parent'] = parent
        if library:
            rule['module'] = library
        if rule_type == 'attr':
            rule['is_general_attr'] = 'true'
        return self.add_rule(rule)

    def remove_exclusion(self, exclusion, name, parent=None):
        """
        Remove an exclusion (SCException constant) for a name (and a Parent
        Process Name, if given). The rule is removed once none of its
        exclusions is set anymore.

        :return: True if the exclusion was found.
        """
        rule_type, key = self.__rule_kind(exclusion)
        match = {key: name, exclusion: 'true'}
        if parent:
            match['parent'] = parent
        if self.update_rules(rule_type, match, {exclusion: 'false'}) == 0:
            return False
        for rule in self.get_rules(rule_type, {key: name}):
            if not any(v == 'true' for k, v in rule.items() if k != 'is_general_attr'):
                self.remove_rules(rule_type, rule)
        return True


    # ------------------------------ Markdown export ------------------------------
    # Exclusion Type labels of the console list (scor.utils.optionStringMap of
    # the ePO 5.10 console).
    EXCLUSION_LABELS = {
        'casp_bypass': 'Disable buffer overflow protection (CASP)',
        'dep_bypass': 'Disable buffer overflow protection (NX)',
        'vasr_force_reloc_bypass': 'Disable ROP protection (Forced Relocation VASR)',
        'vasr_rand_bypass': 'Disable ROP protection (Randomization VASR)',
        'vasr_reloc_bypass': 'Disable ROP protection (DLL Relocation VASR)',
        'uninstall_bypass': 'Bypass uninstaller detection',
        'process_ctx_bypass': 'Exclude from write-protection and allow script execution',
        'process_ctx_reg_bypass': 'Bypass process context registry',
        'skipDenyWrite': 'Exclude path from write-protection rules',
        'skipFileOperation': 'Ignore path for file operations',
        'skipFileOperation_f': 'Exclude path from file operations',
        'skipSolidification': 'Exclude path from the allow list',
        'skipVolume': 'Exclude volume from protection',
        'skipRegistry': 'Skip registry protection',
        'skipChangeTracking': 'Skip Change Tracking'}

    def md_exclusions_table(self, table):
        """
        Returns the exclusion list as a Markdown table (Exclusion Type,
        Process Name, Parent Process Name, Library Name), in the order of the
        console (order of the rules).
        """
        rows = []
        for rule in self.get_rules():
            if rule.get('type') not in ['skiplist', 'attr']:
                continue
            name = rule.get('path') if rule.get('type') == 'skiplist' else rule.get('file')
            for setting in sorted(rule):
                if rule[setting] == 'true' and setting in self.EXCLUSIONS:
                    rows.append([self.EXCLUSION_LABELS.get(setting, setting), name,
                                 rule.get('parent', ''), rule.get('module', '')])
        return table(['Exclusion Type', 'Process Name', 'Parent Process Name', 'Library Name'],
                     rows)

class SCUpdaterRules(SCRules):
    """
    SCUpdaterRules adds the "Updater Processes" and "Users" tabs methods to the
    Solidcore policies and rule groups which have them: Application Control
    Rules and Change Control Rules. Updaters and trusted users can modify any protected file.
    """

    # ------------------------------ UPDATER PROCESSES TAB ------------------------------
    #   Columns: Updater Label, Updater Type, File/SHA-1/SHA-256, Condition,
    #   Parent/Library, Disable Inheritance, Suppress Events.
    #   An updater by name is an 'updater-binary' rule, an updater by SHA-1 or
    #   SHA-256 an 'installer' rule shown as an updater (showas='updater').
    def get_updaters(self):
        """
        Get the list of updaters ('updater-binary' rules and 'installer' rules
        shown as updaters).
        """
        return (self.get_rules('updater-binary') +
                self.get_rules('installer', {'showas': 'updater'}))

    def add_updater(self, file_name, label, parent=None, library=None,
                    disable_inheritance=False, suppress_events=False):
        """
        Add an updater by name (Updater By Name). As in the console, the
        values are trimmed, the file name and the label are required (255
        characters, server check) and on Windows the file name, parent and
        library are checked by is_sc_updater_name.

        :param: file_name: File Name (a file name or a path).
        :param: label: Updater Label.
        :param: parent: Condition Parent - the parent process name, or None.
        :param: library: Condition Library - the library name, or None.
        :param: disable_inheritance: Disable Inheritance checkbox.
        :param: suppress_events: Suppress Events checkbox.
        """
        if parent and library:
            raise ValueError('Condition must be either Parent or Library, not both.')
        os = 'UNIX' if self.is_unix() else 'WIN'
        file_name = check_length('File Name', str(file_name).strip(), 255, required=True)
        label = check_length('Updater Label', str(label).strip(), 255, required=True)
        for field, value in [('File Name', file_name), ('Parent', parent), ('Library', library)]:
            if value:
                check_length(field, str(value).strip(), 255)
                if not is_sc_updater_name(str(value).strip(), os):
                    raise ValueError('Invalid updater {} (see is_sc_updater_name): {!r}'.format(
                        field, value))
        parent = str(parent).strip() if parent else parent
        library = str(library).strip() if library else library
        rule = {'type': 'updater-binary', 'binary': file_name, 'tag': label,
                'caseSensitive': 'false', 'inherit': self._bool(not disable_inheritance),
                'log': self._bool(not suppress_events)}
        if parent:
            rule['parent'] = parent
        if library:
            rule['library'] = library
        return self.add_rule(rule)

    def add_updater_by_checksum(self, checksum, label):
        """
        Add an updater by checksum (Updater By File SHA-1 or SHA-256).
        """
        key = self._checksum_key(checksum)
        label = check_length('Updater Label', str(label).strip(), 255, required=True)
        return self.add_rule({'type': 'installer', key: checksum.lower(), 'tag': label,
                              'ruletype': 'checksum', 'showas': 'updater'})

    def remove_updater(self, label):
        """
        Remove the updater(s) with an Updater Label.

        :return: The number of rules removed.
        """
        return (self.remove_rules('updater-binary', {'tag': label}) +
                self.remove_rules('installer', {'tag': label, 'showas': 'updater'}))

    # ------------------------------ USERS TAB ------------------------------
    #   Columns: Type, UserID/Group, Name, User Label, Include Subgroups.
    #   Trusted users ('updater-user' rules) can modify any protected file.
    #   Not tested: the Active Directory groups imported with "AD Import"
    #   (groupDN, activeDirectoryId, netbiosName settings and the "Include
    #   Subgroups" column) - only single users were checked on the ePO lab.
    def get_trusted_users(self):
        """
        Get the list of trusted users ('updater-user' rules).
        """
        return self.get_rules('updater-user')

    def add_trusted_user(self, user, label, display_name=''):
        """
        Add a trusted user (Domain\\User, User Label, Name). Active Directory
        groups ("AD Import" of the console) are not supported (not tested).
        The user and the label are required, all values take 255 characters
        (server check) and a user already in the list is refused.
        """
        user = check_length('User Name', str(user).strip(), 255, required=True)
        label = check_length('User Label', str(label).strip(), 255, required=True)
        display_name = check_length('Name', str(display_name or '').strip(), 255)
        if any(rule.get('user') == user for rule in self.get_rules('updater-user')):
            raise ValueError('The trusted user {!r} is already in the list.'.format(user))
        return self.add_rule({'type': 'updater-user', 'user': user, 'tag': label,
                              'displayName': display_name, 'activeDirectoryId': '',
                              'groupDN': '', 'netbiosName': ''})

    def remove_trusted_user(self, user):
        """
        Remove a trusted user.
        """
        return self.remove_rules('updater-user', {'user': user}) > 0

    # ------------------------------ Markdown export ------------------------------
    def md_updaters_table(self, table):
        """
        Returns the Updater Processes tab as a Markdown table (table: the
        md_table function of a Policy), with the console columns.
        """
        rows = []
        for rule in self.get_updaters():
            if rule.get('type') == 'updater-binary':
                condition, value = ('Parent', rule['parent']) if rule.get('parent') else \
                    (('Library', rule['library']) if rule.get('library') else ('', ''))
                rows.append([rule.get('tag'), 'Name', rule.get('binary'), condition, value,
                             'Yes' if rule.get('inherit') == 'false' else 'No',
                             'Yes' if rule.get('log') == 'false' else 'No'])
            else:
                key = 'cksum' if 'cksum' in rule else 'cksum256'
                rows.append([rule.get('tag'), 'SHA-1' if key == 'cksum' else 'SHA-256',
                             rule.get(key), '', '', '', ''])
        unix = self.is_unix()
        return table(['Updater Label', 'Updater Type', 'File' if unix else 'File/SHA-1/SHA-256',
                      'Condition', 'Parent' if unix else 'Parent/Library',
                      'Disable Inheritance', 'Suppress Events'], rows)

    def md_users_table(self, table):
        """
        Returns the Users tab as a Markdown table, with the console columns.
        """
        rows = [['Group' if rule.get('groupDN') else 'User', rule.get('user'),
                 rule.get('displayName'), rule.get('tag'), '']
                for rule in self.get_trusted_users()]
        return table(['Type', 'UserID/Group', 'Name', 'User Label', 'Include Subgroups'], rows)
