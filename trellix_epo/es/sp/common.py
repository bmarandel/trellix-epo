# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESSPPolicy, the common part of the Endpoint
Security Storage Protection (ENSSP) policies: ICAP Policies and NetApp
Policies share the Scan Items, Performance, Actions and Reports tabs of the
ePO console, stored in sections prefixed by the policy type (e.g.
ICAPDetection / NetAppDetection).

Storage learnt from test policies changed in the ePO 5.10 console:

- File types to scan: <prefix>Detection.LocalExtensionMode 1 = All files,
  2 = Default and specified file types with "Also scan for macros in all
  files", 3 = the same without it, 4 = Specified file types only; the file
  types are space separated in szIncludeExts (default and specified) or
  szProgExts (specified only), ":::" standing for "Include files with no
  extension".
- Actions: uAction/uSecAction (threats) and <prefix>Spyware.uAction_Program/
  uSecAction_Program (unwanted programs): 5 = Clean, 4 = Delete, 1 =
  Continue Scanning; the secondary action is 0 when the first one is
  "Continue Scanning" (no second action).
"""

from ...policies import Policy
from ...validators import check_int, is_sp_file_type


class ESSPPolicy(Policy):
    """
    Common part of the ESSPPolicyICAP and ESSPPolicyNetApp classes.
    """
    PREFIX = ''
    TYPE = ''
    MD_PRODUCT = 'Endpoint Security Storage Protection'

    ALL_FILES = 'all'
    DEFAULT_AND_SPECIFIED = 'default_and_specified'
    SPECIFIED_ONLY = 'specified'
    NO_EXTENSION = ':::'

    CLEAN, DELETE, CONTINUE = '5', '4', '1'
    ACTIONS = {'5': 'Clean Files Automatically', '4': 'Delete Files Automatically',
               '1': 'Continue Scanning'}
    # Actions offered by the console (first action, second action).
    PRIMARY_ACTIONS = [CLEAN, DELETE, CONTINUE]
    SECONDARY_ACTIONS = [CONTINUE, DELETE]
    LOG_FORMATS = {'0': 'ANSI', '1': 'Unicode (UTF8)', '2': 'Unicode (UTF16)'}

    def __init__(self, policy_from_esssppolicies=None):
        super(ESSPPolicy, self).__init__(policy_from_esssppolicies)
        if policy_from_esssppolicies is not None and self.get_type() != self.TYPE:
            raise ValueError('Wrong policy! Policy type must be "{}".'.format(self.TYPE))

    def __repr__(self):
        return '{}()'.format(type(self).__name__)

    def _get(self, section, setting):
        return self.get_setting_value(self.PREFIX + section, setting)

    def _set(self, section, setting, value):
        return self.set_setting_value(self.PREFIX + section, setting, str(value), True)

    # ------------------------------ Scan Items ------------------------------
    def get_scanning(self):
        """
        Get state of Enable Scanning ('1' or '0').
        """
        return self._get('Detection', 'PlugInEnabled')

    def set_scanning(self, mode):
        """
        Set state of Enable Scanning ('1' or '0').
        """
        return self._set('Detection', 'PlugInEnabled', mode)

    scanning = property(get_scanning, set_scanning)

    @classmethod
    def __split_types(cls, value):
        items = (value or '').split()
        return [item for item in items if item != cls.NO_EXTENSION], cls.NO_EXTENSION in items

    @classmethod
    def __join_types(cls, extensions, no_extension):
        return ' '.join(([cls.NO_EXTENSION] if no_extension else []) + list(extensions))

    def get_file_types_to_scan(self):
        """
        Get the "File types to scan" options: a dict with 'mode' (ALL_FILES,
        DEFAULT_AND_SPECIFIED or SPECIFIED_ONLY), 'file_types' (list of file
        extensions), 'no_extension' (Include files with no extension) and
        'scan_macros' (Also scan for macros in all files, default and
        specified file types only).
        """
        mode = self._get('Detection', 'LocalExtensionMode')
        if mode in ['2', '3']:
            file_types, no_extension = self.__split_types(self._get('Detection', 'szIncludeExts'))
            return {'mode': self.DEFAULT_AND_SPECIFIED, 'file_types': file_types,
                    'no_extension': no_extension, 'scan_macros': mode == '2'}
        if mode == '4':
            file_types, no_extension = self.__split_types(self._get('Detection', 'szProgExts'))
            return {'mode': self.SPECIFIED_ONLY, 'file_types': file_types,
                    'no_extension': no_extension, 'scan_macros': False}
        return {'mode': self.ALL_FILES, 'file_types': [], 'no_extension': False,
                'scan_macros': False}

    def set_file_types_to_scan(self, mode, file_types=(), no_extension=False, scan_macros=False):
        """
        Set the "File types to scan" options (see get_file_types_to_scan).
        The file types of the other mode are kept, as in the console. A file
        type has 3 characters at most, without / " | < > \\ : or space
        (is_sp_file_type; use no_extension for the files with no extension).
        """
        for file_type in file_types:
            if not is_sp_file_type(file_type) or file_type == self.NO_EXTENSION:
                raise ValueError('Invalid file type: {!r}'.format(file_type))
        if mode == self.ALL_FILES:
            return self._set('Detection', 'LocalExtensionMode', '1')
        if mode == self.DEFAULT_AND_SPECIFIED:
            self._set('Detection', 'szIncludeExts', self.__join_types(file_types, no_extension))
            return self._set('Detection', 'LocalExtensionMode', '2' if scan_macros else '3')
        if mode == self.SPECIFIED_ONLY:
            if not file_types and not no_extension:
                raise ValueError('Specified file types only needs at least one file type.')
            self._set('Detection', 'szProgExts', self.__join_types(file_types, no_extension))
            return self._set('Detection', 'LocalExtensionMode', '4')
        raise ValueError('Unknown mode: {}'.format(mode))

    def get_detect_unwanted_programs(self):
        """
        Get state of Detect unwanted programs ('1' or '0').
        """
        return self._get('Spyware', 'ApplyNVP')

    def set_detect_unwanted_programs(self, mode):
        """
        Set state of Detect unwanted programs ('1' or '0').
        """
        return self._set('Spyware', 'ApplyNVP', mode)

    detect_unwanted_programs = property(get_detect_unwanted_programs,
                                        set_detect_unwanted_programs)

    def get_decode_mime(self):
        """
        Get state of Decode MIME encoded files ('1' or '0').
        """
        return self._get('Advanced', 'ScanMime')

    def set_decode_mime(self, mode):
        """
        Set state of Decode MIME encoded files ('1' or '0').
        """
        return self._set('Advanced', 'ScanMime', mode)

    decode_mime = property(get_decode_mime, set_decode_mime)

    def get_scan_archives(self):
        """
        Get state of Scan inside archives (for example .zip) and compressed
        executables ('1' or '0').
        """
        return self._get('Advanced', 'ScanArchives')

    def set_scan_archives(self, mode):
        """
        Set state of Scan inside archives (for example .zip) and compressed
        executables ('1' or '0').
        """
        return self._set('Advanced', 'ScanArchives', mode)

    scan_archives = property(get_scan_archives, set_scan_archives)

    def get_program_heuristics(self):
        """
        Get state of Find unknown unwanted programs and Trojans ('1' or '0').
        """
        return self._get('Advanced', 'dwProgramHeuristicsLevel')

    def set_program_heuristics(self, mode):
        """
        Set state of Find unknown unwanted programs and Trojans ('1' or '0').
        """
        return self._set('Advanced', 'dwProgramHeuristicsLevel', mode)

    program_heuristics = property(get_program_heuristics, set_program_heuristics)

    def get_macro_heuristics(self):
        """
        Get state of Find unknown macro threats ('1' or '0').
        """
        return self._get('Advanced', 'dwMacroHeuristicsLevel')

    def set_macro_heuristics(self, mode):
        """
        Set state of Find unknown macro threats ('1' or '0').
        """
        return self._set('Advanced', 'dwMacroHeuristicsLevel', mode)

    macro_heuristics = property(get_macro_heuristics, set_macro_heuristics)

    # ------------------------------ Performance ------------------------------
    def get_max_scan_time(self):
        """
        Get Maximum scan time (seconds).
        """
        value = self._get('Performance', 'dwMaxScanTime')
        return int(value) if value is not None else None

    def set_max_scan_time(self, seconds):
        """
        Set Maximum scan time (seconds, 10-9999).
        """
        return self._set('Performance', 'dwMaxScanTime',
                         check_int('Maximum scan time', seconds, 10, 9999))

    max_scan_time = property(get_max_scan_time, set_max_scan_time)

    def get_scan_threads(self):
        """
        Get Number of antivirus scan threads.
        """
        value = self._get('Performance', 'dwScanThreadCount')
        return int(value) if value is not None else None

    def set_scan_threads(self, count):
        """
        Set Number of antivirus scan threads (1-800).
        """
        return self._set('Performance', 'dwScanThreadCount',
                         check_int('Number of antivirus scan threads', count, 1, 800))

    scan_threads = property(get_scan_threads, set_scan_threads)

    # ------------------------------ Actions ------------------------------
    def __check_actions(self, primary, secondary):
        if primary not in self.PRIMARY_ACTIONS:
            raise ValueError('First action must be one of {}.'.format(self.PRIMARY_ACTIONS))
        if primary == self.CONTINUE:
            return '0'
        if secondary not in self.SECONDARY_ACTIONS:
            raise ValueError('Second action must be one of {}.'.format(self.SECONDARY_ACTIONS))
        return secondary

    def get_threat_actions(self):
        """
        Get the actions when a threat is found: (first action, second
        action), see ACTIONS; the second action is '0' (none) when the first
        one is CONTINUE.
        """
        return self._get('Action', 'uAction'), self._get('Action', 'uSecAction')

    def set_threat_actions(self, primary, secondary=None):
        """
        Set the actions when a threat is found (CLEAN, DELETE, CONTINUE).
        """
        secondary = self.__check_actions(primary, secondary)
        self._set('Action', 'uAction', primary)
        return self._set('Action', 'uSecAction', secondary)

    def get_unwanted_program_actions(self):
        """
        Get the actions when an unwanted program is found (see
        get_threat_actions).
        """
        return self._get('Spyware', 'uAction_Program'), self._get('Spyware', 'uSecAction_Program')

    def set_unwanted_program_actions(self, primary, secondary=None):
        """
        Set the actions when an unwanted program is found (CLEAN, DELETE,
        CONTINUE).
        """
        secondary = self.__check_actions(primary, secondary)
        self._set('Spyware', 'uAction_Program', primary)
        return self._set('Spyware', 'uSecAction_Program', secondary)

    # ------------------------------ Reports ------------------------------
    def get_reporting(self):
        """
        Get the Reports tab options: a dict with 'log_to_file' (Enable scan
        activity logging), 'limit_size' (Limit the size of log file),
        'max_size_mb', 'format' (see LOG_FORMATS), 'log_settings' (Session
        Settings and Scan Exclusions), 'log_summary' (Session summary) and
        'log_encrypt_fails' (Failure to scan encrypted files).
        """
        get = lambda setting: self._get('Reporting', setting)
        return {'log_to_file': get('bLogToFile'), 'limit_size': get('bLimitSize'),
                'max_size_mb': get('dwMaxLogSizeMB'), 'format': get('LogFileFormat'),
                'log_settings': get('bLogSettings'), 'log_summary': get('bLogSummary'),
                'log_encrypt_fails': get('bLogScanEncryptFail')}

    __REPORTING = {'log_to_file': 'bLogToFile', 'limit_size': 'bLimitSize',
                   'max_size_mb': 'dwMaxLogSizeMB', 'format': 'LogFileFormat',
                   'log_settings': 'bLogSettings', 'log_summary': 'bLogSummary',
                   'log_encrypt_fails': 'bLogScanEncryptFail'}

    def set_reporting(self, **options):
        """
        Set Reports tab options, e.g. set_reporting(log_to_file='1',
        max_size_mb=100, format='1') (see get_reporting). The maximum size
        is 1-999 MB (a textbox of 3 digits).
        """
        for key, value in options.items():
            if key not in self.__REPORTING:
                raise ValueError('Unknown reporting option: {}'.format(key))
            if key == 'format' and str(value) not in self.LOG_FORMATS:
                raise ValueError('Unknown log file format: {}'.format(value))
            if key == 'max_size_mb':
                options[key] = check_int('Maximum log file size (MB)', value, 1, 999)
        for key, value in options.items():
            self._set('Reporting', self.__REPORTING[key], value)
        return True

    # ------------------------------ Markdown export ------------------------------
    # Console labels (ePO 5.10, Endpoint Security Storage Protection policy
    # pages); each class adds its own tabs. See Policy.to_markdown().
    def _md_tab(self, description, groups):
        """
        Returns a console tab: its description then one "###" table per
        group box ((title, rows) tuples).
        """
        text = description + '\n'
        for title, rows in groups:
            text += '\n### {}\n\n{}'.format(title, self.md_settings(rows))
        return text

    def _md_actions(self, primary, secondary):
        rows = [['Perform this action first', self.ACTIONS.get(primary, primary)]]
        if primary != self.CONTINUE:
            rows.append(['If the first action fails, then perform this action',
                         self.ACTIONS.get(secondary, secondary)])
        return rows

    def _md_scan_items(self):
        options = self.get_file_types_to_scan()
        labels = {self.ALL_FILES: 'All files',
                  self.DEFAULT_AND_SPECIFIED: 'Default and specified file types',
                  self.SPECIFIED_ONLY: 'Specified file types only'}
        rows = [['File types to scan', labels[options['mode']]]]
        if options['mode'] != self.ALL_FILES:
            rows += [['Enter file types (file extensions separated by spaces)',
                      ' '.join(options['file_types'])],
                     ['Include files with no extension', 'Yes' if options['no_extension'] else 'No']]
        if options['mode'] == self.DEFAULT_AND_SPECIFIED:
            rows.append(['Also scan for macros in all files',
                         'Yes' if options['scan_macros'] else 'No'])
        return self._md_tab('Specify what items to scan.', [
            ('Scanning', [['Enable Scanning', self.md_check(self.get_scanning())]]),
            ('File types to scan', rows),
            ('Options', [
                ['Detect unwanted programs', self.md_check(self.get_detect_unwanted_programs())],
                ['Decode MIME encoded files', self.md_check(self.get_decode_mime())],
                ['Scan inside archives (for example .zip) and compressed executables',
                 self.md_check(self.get_scan_archives())]]),
            ('Heuristics', [
                ['Find unknown unwanted programs and Trojans',
                 self.md_check(self.get_program_heuristics())],
                ['Find unknown macro threats', self.md_check(self.get_macro_heuristics())]])])

    def _md_performance(self):
        return self._md_tab('Configure performance options', [
            ('Performance', [['Maximum scan time (seconds)', self.get_max_scan_time()],
                             ['Number of antivirus scan threads', self.get_scan_threads()]])])

    def _md_actions_tab(self):
        return self._md_tab('Specify how to respond when a threat is detected.', [
            ('When a threat is found', self._md_actions(*self.get_threat_actions())),
            ('When an unwanted program is found',
             self._md_actions(*self.get_unwanted_program_actions()))])

    def _md_reports(self):
        report = self.get_reporting()
        rows = [['Limit the size of log file', self.md_check(report['limit_size'])]]
        if report['limit_size'] == '1':
            rows.append(['Maximum log file size (MB)', report['max_size_mb']])
        return self._md_tab('Record scanning activity in a log file.', [
            ('Activity log', [['Enable scan activity logging',
                               self.md_check(report['log_to_file'])]]),
            ('Log file size', rows),
            ('Log file format', [['Log file format',
                                  self.LOG_FORMATS.get(report['format'], report['format'])]]),
            ('What to log in addition to scanning activity', [
                ['Session Settings and Scan Exclusions', self.md_check(report['log_settings'])],
                ['Session summary', self.md_check(report['log_summary'])],
                ['Failure to scan encrypted files',
                 self.md_check(report['log_encrypt_fails'])]])])
