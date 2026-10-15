# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class EDRFPolicyInvestigation (Trellix EDR with
Forensics: Investigation - Real-Time Search, Network Flow, File Hashing,
Exclusions).

Storage learnt from test policies changed in the ePO 5.10 console
(extensions XCLIENT_META 2.1.2.270 and 50.3.0.900): every exclusion list is
stored with doubled backslashes and semicolons (line breaks replaced). The
Windows path lists use the Windows known folder names, e.g.
FOLDERID_ProgramData\\McAfee\\Common Framework.

Since the extension 50.3 the lists are split in 3072 character parts by the
ePO server (see EDRFPolicy) and their double quotes are no longer escaped
(2.1.2 stored \\"). The Investigation page reads its settings with
JSON.parse('...'): an unescaped " stops the console from opening the policy
(the same bug on the Remediation page was checked on the lab), so the
library refuses " in the lists.
"""

from .policy import EDRFPolicy, CHECK, NUMBER, SELECT, LIST

FH, NF = 'UEDR/FileHashing/', 'UEDR/NetworkFlow/'


class EDRFPolicyInvestigation(EDRFPolicy):
    """
    The EDRFPolicyInvestigation class can be used to edit the Trellix EDR
    with Forensics policy: Investigation.
    """
    MD_CATEGORY = 'Investigation'
    TYPE = 'Investigation'
    HASH_STRATEGIES = {'low': 'Low', 'normal': 'Normal', 'medium': 'Medium', 'high': 'High',
                       'auto': 'Auto'}

    OPTIONS = {
        # Real-Time Search - System Information
        'max_search_results': ('UEDR/General/max_merge_retrieve',
                               'Maximum number of results returned by Real-time Search', NUMBER,
                               32, 8192),
        'process_history': ('UEDR/SystemInfo/processhistory', 'Enable process history', CHECK),
        # Network Flow
        'network_flow': (NF + 'enabled', 'Enable Network flow collector', CHECK),
        'network_sniffer': (NF + 'netsniffing', 'Enable Network Sniffer', CHECK),
        'network_log_system': (NF + 'log_system',
                               'Collect TCP/UDP system process information (Windows Only)', CHECK),
        'network_storage': (NF + 'max_db_size_mb', 'Maximum size of device storage that can be '
                            'used by Network Flow collector (MB)', NUMBER, 1, 8192),
        'network_storage_percentage': (NF + 'max_db_size_percentage', 'Maximum percentage of '
                                       'device storage that can be used by the Network Flow '
                                       'collector', NUMBER, 0, 100),
        'network_max_results': (NF + 'max_retrieve', 'Maximum number of results returned by the '
                                'Network Flow collector', NUMBER, 64, 8192),
        # File Hashing
        'file_hashing': (FH + 'enabled', 'Enable File Hashing on the device (enables the Files '
                         'collector and trigger)', CHECK),
        'hashing_power_saved': (FH + 'power_saved', 'Pause File Hashing when the device is '
                                'running out of battery life', CHECK),
        'hashing_storage': (FH + 'max_db_size_mb', 'Maximum size (MB) of the device storage that '
                            'can be used by the File Hashing collector', NUMBER, 1, 8192),
        'hashing_storage_percentage': (FH + 'max_db_size_percentage', 'Maximum percentage of the '
                                       'device storage used by the File Hashing collector '
                                       'database', NUMBER, 0, 100),
        'hashing_max_results': (FH + 'max_retrieve', 'Maximum number of results returned by the '
                                'File Hashing collector', NUMBER, 64, 8192),
        'hash_strategy': (FH + 'hash_strategy', 'Hash strategy', SELECT, HASH_STRATEGIES),
        'hash_delay': (FH + 'hash_delay', 'Delay File Hashing process after booting the device '
                       'by (seconds)', NUMBER, 60, 8192),
        'hash_max_file_size': (FH + 'max_file_size_mb', 'Maximum file size for hashing (MB)',
                               NUMBER, 0, 8192),
        # Exclusions
        'network_process_exclusions': (NF + 'ignored_paths', 'Exclude process(es) by full path '
                                       'from collecting TCP/UDP information from Network '
                                       'collection (Windows)', LIST, True),
        'windows_hashing_files': (FH + 'ignored_exact_files_windows',
                                  'Exclude file(s) from File Hashing (Windows)', LIST, True),
        'windows_hashing_extensions': (FH + 'ignored_extensions_windows',
                                       'Exclude file extension(s) from File Hashing (Windows)',
                                       LIST, False),
        'windows_hashing_paths': (FH + 'ignored_paths_windows',
                                  'Exclude path(s) from File Hashing (Windows)', LIST, True),
        'linux_hashing_files': (FH + 'ignored_exact_files_linux',
                                'Exclude file(s) from File Hashing (Linux)', LIST, False),
        'linux_hashing_extensions': (FH + 'ignored_extensions_linux',
                                     'Exclude file extension(s) from File Hashing (Linux)', LIST,
                                     False),
        'linux_hashing_paths': (FH + 'ignored_paths_linux',
                                'Exclude path(s) from File Hashing (Linux)', LIST, False),
        'mac_hashing_files': (FH + 'ignored_exact_files_macos',
                              'Exclude file(s) from File Hashing (Mac)', LIST, False),
        'mac_hashing_extensions': (FH + 'ignored_extensions_macos',
                                   'Exclude files extension(s) from File Hashing (Mac)', LIST,
                                   False),
        'mac_hashing_paths': (FH + 'ignored_paths_macos',
                              'Exclude path(s) from File Hashing (Mac)', LIST, False),
    }
    ESCAPE_QUOTES = True
    DOUBLE_BACKSLASHES = (NF + 'ignored_paths',) + tuple(
        FH + 'ignored_{}_{}'.format(kind, platform) for kind in ('exact_files', 'extensions', 'paths')
        for platform in ('windows', 'linux', 'macos'))
    DEFAULTS = {NF + 'ignored_paths': ''}
    CHUNKED = DOUBLE_BACKSLASHES
    QUOTES_BREAK_CHUNKS = True

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console group box (see Policy.to_markdown). Extension lists
        are shown on one line, file and path lists as tables.
        """
        sections = [
            ('Real-Time Search', '### System Information\n\n' + self.md_settings(self.md_rows(
                ['max_search_results', 'process_history']))),
            ('Network Flow', self.md_settings(self.md_rows(
                ['network_flow', 'network_sniffer', 'network_log_system', 'network_storage',
                 'network_storage_percentage', 'network_max_results']))),
            ('File Hashing', self.md_settings(self.md_rows(
                ['file_hashing', 'hashing_power_saved', 'hashing_storage',
                 'hashing_storage_percentage', 'hashing_max_results', 'hash_strategy',
                 'hash_delay', 'hash_max_file_size'])))]
        text = ''
        for platform in ('Windows', 'Linux', 'Mac'):
            prefix = platform.lower()
            text += '### {}\n\n'.format(platform)
            if platform == 'Windows':
                text += self.md_list('network_process_exclusions') + '\n'
            text += self.md_settings(self.md_rows([prefix + '_hashing_extensions'])) + '\n'
            text += self.md_list(prefix + '_hashing_files') + '\n'
            text += self.md_list(prefix + '_hashing_paths') + '\n'
        sections.append(('Exclusions', text))
        return sections
