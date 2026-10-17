# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class TAPolicyGeneral.
"""

import os
import re
from ..policies import Policy
from ..validators import (check_int, check_length, has_valid_macros, is_orion_ipv4,
                          is_orion_ipv6)
from .markdown import MD_PRODUCT, first_value, minutes, labelled

# Path macros of the agent console (shared.js of the extension EPOAGENTMETA).
PATH_MACROS = ['SYSTEM_DRIVE', 'SYSTEM_ROOT', 'SYSTEM_DIR', 'TEMP_DIR', 'PROGRAM_FILES_DIR',
               'PROGRAM_FILES_COMMON_DIR', 'SOFTWARE_INSTALLED_DIR', 'COMPUTER_NAME', 'USER_NAME',
               'DOMAIN_NAME']


def _valid_path_macros(path):
    """
    ContainsValidPathMacros of the console: valid macros, at most one of the
    folder macros, at the start of the path.
    """
    if not has_valid_macros(path, PATH_MACROS):
        return False
    found = [path.find(macro) for macro in PATH_MACROS[:6] if path.find(macro) != -1]
    return len(found) <= 1 and all(index <= 1 for index in found)


def _blank(text):
    """
    IsBlank of the console: a non-empty text made of spaces only.
    """
    return len(text) > 0 and text.strip(' ') == ''


def check_repository_path(label, path, windows=True, skip_empty=False):
    """
    Raise ValueError if the console refuses a SuperAgent or peer-to-peer
    repository path: 100 characters max; Windows: a drive letter or a path
    macro (<SYSTEM_DRIVE>\\...), two folders at least, none of " ; ? * | /;
    Unix: /folder/folder..., none of " ; ? * | \\ ! @ # & < > : ~ - ' , . (the
    console checks of the extension EPOAGENTMETA 5.8). "DEFAULT" and, where
    the console allows it, an empty path are accepted.
    """
    check_length(label, path, 100)
    if path == 'DEFAULT' or (skip_empty and path == ''):
        return path
    if windows:
        valid = (path[:1] == '<' or (path[:1].isascii() and path[:1].isalpha() and
                                     path.find(':\\') == 1)) and \
            '\\\\' not in path and _valid_path_macros(path) and \
            not any(char in path for char in '";?*|/') and \
            not (len(path) > 2 and path.endswith(':\\'))
        elements = path.split('\\')
    else:
        valid = path[:1] == '/' and '//' not in path and _valid_path_macros(path) and \
            not any(char in path for char in '";?*|\\!@#&<>:~-\',.')
        elements = path.split('/')
    valid = valid and len(elements) >= 3 and elements[2] != '' and \
        not any(_blank(element) for element in elements)
    if not valid:
        raise ValueError('{}: invalid path {!r} (see check_repository_path).'.format(label, path))
    return path


RELAY_ADDRESS_TYPES = ['DNS Name', 'IPv4', 'IPv6']


def check_relay_server(address_type, address, port):
    """
    Raise ValueError if the console refuses a relay server of the Relay
    Client options (extension EPOAGENTMETA 5.8): DNS Name without any of
    : \\ " ` ! @ # $ % ^ & * = ; , < > ? |, IPv4 (dotted, spaces around
    ignored), IPv6 (brackets allowed, no zone index), 254 characters max; a
    port of 1 to 65535. Returns the port as the console stores it (leading
    zeros removed).
    """
    if address_type not in RELAY_ADDRESS_TYPES:
        raise ValueError('Relay address type must be within {}.'.format(RELAY_ADDRESS_TYPES))
    check_length('Relay server address', address, 254, required=True)
    if address_type == 'DNS Name':
        valid = not any(char in address for char in ':\\"`!@#$%^&*=;,<>?|')
    elif address_type == 'IPv4':
        valid = is_orion_ipv4(address)
    else:
        bare = address[1:-1] if address.startswith('[') and address.endswith(']') else address
        valid = is_orion_ipv6(bare)
    if not valid:
        raise ValueError('Invalid {} relay server address: {!r}'.format(address_type, address))
    if not re.fullmatch(r'\d+', str(port)):
        raise ValueError('Relay server port: enter a number between 1 and 65535: {!r}'.format(port))
    return str(check_int('Relay server port', int(port), 1, 65535))

class TAPolicyGeneral(Policy):
    """
    The TAPolicyGeneral class can be used to edit the McAfee Agent policy: General.
    """

    def __init__(self, policy_from_tapolicies=None):
        super(TAPolicyGeneral, self).__init__(policy_from_tapolicies)
        if policy_from_tapolicies is not None and self.get_type() != 'General':
            raise ValueError('Wrong Trellix Agent policy. Policy type must be "General".')

    def __console_value(self, console, service):
        """
        Returns the value of a setting stored twice: the section read by the
        ePO console form (named after its fields, e.g. AgentListenServer)
        first, the "service" section (e.g. HttpServerService) if missing.
        Both are equal in policies saved by the console, not always in
        imported ones, and the console shows the first one (checked on the
        ePO 5.10 lab).
        """
        value = self.get_setting_value(*console)
        if value is None and service is not None:
            value = self.get_setting_value(*service)
        return value

    def get_table_value(self, section, keys):
        """
        Get a table (list of list) of a specific section in the XML content
        """
        return self.get_indexed_table(section, 'NumberOfItems', keys)

    def set_table_value(self, section, table):
        """
        Set a table (list of list) of a specific section in the XML content
        """
        if not table:
            return False
        keys = table[0].keys()
        return self.set_indexed_table(section, 'NumberOfItems', keys, table)

    # ------------------------------ GENERAL TAB ------------------------------
    # General options:
    #   Policy enforcement interval (minutes)
    def get_policy_enforcement_interval(self):
        """
        Get Policy enforcement interval (minutes)
        """
        value = self.__console_value(('General', 'PolicyEnforcementInterval'), None)
        return int(value) // 60 if value is not None else int(
            self.get_setting_value('PolicyService', 'PolicyEnforcementTimeout'))

    def set_policy_enforcement_interval(self, int_minutes):
        """
        Set Policy enforcement interval (minutes)
        """
        int_minutes = check_int('Policy enforcement interval (minutes)', int_minutes, 5, 10080)
        self.set_setting_value('PolicyService', 'PolicyEnforcementTimeout', str(int_minutes), True)
        return self.set_setting_value('General', 'PolicyEnforcementInterval', str(int_minutes*60))

    policy_enforcement_interval = property(get_policy_enforcement_interval,
                                           set_policy_enforcement_interval)

    #   Show the McAfee system tray icon (Windows only)
    def get_mcafee_system_tray_icon(self):
        """
        Get state of Show the McAfee system tray icon (Windows only)
        """
        return self.get_setting_value('General', 'ShowAgentUI')

    def set_mcafee_system_tray_icon(self, mode):
        """
        Set state of Show the McAfee system tray icon (Windows only)
        """
        self.set_setting_value('UpdaterService', 'EnableAgentUI', mode)
        return self.set_setting_value('General', 'ShowAgentUI', mode)

    mcafee_system_tray_icon = property(get_mcafee_system_tray_icon, set_mcafee_system_tray_icon)

    #   Allow end users to update security from the McAfee system tray menu
    def get_allow_update_security(self):
        """
        Get state of Allow end users to update security from the McAfee system tray menu
        """
        return self.get_setting_value('General', 'bAllowUpdateSecurity')

    def set_allow_update_security(self, mode):
        """
        Set state of Allow end users to update security from the McAfee system tray menu
        """
        return self.set_setting_value('General', 'bAllowUpdateSecurity', mode)

    allow_update_security = property(get_allow_update_security, set_allow_update_security)

    #   Enable McAfee system tray icon in a remote desktop session
    def get_mcafee_system_tray_icon_rdp(self):
        """
        Get state of Enable McAfee system tray icon in a remote desktop session
        """
        return self.get_setting_value('General', 'bAllowMcTrayRDP')

    def set_mcafee_system_tray_icon_rdp(self, mode, force=False):
        """
        Set state of Enable McAfee system tray icon in a remote desktop session
        """
        return self.set_setting_value('General', 'bAllowMcTrayRDP', mode, force)

    mcafee_system_tray_icon_rdp = property(get_mcafee_system_tray_icon_rdp,
                                           set_mcafee_system_tray_icon_rdp)

    #   Enable agent wake-up call support
    def get_agent_wakeup_call(self):
        """
        Get state of Enable agent wake-up call support
        """
        return self.__console_value(('AgentListenServer', 'bEnableAgentPing'),
                                    ('HttpServerService', 'IsAgentPingEnabled'))

    def set_agent_wakeup_call(self, mode):
        """
        Set state of Enable agent wake-up call support
        """
        self.set_setting_value('HttpServerService', 'IsAgentPingEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableAgentPing', mode)

    agent_wakeup_call = property(get_agent_wakeup_call, set_agent_wakeup_call)

    #   Enable super agent wake-up call support
    def get_super_agent_wakeup_call(self):
        """
        Get state of Enable super agent wake-up call support
        """
        return self.__console_value(('AgentListenServer', 'bEnableBroadcastPing'),
                                    ('UdpService', 'IsBroadcastPingEnabled'))

    def set_super_agent_wakeup_call(self, mode):
        """
        Set state of Enable super agent wake-up call support
        """
        self.set_setting_value('UdpService', 'IsEnabled', mode)
        self.set_setting_value('UdpService', 'IsBroadcastPingEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableBroadcastPing', mode)

    super_agent_wakeup_call = property(get_super_agent_wakeup_call,
                                       set_super_agent_wakeup_call)

    #   Accept connections only from the ePO server
    def get_listen_eposerver_only(self):
        """
        Get state of Accept connections only from the ePO server
        """
        return self.__console_value(('AgentListenServer', 'bListenToEPOServerOnly'),
                                    ('HttpServerService', 'IsListenToEPOServerOnly'))

    def set_listen_eposerver_only(self, mode):
        """
        Set state of Accept connections only from the ePO server
        """
        self.set_setting_value('HttpServerService', 'IsListenToEPOServerOnly', mode)
        return self.set_setting_value('AgentListenServer', 'bListenToEPOServerOnly', mode)

    listen_eposerver_only = property(get_listen_eposerver_only, set_listen_eposerver_only)

    #   Run agent processes at lower CPU priority (Windows only)
    def get_reduce_process_priority(self):
        """
        Get state of Run agent processes at lower CPU priority (Windows only)
        """
        return self.get_setting_value('General', 'ReduceProcessPriority')

    def set_reduce_process_priority(self, mode):
        """
        Set state of Run agent processes at lower CPU priority (Windows only)
        """
        return self.set_setting_value('General', 'ReduceProcessPriority', mode)

    reduce_process_priority = property(get_reduce_process_priority, set_reduce_process_priority)

    #   Enable self protection (Windows only)
    def get_self_protection(self):
        """
        Get state of Enable self protection (Windows only)
        """
        return self.get_setting_value('General', 'IsSelfProtectionEnabled')

    def set_self_protection(self, mode):
        """
        Set state of Enable self protection (Windows only)
        """
        return self.set_setting_value('General', 'IsSelfProtectionEnabled', mode)

    self_protection = property(get_self_protection, set_self_protection)

    #   Enable msgbus authentication using test certificates
    def get_test_cert_authentication(self):
        """
        Get state of Enable msgbus authentication using test certificates
        """
        return self.get_setting_value('General', 'IsTestCertAuthenticationEnabled')

    def set_test_cert_authentication(self, mode):
        """
        Set state of Enable msgbus authentication using test certificates
        """
        if mode == '1':
            module_dir = os.path.dirname(__file__)
            f_root = open(os.path.join(module_dir, '__root__.ca'), 'rt')
            root_ca = f_root.read()
            f_root.close()
            self.set_setting_value('General', 'TestCertRootCA', root_ca)
            f_signer = open(os.path.join(module_dir, '__signer__.ca'), 'rt')
            signer_ca = f_signer.read()
            f_signer.close()
            self.set_setting_value('General', 'TestCertSignerCA', signer_ca)
        else:
            self.set_setting_value('General', 'TestCertRootCA', '')
            self.set_setting_value('General', 'TestCertSignerCA', '')
        return self.set_setting_value('General', 'IsTestCertAuthenticationEnabled', mode)

    test_cert_authentication = property(get_test_cert_authentication)

    #   IP reporting mode (extension 5.8.6): '2' Default, '1' IPv4, '0' IPv6
    def get_ip_reporting_mode(self):
        """
        Get IP reporting mode: '2' (Default), '1' (IPv4) or '0' (IPv6); '2'
        when the setting is missing (extension older than 5.8.6).
        """
        return self.get_setting_value('General', 'IPVersionPreference') or '2'

    def set_ip_reporting_mode(self, mode):
        """
        Set IP reporting mode: '2' (Default), '1' (IPv4) or '0' (IPv6).
        """
        if str(mode) not in self.IP_REPORTING_MODES:
            raise ValueError('IP reporting mode must be within {}.'.format(
                list(self.IP_REPORTING_MODES)))
        return self.set_setting_value('General', 'IPVersionPreference', str(mode), True)

    ip_reporting_mode = property(get_ip_reporting_mode, set_ip_reporting_mode)

    # --------------------- Cipher suites (read only, no console field) ---------------------
    # Agent-to-server TLS cipher suites (extension 5.8.7, section AHService):
    # the agent 5.8.7 reads CipherSuiteListTA587 (TLS 1.2) and
    # TLS13CipherSuiteListOpenssl (TLS 1.3) (libma_ahclient of the Linux
    # package). No console page shows them; the console Save writes them
    # (ManagePolicy.SavePolicy) and Trellix provides the Web API command
    # EPOAGENTMETA.updateCipher to change them from the server side. The
    # library only reads them.
    def __get_cipher_list(self, setting):
        """
        Returns the cipher suites of an AHService setting as a list, e.g.
        ['TLS_AES_256_GCM_SHA384', 'TLS_AES_128_GCM_SHA256'] for
        'TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256', or None when the
        policy doesn't hold the setting (extension older than 5.8.7).
        """
        value = self.get_setting_value('AHService', setting)
        return None if value is None else [name for name in value.split(':') if name]

    def get_cipher_suites(self):
        """
        Get the TLS 1.2 cipher suites the agent 5.8.7 offers to the ePO
        server and Agent Handlers (CipherSuiteListTA587), as a list of OpenSSL
        names in order of preference, e.g. DEFAULT_CIPHER_SUITES; None when
        the setting is missing (extension older than 5.8.7).
        """
        return self.__get_cipher_list('CipherSuiteListTA587')

    cipher_suites = property(get_cipher_suites)

    def get_tls13_cipher_suites(self):
        """
        Get the TLS 1.3 cipher suites of the agent 5.8.7
        (TLS13CipherSuiteListOpenssl), as a list, e.g.
        ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
        'TLS_AES_128_GCM_SHA256']; None when the setting is missing.
        """
        return self.__get_cipher_list('TLS13CipherSuiteListOpenssl')

    tls13_cipher_suites = property(get_tls13_cipher_suites)

    def get_legacy_cipher_suites(self):
        """
        Returns the cipher suite lists of the agents older than 5.8.7, kept
        by the upgrade of the extension but no longer written by its console
        nor read by the agent 5.8.7: {'CipherSuiteList5Openssl': [...],
        'CipherSuiteList5RSA': [...]} (None for a missing setting).
        """
        return {setting: self.__get_cipher_list(setting) for setting in self.LEGACY_CIPHER_SETTINGS}

    # ------------------------------ GENERAL TAB ------------------------------
    # Reboot options after product deployment (Windows only):
    #    Prompt user when a reboot is required
    def get_prompt_user_on_reboot(self):
        """
        Get state of Prompt user when a reboot is required
        """
        return self.__console_value(('General', 'ShowRebootUI'), ('UpdaterService', 'EnableRebootUI'))

    def set_prompt_user_on_reboot(self, mode):
        """
        Set state of Prompt user when a reboot is required
        """
        self.set_setting_value('UpdaterService', 'EnableRebootUI', mode)
        return self.set_setting_value('General', 'ShowRebootUI', mode)

    prompt_user_on_reboot = property(get_prompt_user_on_reboot, set_prompt_user_on_reboot)

    #    Force automatic reboot after (seconds):
    def get_auto_reboot_after(self):
        """
        Get Force automatic reboot after (seconds)
        """
        return int(self.get_setting_value('General', 'RebootTimeOut'))

    def set_auto_reboot_after(self, int_seconds):
        """
        Set Force automatic reboot after (seconds)
        Possible values:
            -1  :to disable automatic reboot
            1-n :seconds to wait after before automatic reboot
        """
        if str(int_seconds).strip() != '-1':
            int_seconds = check_int('Force automatic reboot after (seconds)', int_seconds, 1, 10000)
        # The console writes both settings (checked on the lab, extension 5.8.6).
        self.set_setting_value('UpdaterService', 'RebootTimeout', str(int_seconds))
        return self.set_setting_value('General', 'RebootTimeOut', str(int_seconds))

    auto_reboot_after = property(get_auto_reboot_after, set_auto_reboot_after)

    # ------------------------------ GENERAL TAB ------------------------------
    # Agent-server communication:
    #   Enable agent-to-server communication
    def get_agent_server_communication(self):
        """
        Get state of Enable agent-to-server communication
        """
        return self.get_setting_value('Network', 'bAgentASCI')

    def set_agent_server_communication(self, mode):
        """
        Set state of Enable agent-to-server communication
        """
        return self.set_setting_value('Network', 'bAgentASCI', mode)

    agent_server_communication = property(get_agent_server_communication,
                                          set_agent_server_communication)

    #   Agent-to-server communication interval (minutes):
    def get_asci(self):
        """
        Get Agent-to-server communication interval (minutes).
        """
        value = self.__console_value(('Network', 'CheckNetworkMessageInterval'), None)
        return int(value) // 60 if value is not None else int(
            self.get_setting_value('PropertyService', 'PropertyCollectionTimeout'))

    def set_asci(self, int_minutes):
        """
        Set Agent-to-server communication interval (minutes)
        """
        int_minutes = check_int('Agent-to-server communication interval (minutes)', int_minutes,
                                5, 2880)
        self.set_setting_value('PropertyService', 'PropertyCollectionTimeout', str(int_minutes))
        return self.set_setting_value('Network', 'CheckNetworkMessageInterval', str(int_minutes*60))

    asci = property(get_asci, set_asci)

    #   Initiate agent-to-server communication within 10 minutes
    #   after startup if policies are older than (days):
    def get_asci_do_when(self):
        """
        Get Initiate agent-to-server communication within 10 minutes
            after startup if policies are older than (days)
        """
        return int(self.__console_value(('Network', 'AsciDoWhen'),
                                        ('PropertyService', 'PropertyCollectionIfDelayByDays')))

    def set_asci_do_when(self, int_days):
        """
        Set Initiate agent-to-server communication within 10 minutes
            after startup if policies are older than (days)
        """
        int_days = check_int('Initiate agent-to-server communication if policies are older than '
                             '(days)', int_days, 1, 360)
        self.set_setting_value('PropertyService', 'PropertyCollectionIfDelayByDays', str(int_days))
        return self.set_setting_value('Network', 'AsciDoWhen', str(int_days))

    asci_do_when = property(get_asci_do_when, set_asci_do_when)

    #   Retrieve all system and product properties (recommended).
    #   If unchecked retrieve only a subset of properties.
    def get_retrieve_full_props(self):
        """
        Get state of Retrieve all system and product properties (recommended).
        """
        return self.__console_value(('General', 'bCollectFullProps'),
                                    ('PropertyService', 'PropertyCollectFullProps'))

    def set_retrieve_full_props(self, mode):
        """
        Set state of Retrieve all system and product properties (recommended).

        Note: If unchecked retrieve only a subset of properties.
        """
        self.set_setting_value('PropertyService', 'PropertyCollectFullProps', mode)
        return self.set_setting_value('General', 'bCollectFullProps', mode)

    retrieve_full_props = property(get_retrieve_full_props, set_retrieve_full_props)

    # ------------------------------ SUPER-AGENT TAB ------------------------------
    # Repository options:
    #   Convert agents to SuperAgents
    def get_super_agent(self):
        """
        Get state of Convert agents to SuperAgents
        """
        return self.__console_value(('AgentListenServer', 'bEnableSuperAgent'),
                                    ('HttpServerService', 'IsSuperAgentEnabled'))

    def set_super_agent(self, mode):
        """
        Set state of Convert agents to SuperAgents
        """
        self.set_setting_value('HttpServerService', 'IsSuperAgentEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableSuperAgent', mode)

    super_agent = property(get_super_agent, set_super_agent)

    #   Use systems running SuperAgents as distributed repositories
    def get_sa_repository(self):
        """
        Get state of Use systems running SuperAgents as distributed repositories
        """
        return self.__console_value(('AgentListenServer', 'bEnableSuperAgentRepository'),
                                    ('HttpServerService', 'IsSuperAgentRepositoryEnabled'))

    def set_sa_repository(self, mode):
        """
        Set state of Use systems running SuperAgents as distributed repositories
        """
        self.set_setting_value('HttpServerService', 'IsSuperAgentRepositoryEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableSuperAgentRepository', mode)

    sa_repository = property(get_sa_repository, set_sa_repository)

    #   Repository path (Windows)
    def get_sa_repo_path_windows(self):
        """
        Get Repository path (Windows)
        """
        return self.__console_value(('AgentListenServer', 'VirtualDirectory'),
                                    ('HttpServerService', 'VirtualDirectory'))

    def set_sa_repo_path_windows(self, path):
        """
        Set Repository path (Windows)
        """
        check_repository_path('Repository path (Windows)', path)
        self.set_setting_value('HttpServerService', 'VirtualDirectory', path)
        return self.set_setting_value('AgentListenServer', 'VirtualDirectory', path)

    sa_repo_path_windows = property(get_sa_repo_path_windows, set_sa_repo_path_windows)

    #   Repository path (Unix)
    def get_sa_repo_path_unix(self):
        """
        Get Repository path (Unix)
        """
        return self.__console_value(('AgentListenServer', 'VirtualDirectoryUnix'),
                                    ('HttpServerService', 'VirtualDirectoryUnix'))

    def set_sa_repo_path_unix(self, path):
        """
        Set Repository path (Unix)
        """
        check_repository_path('Repository path (Unix)', path, windows=False)
        self.set_setting_value('HttpServerService', 'VirtualDirectoryUnix', path)
        return self.set_setting_value('AgentListenServer', 'VirtualDirectoryUnix', path)

    sa_repo_path_unix = property(get_sa_repo_path_unix, set_sa_repo_path_unix)

    #   Enable LazyCaching (Ensure one or more Repository is enabled)
    def get_sa_lazy_caching(self):
        """
        Get state of Enable LazyCaching
        """
        return self.__console_value(('AgentListenServer', 'bEnableLazyCaching'),
                                    ('HttpServerService', 'IsLazyCachingEnabled'))

    def set_sa_lazy_caching(self, mode):
        """
        Set Enable LazyCaching

        Note: Ensure one or more Repository is enabled.
        """
        self.set_setting_value('HttpServerService', 'IsLazyCachingEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableLazyCaching', mode)

    sa_lazy_caching = property(get_sa_lazy_caching, set_sa_lazy_caching)

    #   Interval to flush cache (minutes):
    def get_sa_cache_sync_interval(self):
        """
        Get Interval to flush cache (minutes)
        """
        return int(self.__console_value(('AgentListenServer', 'NewRepositoryContentInterval'),
                                        ('HttpServerService', 'RepositorySyncInterval')))

    def set_sa_cache_sync_interval(self, int_minutes):
        """
        Set Interval to flush cache (minutes)
        """
        int_minutes = check_int('Interval to flush cache (minutes)', int_minutes, 0, 300)
        self.set_setting_value('HttpServerService', 'RepositorySyncInterval', str(int_minutes))
        return self.set_setting_value(
            'AgentListenServer', 'NewRepositoryContentInterval', str(int_minutes))

    sa_cache_sync_interval = property(get_sa_cache_sync_interval, set_sa_cache_sync_interval)

    #   Max disk quota (GB):
    def get_sa_cache_disk_quota(self):
        """
        Get Max disk quota (GB)
        """
        return int(self.__console_value(('AgentListenServer', 'LCDiskQuota'),
                                        ('HttpServerService', 'DiskQuota')))

    def set_sa_cache_disk_quota(self, int_gigabytes):
        """
        Set Max disk quota (GB):
        """
        int_gigabytes = check_int('Max disk quota (GB)', int_gigabytes, 1, 250)
        self.set_setting_value('HttpServerService', 'DiskQuota', str(int_gigabytes))
        return self.set_setting_value('AgentListenServer', 'LCDiskQuota', str(int_gigabytes))

    sa_cache_disk_quota = property(get_sa_cache_disk_quota, set_sa_cache_disk_quota)

    #   Purge Interval (Days):
    def get_sa_cache_purge_interval(self):
        """
        Get Purge Interval (Days)
        """
        return int(self.__console_value(('AgentListenServer', 'ContentLongevity'),
                                        ('HttpServerService', 'ContentLongevity')))

    def set_sa_cache_purge_interval(self, int_days):
        """
        Set Purge Interval (Days)
        """
        int_days = check_int('Purge Interval (Days)', int_days, 1, 90)
        self.set_setting_value('HttpServerService', 'ContentLongevity', str(int_days))
        return self.set_setting_value('AgentListenServer', 'ContentLongevity', str(int_days))

    sa_cache_purge_interval = property(get_sa_cache_purge_interval, set_sa_cache_purge_interval)

    # Relay Client options:
    #   Enable Relay Communication
    def get_relay_client(self):
        """
        Get state of Enable Relay Communication
        """
        return self.__console_value(('AgentListenServer', 'IsRelayClientEnabled'),
                                    ('RelayService', 'EnableClient'))

    def set_relay_client(self, mode):
        """
        Set state of Enable Relay Communication
        """
        self.set_setting_value('RelayService', 'EnableClient', mode)
        return self.set_setting_value('AgentListenServer', 'IsRelayClientEnabled', mode)

    relay_client = property(get_relay_client, set_relay_client)

    #   Disable Discovery
    def get_relay_disable_discovery(self):
        """
        Get state of Disable Discovery
        """
        return self.get_setting_value('RelayService', 'IsRelayDiscoveryDisabled')

    def set_relay_disable_discovery(self, mode):
        """
        Set state of Disable Discovery
        """
        return self.set_setting_value('RelayService', 'IsRelayDiscoveryDisabled', mode)

    relay_disable_discovery = property(get_relay_disable_discovery, set_relay_disable_discovery)

    def get_relay_server_list(self):
        """
        Get the Relay Server list
        """
        keys = ['relayselect', 'relayip', 'relayport']
        return self.get_indexed_table('RelayService', 'RelayServerCount', keys, start=1)

    def set_relay_server_list(self, table):
        """
        Set the Relay Server list: a list of dicts {'relayselect': 'DNS Name',
        'IPv4' or 'IPv6', 'relayip': address, 'relayport': port}, checked as
        in the console (see check_relay_server).
        """
        if not table:
            return False
        keys = ['relayselect', 'relayip', 'relayport']
        rows = []
        for row in table:
            if sorted(row) != sorted(keys):
                raise ValueError('A relay server is a dict with the keys {}: {!r}'.format(keys, row))
            rows.append(dict(row, relayport=check_relay_server(row['relayselect'], row['relayip'],
                                                                row['relayport'])))
        return self.set_indexed_table('RelayService', 'RelayServerCount', keys, rows, start=1)

    relay_server_list = property(get_relay_server_list, set_relay_server_list)

    # RelayServer options:
    #   Enable RelayServer
    def get_relay_server(self):
        """
        Get state of Enable RelayServer
        """
        return self.__console_value(('AgentListenServer', 'bEnableRelayService'),
                                    ('RelayService', 'IsEnabled'))

    def set_relay_server(self, mode):
        """
        Set state of Enable RelayServer
        """
        self.set_setting_value('RelayService', 'IsEnabled', mode)
        return self.set_setting_value('AgentListenServer', 'bEnableRelayService', mode)

    relay_server = property(get_relay_server, set_relay_server)

    #   Service Manager port (RelayServer):
    def get_relay_server_port(self):
        """
        Get Service Manager port (RelayServer)
        """
        return int(self.__console_value(('AgentListenServer', 'AgtServiceMgrPort'),
                                        ('RelayService', 'RelayServerPort')))

    def set_relay_server_port(self, int_port):
        """
        Set Service Manager port (RelayServer)
        """
        int_port = check_int('Service Manager port', int_port, 1, 65535)
        self.set_setting_value('RelayService', 'RelayServerPort', str(int_port))
        return self.set_setting_value('AgentListenServer', 'AgtServiceMgrPort', str(int_port))

    relay_server_port = property(get_relay_server_port, set_relay_server_port)

    # ------------------------------ EVENTS TAB ------------------------------
    # Priority event forwarding:
    #    Enable priority event forwarding
    def get_events_priority_forwarding(self):
        """
        Get state of Enable priority event forwarding
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyEnableEventTrigger')
        return value if value is not None else self.get_setting_value(
            'EventService', 'EventIsEnabledPriorityForward')

    def set_events_priority_forwarding(self, mode, force=False):
        """
        Set state of Enable priority event forwarding
        """
        self.set_setting_value('AgentEvents', 'AgPlcyEnableEventTrigger', mode, force)
        return self.set_setting_value('EventService', 'EventIsEnabledPriorityForward', mode, force)

    events_priority_forwarding = property(get_events_priority_forwarding,
                                          set_events_priority_forwarding)

    #   Forward events with a priority equal or greater than:
    def get_events_priority_level(self):
        """
        Get Forward events with a priority equal or greater than
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyEventTriggerThreshold')
        return value if value is not None else self.get_setting_value(
            'EventService', 'EventPriorityLevel')

    def set_events_priority_level(self, level, force=False):
        """
        Set Forward events with a priority equal or greater than
        """
        if level not in ['0', '1', '2', '3', '4']:
            raise ValueError('Priority level must be within ["0", "1", "2", "3", "4"].')
        self.set_setting_value('AgentEvents', 'AgPlcyEventTriggerThreshold', level, force)
        return self.set_setting_value('EventService', 'EventPriorityLevel', level, force)

    events_priority_level = property(get_events_priority_level, set_events_priority_level)

    #   Interval between uploads (minutes):
    def get_events_upload_interval(self):
        """
        Get  Interval between uploads (minutes)
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyEventTriggerDelayMins')
        return int(value) if value is not None else int(
            self.get_setting_value('EventService', 'EventUploadTimeout'))

    def set_events_upload_interval(self, int_minutes, force=False):
        """
        Set  Interval between uploads (minutes)
        """
        int_minutes = check_int('Interval between uploads (minutes)', int_minutes, 1, 60)
        self.set_setting_value('AgentEvents', 'AgPlcyEventTriggerDelayMins',
                               str(int_minutes), force)
        return self.set_setting_value('EventService', 'EventUploadTimeout', str(int_minutes), force)

    events_upload_interval = property(get_events_upload_interval, set_events_upload_interval)

    #   Maximum number of events per upload:
    def get_events_max_per_upload(self):
        """
        Get Maximum number of events per upload:
        """
        value = self.get_setting_value('AgentEvents', 'AgPlcyMaxEventsPerTrigger')
        return int(value) if value is not None else int(
            self.get_setting_value('EventService', 'EventUploadThreshold'))

    def set_events_max_per_upload(self, int_events, force=False):
        """
        Set Maximum number of events per upload:
        """
        int_events = check_int('Maximum number of events per upload', int_events, 1, 1000)
        self.set_setting_value('AgentEvents', 'AgPlcyMaxEventsPerTrigger', str(int_events), force)
        return self.set_setting_value('EventService', 'EventUploadThreshold',
                                      str(int_events), force)

    events_max_per_upload = property(get_events_max_per_upload, set_events_max_per_upload)

    # ------------------------------ LOGGING TAB ------------------------------
    # Application logging:
    #   Enable application logging
    def get_log_application(self):
        """
        Get state of Enable application logging
        """
        value = self.get_setting_value('AgentLogging', 'IsApplicationLogEnabled')
        return value if value is not None else self.get_setting_value(
            'LoggerService', 'IsApplicationLogEnabled')

    def set_log_application(self, mode, force=False):
        """
        Set Enable application logging
        """
        self.set_setting_value('AgentLogging', 'IsApplicationLogEnabled', mode, force)
        return self.set_setting_value('LoggerService', 'IsApplicationLogEnabled', mode, force)

    log_application = property(get_log_application, set_log_application)

    #   Enable detailed logging
    def get_log_detailed(self):
        """
        Get state of Enable detailed logging
        """
        value = self.get_setting_value('AgentLogging', 'bVerbose')
        return value if value is not None else self.get_setting_value('LoggerService', 'bVerbose')

    def set_log_detailed(self, mode, force=False):
        """
        Set Enable detailed logging
        """
        self.set_setting_value('AgentLogging', 'bVerbose', mode, force)
        return self.set_setting_value('LoggerService', 'bVerbose', mode, force)

    log_detailed = property(get_log_detailed, set_log_detailed)

    #   Log file size limit (MB):
    def get_log_limit(self):
        """
        Get Log file size limit (MB)
        """
        value = self.get_setting_value('AgentLogging', 'LogSizeLimit')
        return int(value) if value is not None else int(
            self.get_setting_value('LoggerService', 'LogSizeLimit'))

    def set_log_limit(self, int_megabytes, force=False):
        """
        Set Log file size limit (MB)
        """
        int_megabytes = check_int('Log file size limit (MB)', int_megabytes, 2, 100)
        self.set_setting_value('AgentLogging', 'LogSizeLimit', str(int_megabytes), force)
        return self.set_setting_value('LoggerService', 'LogSizeLimit', str(int_megabytes), force)

    log_limit = property(get_log_limit, set_log_limit)

    #   Roll over count:
    def get_log_roll_over(self):
        """
        Get Roll over count
        """
        value = self.get_setting_value('AgentLogging', 'LogMaxRollover')
        return int(value) if value is not None else int(
            self.get_setting_value('LoggerService', 'LogMaxRollover'))

    def set_log_roll_over(self, int_count, force=False):
        """
        Set Roll over count
        """
        int_count = check_int('Roll over count', int_count, 1, 10)
        self.set_setting_value('AgentLogging', 'LogMaxRollover', str(int_count), force)
        return self.set_setting_value('LoggerService', 'LogMaxRollover', str(int_count), force)

    log_roll_over = property(get_log_roll_over, set_log_roll_over)

    # Remote logging:
    #   Enable remote Logging
    def get_log_remote(self):
        """
        Get state of Enable remote Logging
        """
        value = self.get_setting_value('AgentLogging', 'bEnableLog')
        return value if value is not None else self.get_setting_value(
            'LoggerService', 'IsLogRecordingEnabled')

    def set_log_remote(self, mode, force=False):
        """
        Set state of Enable remote Logging
        """
        self.set_setting_value('AgentLogging', 'bEnableLog', mode, force)
        return self.set_setting_value('LoggerService', 'IsLogRecordingEnabled', mode, force)

    log_remote = property(get_log_remote, set_log_remote)

    #   Limit in lines:
    def get_log_remote_limit(self):
        """
        Get Limit in lines
        """
        value = self.get_setting_value('AgentLogging', 'nLogSizeLimit')
        return int(value) if value is not None else int(
            self.get_setting_value('LoggerService', 'LogRecordsSize'))

    def set_log_remote_limit(self, int_lines, force=False):
        """
        Set Limit in lines
        """
        int_lines = check_int('Limit in lines', int_lines, 1, 5000)
        self.set_setting_value('AgentLogging', 'nLogSizeLimit', str(int_lines), force)
        return self.set_setting_value('LoggerService', 'LogRecordsSize', str(int_lines), force)

    log_remote_limit = property(get_log_remote_limit, set_log_remote_limit)

    #   Enable remote access to log
    def get_log_remote_access(self):
        """
        Get state of Enable remote access to log
        """
        value = self.get_setting_value('AgentLogging', 'bEnableRemoteLog')
        return value if value is not None else self.get_setting_value(
            'LoggerService', 'IsRemoteLogEnabled')

    def set_log_remote_access(self, mode, force=False):
        """
        Set state of Enable remote access to log
        """
        self.set_setting_value('AgentLogging', 'bEnableRemoteLog', mode, force)
        return self.set_setting_value('LoggerService', 'IsRemoteLogEnabled', mode, force)

    log_remote_access = property(get_log_remote_access, set_log_remote_access)

    # ------------------------------ UPDATES TAB ------------------------------
    # Product update log file:
    def get_upd_log_file(self):
        """
        Get Product update log file
        """
        value = self.get_setting_value('UpdateOptions', 'szLogFileName')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'UpdateLogFileName')

    def set_upd_log_file(self, path, force=False):
        """
        Set Product update log file
        """
        check_length('Product update log file', path, 254)
        self.set_setting_value('UpdateOptions', 'szLogFileName', path, force)
        return self.set_setting_value('UpdaterService', 'UpdateLogFileName', path, force)

    upd_log_file = property(get_upd_log_file, set_upd_log_file)

    # Post-update options:
    #   Enter an executable to run after an update completes:
    def get_upd_run_exe(self):
        """
        Get Enter an executable to run after an update completes
        """
        value = self.get_setting_value('UpdateOptions', 'szRunAfterUpdateEXE')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'ExeNameToRunAfterUpdate')

    def set_upd_run_exe(self, path, force=False):
        """
        Set Enter an executable to run after an update completes
        """
        check_length('Executable to run after an update', path, 254)
        self.set_setting_value('UpdateOptions', 'szRunAfterUpdateEXE', path, force)
        return self.set_setting_value('UpdaterService', 'ExeNameToRunAfterUpdate', path, force)

    upd_run_exe = property(get_upd_run_exe, set_upd_run_exe)

    #   Run only after successful updates
    def get_upd_run_exe_after_success(self):
        """
        Get state of Run only after successful updates
        """
        value = self.get_setting_value('UpdateOptions', 'bRunIfUpdateSuccess')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'EnableExeAfterUpdate')

    def set_upd_run_exe_after_success(self, mode, force=False):
        """
        Set state of Run only after successful updates
        """
        self.set_setting_value('UpdateOptions', 'bRunIfUpdateSuccess', mode, force)
        return self.set_setting_value('UpdaterService', 'EnableExeAfterUpdate', mode, force)

    upd_run_exe_after_success = property(get_upd_run_exe_after_success,
                                         set_upd_run_exe_after_success)

    #   DAT file downgrades: Enable DAT file downgrades when the version
    #   in the repository is older than local version
    def get_upd_dat_downgrade(self):
        """
        Get state of Enable DAT file downgrades when the version
            in the repository is older than local version
        """
        value = self.get_setting_value('UpdateOptions', 'bAllowDATDowngrade')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'EnableDatDowngrade')

    def set_upd_dat_downgrade(self, mode, force=False):
        """
        Set state of Enable DAT file downgrades when the version
            in the repository is older than local version
        """
        self.set_setting_value('UpdateOptions', 'bAllowDATDowngrade', mode, force)
        return self.set_setting_value('UpdaterService', 'EnableDatDowngrade', mode, force)

    upd_dat_downgrade = property(get_upd_dat_downgrade, set_upd_dat_downgrade)

    # Update options: Enable update after deployment
    def get_upd_after_deployment(self):
        """
        Get state of Enable update after deployment
        """
        value = self.get_setting_value('UpdateOptions', 'bUpdateAfterDeployment')
        return value if value is not None else self.get_setting_value(
            'UpdaterService', 'EnableUpdateAfterDeployment')

    def set_upd_after_deployment(self, mode, force=False):
        """
        Set state of Enable update after deployment
        """
        self.set_setting_value('UpdateOptions', 'bUpdateAfterDeployment', mode, force)
        return self.set_setting_value('UpdaterService', 'EnableUpdateAfterDeployment', mode, force)

    upd_after_deployment = property(get_upd_after_deployment, set_upd_after_deployment)

    # Update type and Repository branch to use:
    def get_upd_branch_selection(self):
        """
        Get  Update type and Repository branch to use
        """
        keys = ['BranchType', 'OneClickEnabled', 'SoftwareID']
        return self.get_table_value('BranchSelection', keys)

    def set_upd_branch_selection(self, table):
        """
        Set  Update type and Repository branch to use
        """
        return self.set_table_value('BranchSelection', table)

    upd_branch_selection = property(get_upd_branch_selection, set_upd_branch_selection)

    # ------------------------------ PEER-TO-PEER TAB ------------------------------
    # Peer-to-Peer Options:
    #   Enable Peer-to-Peer Communication
    def get_p2p_client(self):
        """
        Get state of Enable Peer-to-Peer Communication
        """
        return self.get_setting_value('P2pService', 'EnableClient')

    def set_p2p_client(self, mode):
        """
        Set state of Enable Peer-to-Peer Communication
        """
        return self.set_setting_value('P2pService', 'EnableClient', mode)

    p2p_client = property(get_p2p_client, set_p2p_client)

    #   Enable Peer-to-Peer Serving
    def get_p2p_server(self):
        """
        Get state of Enable Peer-to-Peer Serving
        """
        return self.get_setting_value('P2pService', 'EnableServing')

    def set_p2p_server(self, mode):
        """
        Set state of Enable Peer-to-Peer Serving
        """
        return self.set_setting_value('P2pService', 'EnableServing', mode)

    p2p_server = property(get_p2p_server, set_p2p_server)

    #   Repository path (Windows):
    def get_p2p_repo_path(self):
        """
        Get Repository path (Windows)
        """
        return self.get_setting_value('P2pService', 'P2pRepoPath')

    def set_p2p_repo_path(self, path):
        """
        Set Repository path (Windows)
        """
        check_repository_path('Repository path (Windows)', path, skip_empty=True)
        return self.set_setting_value('P2pService', 'P2pRepoPath', path)

    p2p_repo_path = property(get_p2p_repo_path, set_p2p_repo_path)

    #   Repository path (Unix):
    def get_p2p_repo_path_unix(self):
        """
        Get Repository path (Unix)
        """
        return self.get_setting_value('P2pService', 'P2pRepoPathUnix')

    def set_p2p_repo_path_unix(self, path):
        """
        Set Repository path (Unix)
        """
        check_repository_path('Repository path (Unix)', path, windows=False,
                              skip_empty=True)
        return self.set_setting_value('P2pService', 'P2pRepoPathUnix', path)

    p2p_repo_path_unix = property(get_p2p_repo_path_unix, set_p2p_repo_path_unix)

    #   Max disk quota (MB):
    def get_p2p_disk_quota(self):
        """
        Get Max disk quota (MB)
        """
        return int(self.get_setting_value('P2pService', 'DiskQuota'))

    def set_p2p_disk_quota(self, int_in_megabytes):
        """
        Set Max disk quota (MB)
        """
        int_in_megabytes = check_int('Max disk quota (MB)', int_in_megabytes, 100, 5000)
        return self.set_setting_value('P2pService', 'DiskQuota', str(int_in_megabytes))

    p2p_disk_quota = property(get_p2p_disk_quota, set_p2p_disk_quota)

    #   Purge Interval (Days):
    def get_p2p_purge_interval(self):
        """
        Get Purge Interval (Days)
        """
        return int(self.get_setting_value('P2pService', 'ContentLongevity'))

    def set_p2p_purge_interval(self, int_in_days):
        """
        Set Purge Interval (Days)
        """
        int_in_days = check_int('Purge Interval (Days)', int_in_days, 1, 90)
        return self.set_setting_value('P2pService', 'ContentLongevity', str(int_in_days))

    p2p_purge_interval = property(get_p2p_purge_interval, set_p2p_purge_interval)

    # ------------------------------ DEPLOYMENT TAB ------------------------------
    # Incompatibility check:
    #   Enable Incompatibility check
    def get_dep_compatibility_check(self):
        """
        Get state of Enable Incompatibility check
        """
        return self.get_setting_value('Deployment', 'EnableCompatibilityCheck')

    def set_dep_compatibility_check(self, mode):
        """
        Set state of Enable Incompatibility check
        """
        return self.set_setting_value('Deployment', 'EnableCompatibilityCheck', mode)

    dep_compatibility_check = property(get_dep_compatibility_check, set_dep_compatibility_check)
    # ------------------------------ Markdown export ------------------------------
    # One section per console tab, one "###" table per group box, with the
    # labels of the ePO 5.10 console (Trellix Agent > General). See
    # Policy.to_markdown() and ta/markdown.py for the settings read.
    MD_PRODUCT = MD_PRODUCT
    MD_CATEGORY = 'General'
    IP_REPORTING_MODES = {'2': 'Default', '1': 'IPv4', '0': 'IPv6'}
    # Cipher suites written by the extension 5.8.7.232 (DefaultPolicy.xml,
    # migration and console Save).
    DEFAULT_CIPHER_SUITES = ['ECDHE-ECDSA-AES256-GCM-SHA384', 'ECDHE-ECDSA-AES128-GCM-SHA256',
                             'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384',
                             'ECDHE-ECDSA-CHACHA20-POLY1305', 'ECDHE-RSA-CHACHA20-POLY1305',
                             'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES256-GCM-SHA384']
    DEFAULT_TLS13_CIPHER_SUITES = ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256',
                                   'TLS_AES_128_GCM_SHA256']
    LEGACY_CIPHER_SETTINGS = ['CipherSuiteList5Openssl', 'CipherSuiteList5RSA']
    EVENT_PRIORITIES = {'4': 'Critical', '3': 'Major', '2': 'Minor', '1': 'Warning',
                        '0': 'Informational'}
    # Update type and Repository branch to use: products known by the
    # library (product ID -> console name and group). The console lists the
    # products checked in to the ePO master repository, with their version.
    SIGNATURES, PATCHES = 'Signatures and engines', 'Patches and service packs'
    UPDATE_PRODUCTS = {
        'AMCORDAT2000': ('AMCore Content Package', SIGNATURES),
        'VSCANDAT1000': ('DAT', SIGNATURES),
        'VSCANENG1000': ('Engine', SIGNATURES),
        'MSCANENG1000': ('Mac Engine', SIGNATURES),
        'LV2SNENG1000': ('Linux Engine', SIGNATURES),
        'MED_DAT_1000': ('MEDDAT', SIGNATURES),
        'ENDPCNT_1000': ('Endpoint Security Exploit Prevention Content', SIGNATURES),
        'ENDPCNT_1000_LYNX': ('Endpoint Security Exploit Prevention Linux Content', SIGNATURES),
        'MVEDR_R_3000': ('Trellix EDR Rules for Windows', SIGNATURES),
        'MVEDR_R_3000WINX': ('Trellix EDR Rules for Windows', SIGNATURES),
        'MVEDR_R_3000LYNX': ('Trellix EDR Rules for Linux', SIGNATURES),
        'MVEDR_R_3000MACX': ('Trellix EDR Rules for macOS', SIGNATURES),
        'MAR_CONTENT_1000': ('McAfee Active Response Content Update', PATCHES),
        'JTICLIENTMETA': ('Threat Intelligence Exchange module Content', PATCHES),
        'ENDP_GS_1070LYNX': ('Trellix Endpoint Security Kernel Modules for Linux', PATCHES),
        'EPOAGENT3000META': ('ePO Agent Key Updater', PATCHES),
        'EPOAGENT5000META': ('MsgBus Cert Updater', PATCHES),
        'SOLIDCOR_KMOD_5000_LNX': ('Solidcore Kernel Modules for Linux', PATCHES),
    }

    def __md(self, *pairs):
        return first_value(self, *pairs)

    def __md_check(self, *pairs):
        return self.md_check(first_value(self, *pairs))

    def __md_group(self, title, rows):
        return '### {}\n\n{}'.format(title, self.md_settings(rows))

    def __md_cipher_suites(self):
        """
        Returns the "Agent-to-server TLS" group of the General tab (settings
        of the extension 5.8.7 that no console page shows), or '' when the
        policy holds neither list (extension older than 5.8.7). A list equal
        to the extension default is marked "(default)", e.g.
        "TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256" or
        "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
        TLS_AES_128_GCM_SHA256 (default)".
        """
        def shown(suites, default):
            if suites is None:
                return None
            return ', '.join(suites) + (' (default)' if suites == default else '')
        tls12, tls13 = self.get_cipher_suites(), self.get_tls13_cipher_suites()
        if tls12 is None and tls13 is None:
            return ''
        return '\n' + self.__md_group('Agent-to-server TLS (not shown by the console)', [
            ['TLS 1.2 cipher suites', shown(tls12, self.DEFAULT_CIPHER_SUITES)],
            ['TLS 1.3 cipher suites', shown(tls13, self.DEFAULT_TLS13_CIPHER_SUITES)]])

    def __md_general_tab(self):
        reboot = self.__md(('General', 'RebootTimeOut'), ('UpdaterService', 'RebootTimeout'))
        if reboot is not None:
            reboot = 'No' if reboot == '-1' else 'Yes, {} seconds'.format(reboot)
        text = self.__md_group('General options', [
            ['Policy enforcement interval (minutes)',
             minutes(self.__md(('General', 'PolicyEnforcementInterval')))],
            ['Show the Trellix system tray icon (Windows only)',
             self.__md_check(('General', 'ShowAgentUI'))],
            ['Allow end users to update security from the Trellix system tray menu',
             self.__md_check(('General', 'bAllowUpdateSecurity'))],
            ['Enable About box in the Trellix system tray menu',
             self.__md_check(('General', 'bEnableAboutBox'))],
            ['Enable Trellix system tray icon in a remote desktop session',
             self.__md_check(('General', 'bAllowMcTrayRDP'))],
            ['Enable agent wake-up call support',
             self.__md_check(('AgentListenServer', 'bEnableAgentPing'),
                             ('HttpServerService', 'IsAgentPingEnabled'))],
            ['Enable super agent wake-up call support',
             self.__md_check(('AgentListenServer', 'bEnableBroadcastPing'),
                             ('UdpService', 'IsBroadcastPingEnabled'))],
            ['Accept connections only from the ePO server',
             self.__md_check(('AgentListenServer', 'bListenToEPOServerOnly'),
                             ('HttpServerService', 'IsListenToEPOServerOnly'))],
            ['Run agent processes at lower CPU priority (Windows only)',
             self.__md_check(('General', 'ReduceProcessPriority'))],
            ['Enable self protection (Windows only)',
             self.__md_check(('General', 'IsSelfProtectionEnabled'))],
            ['Enable msgbus authentication using test certificates',
             self.__md_check(('General', 'IsTestCertAuthenticationEnabled'))],
            ['IP reporting mode', labelled(self.__md(('General', 'IPVersionPreference')),
                                           self.IP_REPORTING_MODES)]])
        text += self.__md_cipher_suites()
        text += '\n' + self.__md_group('Reboot options after product deployment (Windows only)', [
            ['Prompt user when a reboot is required',
             self.__md_check(('General', 'ShowRebootUI'), ('UpdaterService', 'EnableRebootUI'))],
            ['Force automatic reboot after (seconds)', reboot]])
        text += '\n' + self.__md_group('Agent-server communication', [
            ['Enable agent-to-server communication', self.__md_check(('Network', 'bAgentASCI'))],
            ['Agent-to-server communication interval (minutes)',
             minutes(self.__md(('Network', 'CheckNetworkMessageInterval')))],
            ['Initiate agent-to-server communication within 10 minutes after startup if '
             'policies are older than (days)',
             self.__md(('Network', 'AsciDoWhen'),
                       ('PropertyService', 'PropertyCollectionIfDelayByDays'))],
            ['Retrieve all system and product properties (recommended). If unchecked retrieve '
             'only a subset of properties.',
             self.__md_check(('General', 'bCollectFullProps'),
                             ('PropertyService', 'PropertyCollectFullProps'))]])
        return text

    def __md_superagent_tab(self):
        # "DEFAULT" (default repository path) is shown empty by the console.
        def path(setting):
            value = self.__md(('AgentListenServer', setting), ('HttpServerService', setting))
            return '' if value == 'DEFAULT' else value
        text = self.__md_group('Repository options', [
            ['Convert agents to SuperAgents',
             self.__md_check(('AgentListenServer', 'bEnableSuperAgent'),
                             ('HttpServerService', 'IsSuperAgentEnabled'))],
            ['Use systems running SuperAgents as distributed repositories',
             self.__md_check(('AgentListenServer', 'bEnableSuperAgentRepository'),
                             ('HttpServerService', 'IsSuperAgentRepositoryEnabled'))],
            ['Repository path (Windows)', path('VirtualDirectory')],
            ['Repository path (Unix)', path('VirtualDirectoryUnix')],
            ['Enable LazyCaching (Ensure one or more Repository is enabled)',
             self.__md_check(('AgentListenServer', 'bEnableLazyCaching'),
                             ('HttpServerService', 'IsLazyCachingEnabled'))],
            ['Interval to flush cache (minutes)',
             self.__md(('AgentListenServer', 'NewRepositoryContentInterval'),
                       ('HttpServerService', 'RepositorySyncInterval'))],
            ['Max disk quota (GB)', self.__md(('AgentListenServer', 'LCDiskQuota'),
                                              ('HttpServerService', 'DiskQuota'))],
            ['Purge Interval (Days)', self.__md(('AgentListenServer', 'ContentLongevity'),
                                                ('HttpServerService', 'ContentLongevity'))]])
        text += '\n' + self.__md_group('Relay Client options', [
            ['Enable Relay Communication',
             self.__md_check(('AgentListenServer', 'IsRelayClientEnabled'),
                             ('RelayService', 'EnableClient'))],
            ['Disable Discovery', self.__md_check(('RelayService', 'IsRelayDiscoveryDisabled'))]])
        servers = self.get_relay_server_list() or []
        text += '\nIP Address / DNS Name : Port\n\n' + self.md_table(
            ['Address type', 'IP Address / DNS Name', 'Port'],
            [[server.get('relayselect'), server.get('relayip'), server.get('relayport')]
             for server in servers if server.get('relayip')], numbered=True)
        text += '\n' + self.__md_group('RelayServer options', [
            ['Enable RelayServer', self.__md_check(('AgentListenServer', 'bEnableRelayService'),
                                                   ('RelayService', 'IsEnabled'))],
            ['Service Manager port (RelayServer)',
             self.__md(('AgentListenServer', 'AgtServiceMgrPort'),
                       ('RelayService', 'RelayServerPort'))]])
        return text

    def __md_events_tab(self):
        return self.__md_group('Priority event forwarding', [
            ['Enable priority event forwarding',
             self.__md_check(('AgentEvents', 'AgPlcyEnableEventTrigger'),
                             ('EventService', 'EventIsEnabledPriorityForward'))],
            ['Also forward non-priority events',
             self.__md_check(('AgentEvents', 'AgPlcySendNonPriorityEventsAlso'),
                             ('EventService', 'NonPriorityEventsAlso'))],
            ['Forward events with a priority equal or greater than',
             labelled(self.__md(('AgentEvents', 'AgPlcyEventTriggerThreshold'),
                                ('EventService', 'EventPriorityLevel')), self.EVENT_PRIORITIES)],
            ['Interval between uploads (minutes)',
             self.__md(('AgentEvents', 'AgPlcyEventTriggerDelayMins'),
                       ('EventService', 'EventUploadTimeout'))],
            ['Maximum number of events per upload',
             self.__md(('AgentEvents', 'AgPlcyMaxEventsPerTrigger'),
                       ('EventService', 'EventUploadThreshold'))]])

    def __md_logging_tab(self):
        text = self.__md_group('Application logging', [
            ['Enable application logging',
             self.__md_check(('AgentLogging', 'IsApplicationLogEnabled'),
                             ('LoggerService', 'IsApplicationLogEnabled'))],
            ['Enable detailed logging', self.__md_check(('AgentLogging', 'bVerbose'),
                                                        ('LoggerService', 'bVerbose'))],
            ['Log file size limit (MB)', self.__md(('AgentLogging', 'LogSizeLimit'),
                                                   ('LoggerService', 'LogSizeLimit'))],
            ['Roll over count', self.__md(('AgentLogging', 'LogMaxRollover'),
                                          ('LoggerService', 'LogMaxRollover'))]])
        text += '\n' + self.__md_group('Remote logging', [
            ['Enable remote Logging', self.__md_check(('AgentLogging', 'bEnableLog'),
                                                      ('LoggerService', 'IsLogRecordingEnabled'))],
            ['Limit in lines', self.__md(('AgentLogging', 'nLogSizeLimit'),
                                         ('LoggerService', 'LogRecordsSize'))],
            ['Enable remote access to log',
             self.__md_check(('AgentLogging', 'bEnableRemoteLog'),
                             ('LoggerService', 'IsRemoteLogEnabled'))]])
        # Shown with 50 by the console when the setting is missing.
        size = self.__md(('AgentLogging', 'sstZipSizeLimitMB'))
        text += '\n' + self.__md_group('Product Logs / File Retrieval', [
            ['Zipped log file size limit (MB)', size if size is not None else '50 (default)']])
        return text

    def __md_updates_tab(self):
        # The "Sensor options" group (bEnablePowerOption, SensorAvoidUpdateMins)
        # stays hidden in the console, even when the policy holds them.
        text = self.__md_group('Product update log file', [
            ['Product update log file', self.__md(('UpdateOptions', 'szLogFileName'),
                                                  ('UpdaterService', 'UpdateLogFileName'))]])
        text += '\n' + self.__md_group('Post-update options', [
            ['Enter an executable to run after an update completes',
             self.__md(('UpdateOptions', 'szRunAfterUpdateEXE'),
                       ('UpdaterService', 'ExeNameToRunAfterUpdate'))],
            ['Run only after successful updates',
             self.__md_check(('UpdateOptions', 'bRunIfUpdateSuccess'))]])
        text += '\n' + self.__md_group('DAT file downgrades', [
            ['Enable DAT file downgrades when the version in the repository is older than '
             'local version', self.__md_check(('UpdateOptions', 'bAllowDATDowngrade'),
                                              ('UpdaterService', 'EnableDatDowngrade'))]])
        text += '\n' + self.__md_group('Update options', [
            ['Enable update after deployment',
             self.__md_check(('UpdateOptions', 'bUpdateAfterDeployment'),
                             ('UpdaterService', 'EnableUpdateAfterDeployment'))]])
        rows = []
        for item in self.get_upd_branch_selection() or []:
            product = item.get('SoftwareID', '')
            name, group = self.UPDATE_PRODUCTS.get(product, ('', 'Other products'))
            rows.append([group, name, product, self.md_check(item.get('OneClickEnabled')),
                         item.get('BranchType')])
        order = [self.SIGNATURES, self.PATCHES, 'Other products']
        rows.sort(key=lambda row: order.index(row[0]))
        text += '\n### Update type and Repository branch to use\n\n' \
                'Select branch for the update type (the checkbox enables/disables the updates ' \
                'for One Click update and Update after deployment). The console only lists ' \
                'the products checked in to the ePO repository.\n\n'
        text += self.md_table(['Update type', 'Product', 'Product ID', 'Enabled', 'Branch'], rows)
        return text

    def __md_p2p_tab(self):
        return self.__md_group('Peer-to-Peer Options', [
            ['Enable Peer-to-Peer Communication', self.__md_check(('P2pService', 'EnableClient'))],
            ['Enable Peer-to-Peer Serving', self.__md_check(('P2pService', 'EnableServing'))],
            ['Repository path (Windows)', self.__md(('P2pService', 'P2pRepoPath'))],
            ['Repository path (Unix)', self.__md(('P2pService', 'P2pRepoPathUnix'))],
            ['Max disk quota (MB)', self.__md(('P2pService', 'DiskQuota'))],
            ['Purge Interval (Days)', self.__md(('P2pService', 'ContentLongevity'))]])

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        return [('General', self.__md_general_tab()),
                ('SuperAgent', self.__md_superagent_tab()),
                ('Events', self.__md_events_tab()),
                ('Logging', self.__md_logging_tab()),
                ('Updates', self.__md_updates_tab()),
                ('Peer-to-Peer', self.__md_p2p_tab()),
                ('Deployment', self.__md_group('Incompatibility check', [
                    ['Enable Incompatibility check',
                     self.__md_check(('Deployment', 'EnableCompatibilityCheck'))]]))]
