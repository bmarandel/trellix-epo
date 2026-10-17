# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes ESCommonPolicyOptions (Endpoint Security
Common: Options) and AACExclusion.

Storage learnt from a test policy changed in the ePO 5.10 console:

- Checkboxes are stored as 'true' / 'false' (the class reads and writes
  '1' / '0', like the other ENS classes).
- Client Interface Mode: ClientInterfaceStatus.clientUIAccessLevel 0 = Full
  access, 2 = Standard access, 1 = Lock client interface.
- Radio buttons store their position: proxy (gtiProxyType) 0 = No proxy
  server, 1 = Use system proxy settings, 2 = Configure proxy server; What to
  update (whatToUpdateLevel) 0 = Security content, hotfixes, and patches,
  1 = Security content, 2 = Hotfixes and patches.
- Event levels (suppressAlertsBelow<module>) 5 = None ... 0 = All; EDR
  events (EDREventLevel<module>) 0 = None, 1 = Alerts only (also when the
  setting is missing), 2 = Alerts and events. Modules: AP (Access
  Protection), BO (Exploit Prevention), OAS, ODS, FW, WP (Web Control), ATP.
- Lists: SelfProtectionStatus.spProcessExclusion_<n> (spProcessExclCount);
  GlobalExclusions.GlobalExclusion_<n> = "process|process MD5|signer
  certificate MD5|notes" (dwExclCount). The console creates the
  GlobalExclusions and NetworkConfigurations sections when missing; so does
  the library.

Passwords: the client interface administrator password, the uninstall
password, the HTTP proxy password and the time of the time-based password
are not in the policy export (adminPassword, clientUninstallPassword,
httpAuthPassword are always empty). Checked on the ePO 5.10 lab: importing
an exported Common policy (with the library or the console Import) erases
the passwords defined in the console - they must be defined again in the
console after the import. The library never sets them.
The trusted vendor Certificates list (Upload Client Certificate) is not
supported (no certificate on the lab to learn its storage).

Values accepted by the console (Endpoint Security Platform extension
26.8.0.19750, checked on the lab page): number ranges in number_options();
Log files location 256 characters, no * ? " | and only the macros
LOG_PATH_MACROS (a path starting with / follows the Linux rule: no \\ * ?
| & ; + "); proxy address 100 characters, an IP address or a host name /
FQDN (validateServerIpOrFqdn); proxy port 1-65535; Self Protection process
exclusions: a drive letter path or a file name, wildcards allowed, none of
\\\\ / " < > | in a file name, no duplicate (validateExclusion).
"""

import re
import xml.etree.ElementTree as et

from ...policies import Policy
from ...validators import (check_int, check_length, has_valid_macros, is_orion_hostname,
                           is_orion_ipv4, is_orion_ipv6)

# Path macros of the ENS pages (g_szValidMacros of GeneralSettingsPolicy).
LOG_PATH_MACROS = ['SYSTEM_DRIVE', 'SYSTEM_ROOT', 'SYSTEM_DIR', 'TEMP_DIR', 'PROGRAM_FILES_DIR',
                   'PROGRAM_FILES_COMMON_DIR', 'SOFTWARE_INSTALLED_DIR']
# IsValidDriveLetterPath / IsValidFilename of VSECommon.js, wildcards allowed.
DRIVE_PATH = re.compile(r'^(((([a-zA-Z*?]:(\\(?!\\))))(([^\\/"<>|]+(\\(?!\\)))|([^\\/"<>|]))*))$')
FILE_NAME = re.compile(r'^([^\\/"<>|]+)$')


def check_log_location(location):
    """
    Raise ValueError if the console refuses a Log files location
    (validateLogfilePath of the ENS Common page).
    """
    check_length('Log files location', location, 256, required=True)
    if location.startswith('/'):
        valid = not any(char in location for char in '\\*?|&;+"')
    else:
        valid = not any(char in location for char in '*?"|') and \
            has_valid_macros(location, LOG_PATH_MACROS)
    if not valid:
        raise ValueError('Invalid log files location: {!r}'.format(location))
    return location


def check_proxy_address(address):
    """
    Raise ValueError if the console refuses a proxy server address
    (validateServerIpOrFqdn of the ENS Common page): an IP address, a host
    name, or a host name followed by a domain name.
    """
    check_length('Proxy server address', address, 100, required=True)
    if address != address.strip(' '):
        valid = False
    elif is_orion_ipv4(address) or is_orion_ipv6(address):
        valid = True
    elif '.' not in address:
        valid = is_orion_hostname(address)
    else:
        host, domain = address[:address.index('.')], address[address.index('.'):]
        valid = is_orion_hostname(host) and is_orion_hostname(domain)
    if not valid:
        raise ValueError('Invalid proxy server address: {!r}'.format(address))
    return address


def check_sp_exclusion(process):
    """
    Raise ValueError if the console refuses a Self Protection process
    exclusion (validateExclusion of the ENS Common page).
    """
    if not isinstance(process, str) or not process.strip() or \
            not (DRIVE_PATH.search(process) or FILE_NAME.search(process)):
        raise ValueError('Invalid Self Protection process exclusion: {!r}'.format(process))
    return process


class AACExclusion():
    """
    A process excluded from Trellix AAC protection (Exclusions, Windows only).

    :param: process: Process (full path), required.
    :param: md5: Process MD5 hash.
    :param: signer_md5: Signer certificate MD5 hash.
    :param: notes: Notes.
    The console requires the process hash, the signer certificate hash, or both.
    """

    def __init__(self, process, md5='', signer_md5='', notes=''):
        self.process = process
        self.md5 = md5 or ''
        self.signer_md5 = signer_md5 or ''
        self.notes = notes or ''

    def __repr__(self):
        return 'AACExclusion({!r}, md5={!r}, signer_md5={!r}, notes={!r})'.format(
            self.process, self.md5, self.signer_md5, self.notes)

    def __eq__(self, other):
        return isinstance(other, AACExclusion) and self.to_value() == other.to_value()

    @classmethod
    def from_value(cls, value):
        parts = (value.split('|') + ['', '', '', ''])[:4]
        return cls(*parts)

    def to_value(self):
        return '|'.join([self.process, self.md5, self.signer_md5, self.notes])

    def check(self):
        """
        Raise ValueError if the console would refuse the exclusion.
        """
        import re
        if not self.process:
            raise ValueError('An AAC exclusion needs a process (full path).')
        if not (self.md5 or self.signer_md5):
            raise ValueError('Process hash, signer certificate hash, or both must be specified.')
        for value in (self.md5, self.signer_md5):
            if value and not re.fullmatch('[0-9a-fA-F]{32}', value):
                raise ValueError('An MD5 hash is 32 hexadecimal digits: {!r}'.format(value))
        for value in (self.process, self.notes):
            if '|' in value or len(value) > 260:
                raise ValueError('Process and notes: 260 characters max, no "|".')


class ESCommonPolicyOptions(Policy):
    """
    The ESCommonPolicyOptions class can be used to edit the Endpoint Security
    Common policy: Options (checked against the ePO 5.10 console).
    """

    MD_PRODUCT = 'Endpoint Security Common'
    MD_CATEGORY = 'Options'
    TYPE = 'EGS_Product_Configuration_Policies'

    FULL_ACCESS, LOCK_INTERFACE, STANDARD_ACCESS = '0', '1', '2'
    ACCESS_LEVELS = {FULL_ACCESS: 'Full access', STANDARD_ACCESS: 'Standard access',
                     LOCK_INTERFACE: 'Lock client interface'}
    LANGUAGES = {'0000': 'Automatic', '0404': 'Chinese (Traditional)',
                 '0804': 'Chinese (Simplified)', '0413': 'Dutch', '0409': 'English',
                 '040C': 'French', '0407': 'German', '040D': 'Hebrew', '0410': 'Italian',
                 '0411': 'Japanese', '0412': 'Korean', '0415': 'Polish',
                 '0416': 'Portuguese (Brazilian)', '0419': 'Russian', '0C0A': 'Spanish',
                 '041D': 'Swedish'}
    SP_ACTIONS = {'1': 'Block only', '2': 'Report only', '3': 'Block and report'}
    EVENT_LEVELS = {'5': 'None', '4': 'Alert only', '3': 'Critical and Alert',
                    '2': 'Warning, Critical, and Alert', '1': 'All except Informational',
                    '0': 'All'}
    EDR_LEVELS = {'0': 'None', '1': 'Alerts only', '2': 'Alerts and events'}
    # Event modules: key -> console label, in the console order.
    EVENT_MODULES = {'AP': 'Access Protection', 'BO': 'Exploit Prevention',
                     'OAS': 'On-Access Scan', 'ODS': 'On-Demand Scan', 'FW': 'Firewall',
                     'WP': 'Web Control', 'ATP': 'Adaptive Threat Protection'}
    PROXY_TYPES = {'0': 'No proxy server', '1': 'Use system proxy settings',
                   '2': 'Configure proxy server'}
    UPDATE_LEVELS = {'0': 'Security content, hotfixes, and patches', '1': 'Security content',
                     '2': 'Hotfixes and patches'}
    LOG_LOCATION_MACROS = ['<SYSTEM_DRIVE>', '<SYSTEM_ROOT>', '<SYSTEM_DIR>', '<TEMP_DIR>',
                           '<PROGRAM_FILES_DIR>', '<PROGRAM_FILES_COMMON_DIR>',
                           '<SOFTWARE_INSTALLED_DIR>']
    # Threat Prevention debug logging: one checkbox per module.
    TP_DEBUG = {'enableSPAPClientDebugLogging': 'Enable for Access Protection',
                'enableSPBOClientDebugLogging': 'Enable for Exploit Prevention',
                'enableSPOASClientDebugLogging': 'Enable for On-Access Scan',
                'enableSPODSClientDebugLogging': 'Enable for On-Demand Scan'}

    # Checkbox options: name -> (section, setting, console label).
    __CHECKBOXES = {
        'interface_lockout': ('ClientInterfaceStatus', 'enableClientUI',
                              'Enable client interface lockout'),
        'uninstall_password': ('ClientUninstall', 'enableClientUninstallPassword',
                               'Require password to uninstall the client'),
        'time_based_password': ('ClientInterfaceStatus', 'enableTimeBasedPassword',
                                'Enable time-based password in client interface'),
        'self_protection': ('SelfProtectionStatus', 'spEnable', 'Enable Self Protection'),
        'sp_files': ('SelfProtectionStatus', 'spFiles', 'Files and folders'),
        'sp_registry': ('SelfProtectionStatus', 'spRegistry', 'Registry (Windows only)'),
        'sp_processes': ('SelfProtectionStatus', 'spProcesses',
                         'Processes (Windows & Mac only)'),
        'activity_logging': ('ClientLoggingOptions', 'enableClientActivityLogging',
                             'Enable activity logging'),
        'ods_activity_logging': ('ClientLoggingOptions', 'enableODSClientActivityLogging',
                                 'Log all scanned files during on-demand scans'),
        'activity_log_size_limit': ('ClientLoggingOptions',
                                    'enableClientActivityLoggingSizeLimits',
                                    'Limit size (MB) of each of the activity log files'),
        'debug_fw': ('ClientLoggingOptions', 'enableDFClientDebugLogging', 'Enable for Firewall'),
        'debug_wc': ('ClientLoggingOptions', 'enableWPClientDebugLogging',
                     'Enable for Web Control (Windows & Mac only)'),
        'debug_atp': ('ClientLoggingOptions', 'enableATPClientDebugLogging',
                      'Enable for Adaptive Threat Protection (Windows only)'),
        'debug_sp': ('ClientLoggingOptions', 'enableSTPClientDebugLogging',
                     'Enable for Storage Protection (Windows only)'),
        'debug_log_size_limit': ('ClientLoggingOptions', 'enableClientDebugLoggingSizeLimits',
                                 'Limit size (MB) of each of the debug log files (Windows only)'),
        'send_events_to_epo': ('ClientLoggingOptions', 'IsSendEventsToepoEnabled',
                               'Send events to Trellix ePO'),
        'windows_event_log': ('ClientLoggingOptions', 'IsWindowsApplicationLoggingEnabled',
                              'Log events to Windows Event Log or syslog (Windows & Linux only)'),
        'event_db_size_limit': ('ClientLoggingOptions', 'enableClientEventLoggingSizeLimits',
                                'Limit the size (MB) of event DB (Windows only)'),
        'proxy_authentication': ('ClientGTIProxy', 'enableHTTPAuth',
                                 'Enable HTTP proxy authentication'),
        'ipv6': ('NetworkConfigurations', 'useIPv6Url', 'Use IPv6 for cloud connectivity'),
        'update_now_button': ('ClientUpdate', 'enableUpdateNowButton',
                              'Enable the Update Now button (Windows only)'),
        'default_update_task': ('ClientUpdate', 'enableDefaultUpdateTask',
                                'Enable Default Client Update task schedule'),
        'managed_tasks': ('ClientInterfaceAccess', 'showManagedTasks',
                          'Display managed custom tasks'),
    }
    # Number options: name -> (section, setting, console label, min, max).
    __NUMBERS = {
        'password_attempts': ('ClientInterfaceStatus', 'clientUIPasswordAttemptCount',
                              'Number of failed password attempts', 1, 99),
        'lockout_time_frame': ('ClientInterfaceStatus', 'clientUILockOutRepeatAttemptsWithin',
                               'Within time frame (minutes)', 1, 999),
        'lockout_minutes': ('ClientInterfaceStatus', 'clientUILockOutInterval',
                            'Number of minutes to lock client interface', 1, 999),
        'activity_log_size': ('ClientLoggingOptions', 'maxClientActivityLogSizeMB',
                              'Limit size (MB) of each of the activity log files', 1, 999),
        'debug_log_size': ('ClientLoggingOptions', 'maxClientDebugLogSizeMB',
                           'Limit size (MB) of each of the debug log files', 1, 999),
        'event_db_size': ('ClientLoggingOptions', 'maxClientEventLogSizeMB',
                          'Limit the size (MB) of event DB', 50, 999),
    }

    def __init__(self, policy_from_escommonpolicies=None):
        super(ESCommonPolicyOptions, self).__init__(policy_from_escommonpolicies)
        if policy_from_escommonpolicies is not None and self.get_type() != self.TYPE:
            raise ValueError('Wrong policy! Policy type must be "{}".'.format(self.TYPE))

    def _info_counts(self):
        """
        The counts of get_info() and of the representation: the Self Protection and AAC exclusions.
        """
        return {'self_protection_exclusions': len(self.get_sp_process_exclusions()),
                'aac_exclusions': len(self.get_aac_exclusions())}

    # ------------------------------ Storage helpers ------------------------------
    def __section(self, name):
        """
        Returns a Section, created if missing (as the console does).
        """
        section = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(name))
        if section is None:
            settings = self.root.find('./EPOPolicySettings')
            section = et.SubElement(settings, 'Section', {'name': name})
        return section

    def __get(self, section, setting, default=None):
        value = self.get_setting_value(section, setting)
        return default if value is None else value

    def __set(self, section, setting, value):
        self.__section(section)
        return self.set_setting_value(section, setting, str(value), True)

    @staticmethod
    def __to_mode(value):
        return None if value is None else ('1' if value == 'true' else '0')

    @staticmethod
    def __from_mode(mode):
        if str(mode) in ('1', 'True', 'true'):
            return 'true'
        if str(mode) in ('0', 'False', 'false'):
            return 'false'
        raise ValueError('The state must be "1" or "0".')

    # ------------------------------ Generic options ------------------------------
    @classmethod
    def options(cls):
        """
        Returns the checkbox options as a dict {name: console label}.
        """
        return {name: label for name, (_, _, label) in cls.__CHECKBOXES.items()}

    @classmethod
    def number_options(cls):
        """
        Returns the number options as a dict {name: (console label, min, max)}.
        """
        return {name: (label, low, high)
                for name, (_, _, label, low, high) in cls.__NUMBERS.items()}

    def get_option(self, name):
        """
        Get a checkbox ('1' or '0') or number option, e.g. get_option('ipv6').
        See ESCommonPolicyOptions.options() and number_options().
        """
        if name in self.__NUMBERS:
            section, setting = self.__NUMBERS[name][:2]
            value = self.__get(section, setting)
            return int(value) if value not in (None, '') else None
        section, setting, _ = self.__CHECKBOXES[name]
        default = 'false' if name == 'ipv6' else None
        return self.__to_mode(self.__get(section, setting, default))

    def set_option(self, name, value):
        """
        Set a checkbox ('1' or '0') or number option, e.g. set_option('ipv6', '1').
        """
        if name in self.__NUMBERS:
            section, setting, label, low, high = self.__NUMBERS[name]
            return self.__set(section, setting, check_int(label, value, low, high))
        section, setting, _ = self.__CHECKBOXES[name]
        return self.__set(section, setting, self.__from_mode(value))

    # ------------------------------ Client interface ------------------------------
    def get_access_level(self):
        """
        Get the Client Interface Mode: FULL_ACCESS ('0'), STANDARD_ACCESS
        ('2') or LOCK_INTERFACE ('1').
        """
        return self.__get('ClientInterfaceStatus', 'clientUIAccessLevel')

    def set_access_level(self, level):
        """
        Set the Client Interface Mode: FULL_ACCESS ('0'), STANDARD_ACCESS
        ('2') or LOCK_INTERFACE ('1'). Standard access and Lock client
        interface need an administrator password, which can only be defined
        in the ePO console (see the module documentation).
        """
        if str(level) not in self.ACCESS_LEVELS:
            raise ValueError('The access level must be "0" (Full), "2" (Standard) or "1" (Lock).')
        return self.__set('ClientInterfaceStatus', 'clientUIAccessLevel', level)

    access_level = property(get_access_level, set_access_level)

    def get_interface_language(self):
        """
        Get the Client Interface Language code ('0000' Automatic, '0409'
        English, '040C' French... see LANGUAGES).
        """
        return self.__get('ClientInterfaceStatus', 'clientInterfaceLanguage')

    def set_interface_language(self, code):
        """
        Set the Client Interface Language code (see LANGUAGES).
        """
        if code not in self.LANGUAGES:
            raise ValueError('Language must be within {}.'.format(list(self.LANGUAGES)))
        return self.__set('ClientInterfaceStatus', 'clientInterfaceLanguage', code)

    interface_language = property(get_interface_language, set_interface_language)

    # ------------------------------ Self Protection ------------------------------
    def get_sp_action(self, resource):
        """
        Get the Self Protection action of a resource ('files', 'registry' or
        'processes'): '1' Block only, '2' Report only, '3' Block and report.
        """
        return self.__get('SelfProtectionStatus', 'sp{}Action'.format(resource.capitalize()))

    def set_sp_action(self, resource, action):
        """
        Set the Self Protection action of a resource ('files', 'registry' or
        'processes'): '1' Block only, '2' Report only, '3' Block and report.
        """
        if resource not in ('files', 'registry', 'processes'):
            raise ValueError('The resource must be "files", "registry" or "processes".')
        if str(action) not in self.SP_ACTIONS:
            raise ValueError('The action must be "1", "2" or "3".')
        return self.__set('SelfProtectionStatus', 'sp{}Action'.format(resource.capitalize()),
                          action)

    def get_sp_process_exclusions(self):
        """
        Get the processes excluded from Self Protection (Exclude these
        processes, Windows & Mac only).
        """
        return self.get_indexed_list('SelfProtectionStatus', 'spProcessExclCount',
                                     'spProcessExclusion_{}') or []

    def set_sp_process_exclusions(self, processes):
        """
        Set the processes excluded from Self Protection.
        """
        processes = [check_sp_exclusion(process) for process in processes]
        if len({process.strip() for process in processes}) != len(processes):
            raise ValueError('Self Protection process exclusions: duplicate item.')
        self.__section('SelfProtectionStatus')
        return self.set_indexed_list('SelfProtectionStatus', 'spProcessExclCount',
                                     'spProcessExclusion_{}', processes)

    sp_process_exclusions = property(get_sp_process_exclusions, set_sp_process_exclusions)

    # ------------------------------ Exclusions (AAC) ------------------------------
    def get_aac_exclusions(self):
        """
        Get the processes excluded from Trellix AAC protection (list of
        AACExclusion).
        """
        values = self.get_indexed_list('GlobalExclusions', 'dwExclCount',
                                       'GlobalExclusion_{}') or []
        return [AACExclusion.from_value(value) for value in values]

    def set_aac_exclusions(self, exclusions):
        """
        Set the processes excluded from Trellix AAC protection (list of
        AACExclusion).
        """
        for exclusion in exclusions:
            exclusion.check()
        self.__section('GlobalExclusions')
        return self.set_indexed_list('GlobalExclusions', 'dwExclCount', 'GlobalExclusion_{}',
                                     [exclusion.to_value() for exclusion in exclusions])

    aac_exclusions = property(get_aac_exclusions, set_aac_exclusions)

    def add_aac_exclusion(self, exclusion):
        """
        Add an AAC exclusion (AACExclusion) if not already in the list.
        """
        exclusion.check()
        exclusions = self.get_aac_exclusions()
        if exclusion in exclusions:
            return False
        return self.set_aac_exclusions(exclusions + [exclusion])

    def remove_aac_exclusion(self, process):
        """
        Remove the AAC exclusions of a process (full path).
        """
        exclusions = self.get_aac_exclusions()
        kept = [exclusion for exclusion in exclusions if exclusion.process != process]
        if len(kept) == len(exclusions):
            return False
        return self.set_aac_exclusions(kept)

    # ------------------------------ Client Logging ------------------------------
    def get_log_location(self):
        """
        Get the Log files location (e.g. '%DEFLOGDIR%' or
        '<SYSTEM_DRIVE>\\Logs').
        """
        return self.__get('ClientLoggingOptions', 'clientLogFilesLocation')

    def set_log_location(self, location):
        """
        Set the Log files location (256 characters max).
        """
        check_log_location(location)
        return self.__set('ClientLoggingOptions', 'clientLogFilesLocation', location)

    log_location = property(get_log_location, set_log_location)

    def get_log_utc(self):
        """
        Get the Timestamp for log files: '1' Coordinated Universal Time
        (UTC), '0' Local system time.
        """
        return self.__to_mode(self.__get('ClientLoggingOptions', 'enableclientLoggingUTC'))

    def set_log_utc(self, mode):
        """
        Set the Timestamp for log files: '1' UTC, '0' Local system time.
        """
        return self.__set('ClientLoggingOptions', 'enableclientLoggingUTC',
                          self.__from_mode(mode))

    log_utc = property(get_log_utc, set_log_utc)

    def get_activity_log_language(self):
        """
        Get the Activity logging language code (see LANGUAGES, '0000'
        Automatic when not set).
        """
        return self.__get('ClientLoggingOptions', 'clientActivityLoggingLanguage', '0000')

    def set_activity_log_language(self, code):
        """
        Set the Activity logging language code (see LANGUAGES).
        """
        if code not in self.LANGUAGES:
            raise ValueError('Language must be within {}.'.format(list(self.LANGUAGES)))
        return self.__set('ClientLoggingOptions', 'clientActivityLoggingLanguage', code)

    activity_log_language = property(get_activity_log_language, set_activity_log_language)

    def get_tp_debug_logging(self):
        """
        Get the Threat Prevention debug logging ('1' if enabled for one of
        Access Protection, Exploit Prevention, On-Access Scan, On-Demand Scan).
        """
        return '1' if any(self.__get('ClientLoggingOptions', setting) == 'true'
                          for setting in self.TP_DEBUG) else '0'

    def set_tp_debug_logging(self, mode, modules=None):
        """
        Enable or disable the Threat Prevention debug logging for all its
        modules, or for the given settings of TP_DEBUG.
        """
        for setting in modules or self.TP_DEBUG:
            if setting not in self.TP_DEBUG:
                raise ValueError('Unknown Threat Prevention module: {}'.format(setting))
            self.__set('ClientLoggingOptions', setting, self.__from_mode(mode))
        return True

    def get_event_level(self, module):
        """
        Get the events to log of a module (see EVENT_MODULES): '5' None ...
        '0' All (see EVENT_LEVELS).
        """
        return self.__get('ClientLoggingOptions', 'suppressAlertsBelow{}'.format(module))

    def set_event_level(self, module, level):
        """
        Set the events to log of a module (see EVENT_MODULES and EVENT_LEVELS).
        """
        if module not in self.EVENT_MODULES or str(level) not in self.EVENT_LEVELS:
            raise ValueError('Unknown module or level: {} {}'.format(module, level))
        return self.__set('ClientLoggingOptions', 'suppressAlertsBelow{}'.format(module), level)

    def get_edr_event_level(self, module):
        """
        Get the EDR events to log of a module (see EVENT_MODULES): '0' None,
        '1' Alerts only (default), '2' Alerts and events.
        """
        return self.__get('ClientLoggingOptions', 'EDREventLevel{}'.format(module), '1')

    def set_edr_event_level(self, module, level):
        """
        Set the EDR events to log of a module (see EVENT_MODULES and EDR_LEVELS).
        """
        if module not in self.EVENT_MODULES or str(level) not in self.EDR_LEVELS:
            raise ValueError('Unknown module or level: {} {}'.format(module, level))
        return self.__set('ClientLoggingOptions', 'EDREventLevel{}'.format(module), level)

    # ------------------------------ Proxy Server ------------------------------
    def get_proxy(self):
        """
        Get the Proxy Server: a dict with 'type' ('0' No proxy server, '1'
        Use system proxy settings, '2' Configure proxy server), 'address',
        'port', 'exclusions' (list), 'authentication' ('1'/'0') and 'user'.
        The proxy password is not in the export.
        """
        exclusions = self.__get('ClientGTIProxy', 'proxyServerExclusions', '')
        port = self.__get('ClientGTIProxy', 'gtiProxyServerPort')
        return {'type': self.__get('ClientGTIProxy', 'gtiProxyType'),
                'address': self.__get('ClientGTIProxy', 'gtiProxyServerAddress', ''),
                'port': int(port) if port else None,
                'exclusions': [item for item in exclusions.split(';') if item],
                'authentication': self.get_option('proxy_authentication'),
                'user': self.__get('ClientGTIProxy', 'httpAuthUserName', '')}

    def set_proxy(self, proxy_type, address=None, port=None, exclusions=None):
        """
        Set the Proxy Server (see get_proxy; None = keep the current value).
        HTTP proxy authentication needs a password, which can only be defined
        in the ePO console.
        """
        if str(proxy_type) not in self.PROXY_TYPES:
            raise ValueError('The proxy type must be "0", "1" or "2".')
        if address is not None:
            self.__set('ClientGTIProxy', 'gtiProxyServerAddress', check_proxy_address(address))
        if port is not None:
            self.__set('ClientGTIProxy', 'gtiProxyServerPort',
                       check_int('Proxy server port', port, 1, 65535))
        if exclusions is not None:
            self.__set('ClientGTIProxy', 'proxyServerExclusions', ';'.join(exclusions))
        if str(proxy_type) == '2' and not self.__get('ClientGTIProxy', 'gtiProxyServerAddress'):
            raise ValueError('Configure proxy server needs an HTTP address.')
        return self.__set('ClientGTIProxy', 'gtiProxyType', proxy_type)

    # ------------------------------ Default Client Update ------------------------------
    def get_update_level(self):
        """
        Get What to update: '0' Security content, hotfixes, and patches, '1'
        Security content, '2' Hotfixes and patches.
        """
        return self.__get('ClientUpdate', 'whatToUpdateLevel')

    def set_update_level(self, level):
        """
        Set What to update (see get_update_level).
        """
        if str(level) not in self.UPDATE_LEVELS:
            raise ValueError('What to update must be "0", "1" or "2".')
        return self.__set('ClientUpdate', 'whatToUpdateLevel', level)

    update_level = property(get_update_level, set_update_level)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        check = self.md_check
        opt = lambda name: [self.__CHECKBOXES[name][2], check(self.get_option(name))]
        num = lambda name: [self.__NUMBERS[name][2], self.get_option(name)]
        label = lambda table, value: table.get(value, value)
        on = lambda name: self.get_option(name) == '1'
        sections = []
        level = self.get_access_level()
        rows = [['Client Interface Mode', label(self.ACCESS_LEVELS, level)]]
        if level != self.FULL_ACCESS:
            rows += [['Administrator password', 'Defined in the ePO console (not exported)'],
                     opt('interface_lockout')]
            if on('interface_lockout'):
                rows += [num('password_attempts'), num('lockout_time_frame'),
                         num('lockout_minutes')]
        sections.append(('Client Interface Mode', self.md_settings(rows)))
        rows = [[self.__CHECKBOXES['uninstall_password'][2], check(self.get_option(
            'uninstall_password'))]]
        if on('uninstall_password'):
            rows.append(['Password', 'Defined in the ePO console (not exported)'])
        sections.append(('Uninstallation', self.md_settings(rows)))
        rows = [[self.__CHECKBOXES['time_based_password'][2],
                 check(self.get_option('time_based_password'))]]
        if on('time_based_password'):
            rows.append(['Time', 'Defined in the ePO console (not exported)'])
        sections.append(('Time-Based Administrator Password (Windows only)',
                         self.md_settings(rows)))
        sections.append(('Client Interface Language (Windows only)', self.md_settings(
            [['Client interface language', label(self.LANGUAGES, self.get_interface_language())]])))
        rows = [opt('self_protection')]
        for resource, name in [('files', 'sp_files'), ('registry', 'sp_registry'),
                               ('processes', 'sp_processes')]:
            enabled = self.get_option(name)
            rows.append([self.__CHECKBOXES[name][2], label(self.SP_ACTIONS, self.get_sp_action(
                resource)) if enabled == '1' else check(enabled)])
        text = 'Select Endpoint Security resources to protect and specify the action to take ' \
               'when malicious activity occurs.\n\n' + self.md_settings(rows)
        text += '\nExclude these processes (Windows & Mac only):\n\n' + self.md_table(
            ['Process'], [[process] for process in self.get_sp_process_exclusions()],
            numbered=True)
        sections.append(('Self Protection', text))
        sections.append(('Exclusions (Windows only)',
                         'Specify processes to exclude from Trellix AAC protection.\n\n' +
                         self.md_table(['Process', 'Process MD5 Hash',
                                        'Signer Certificate MD5 Hash', 'Notes'],
                                       [[e.process, e.md5, e.signer_md5, e.notes]
                                        for e in self.get_aac_exclusions()], numbered=True)))
        rows = [['Log files location (Windows & Linux only)', self.get_log_location()],
                ['Timestamp for log files', 'Coordinated Universal Time (UTC)'
                 if self.get_log_utc() == '1' else 'Local system time']]
        text = self.md_settings(rows)
        rows = [[self.__CHECKBOXES['activity_logging'][2], check(self.get_option(
            'activity_logging'))]]
        if on('activity_logging'):
            rows += [[self.__CHECKBOXES['ods_activity_logging'][2],
                      check(self.get_option('ods_activity_logging'))],
                     [self.__CHECKBOXES['activity_log_size_limit'][2],
                      self.get_option('activity_log_size') if on('activity_log_size_limit')
                      else 'No'],
                     ['Activity logging language', label(self.LANGUAGES,
                                                         self.get_activity_log_language())]]
        text += '\n### Activity Logging (Windows & Linux only)\n\n' + self.md_settings(rows)
        rows = [['Enable for Threat Prevention', check(self.get_tp_debug_logging())]]
        rows += [[module_label, check(self.__to_mode(self.__get('ClientLoggingOptions',
                                                                setting, 'false')))]
                 for setting, module_label in self.TP_DEBUG.items()]
        rows += [[self.__CHECKBOXES[name][2], check(self.get_option(name))]
                 for name in ['debug_fw', 'debug_wc', 'debug_atp', 'debug_sp']]
        rows.append([self.__CHECKBOXES['debug_log_size_limit'][2],
                     self.get_option('debug_log_size') if on('debug_log_size_limit') else 'No'])
        text += '\n### Debug Logging\n\nEnabling debug logging for any module will also ' \
                'enable debug logging for Self Protection.\n\n' + self.md_settings(rows)
        rows = [[self.__CHECKBOXES[name][2], check(self.get_option(name))]
                for name in ['send_events_to_epo', 'windows_event_log']]
        rows.append([self.__CHECKBOXES['event_db_size_limit'][2],
                     self.get_option('event_db_size') if on('event_db_size_limit') else 'No'])
        text += '\n### Event Logging (Windows & Linux only)\n\n' + self.md_settings(rows)
        text += '\n' + self.md_table(['Events to log', 'Event Logging', 'EDR Events'], [
            [module_label, label(self.EVENT_LEVELS, self.get_event_level(module)),
             label(self.EDR_LEVELS, self.get_edr_event_level(module))]
            for module, module_label in self.EVENT_MODULES.items()])
        sections.append(('Client Logging', text))
        proxy = self.get_proxy()
        rows = [['Proxy server', label(self.PROXY_TYPES, proxy['type'])]]
        if proxy['type'] == '2':
            rows += [['HTTP address', proxy['address']], ['Port', proxy['port']],
                     ['Exclusions', ', '.join(proxy['exclusions'])]]
        if proxy['type'] in ('1', '2'):
            rows.append([self.__CHECKBOXES['proxy_authentication'][2],
                         check(proxy['authentication'])])
            if proxy['authentication'] == '1':
                rows.append(['User name', proxy['user']])
        sections.append(('Proxy Server', self.md_settings(rows)))
        sections.append(('Network Configuration', self.md_settings([opt('ipv6')])))
        rows = [[self.__CHECKBOXES[name][2], check(self.get_option(name))]
                for name in ['update_now_button', 'default_update_task']]
        rows.append(['What to update (Windows only)', label(self.UPDATE_LEVELS,
                                                            self.get_update_level())])
        sections.append(('Default Client Update', self.md_settings(rows)))
        sections.append(('Managed Tasks (Windows & Linux only)', self.md_settings(
            [[self.__CHECKBOXES['managed_tasks'][2], check(self.get_option('managed_tasks'))]])))
        return sections
