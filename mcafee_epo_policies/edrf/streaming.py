# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class EDRFPolicyStreaming (Trellix EDR with
Forensics: Streaming - Trace, Event streamer, Alerts, Process Tracker,
Logon Tracker) and the Event streamer table rows EDRFEventLog,
EDRFFileEvent, EDRFEventFilter, EDRFFilterCondition and EDRFSyslogServer.

Storage learnt from test policies changed in the ePO 5.10 console
(extensions XCLIENT_META 2.1.2.270 and 50.3.0.900):

- The ePO server escapes the double quotes of the settings (\\") except, since
  the extension 50.3, those of the exclusion lists. The Streaming page shows
  the stored values as they are: a " typed in a text field (Helix, S3) comes
  back as \\" and gets one more backslash at each save, so the library
  refuses " in the text settings.
- The eight Trace exclusion lists (Windows, Linux and Mac process
  exclusions and disabled trace rules, Linux file and folder exclusions)
  are stored with doubled backslashes; the console keeps the line breaks
  typed in them (the library writes semicolons, the documented separator).
- The Logon Tracker exclusion lists are stored as typed (line breaks
  replaced by semicolons).
- Since the extension 50.3 the thirteen lists are split in 3072 character
  parts by the ePO server (see EDRFPolicy); the console text areas accept
  200000 characters.
- The S3 bucket Access Key ID and Secret Access Key are encrypted by the ePO
  server: the library never defines them, and "Send traces to S3 bucket"
  can only be enabled when the keys were entered in the console. The other
  S3 settings can only be changed while "Send traces to S3 bucket" is
  checked: unchecking it clears them, as the console does (keys, region,
  bucket and endpoint emptied, interval reset to 30 seconds).
- Event streamer (extension 50.3): Windows event logs, Windows file events,
  event filters and syslog servers are JSON lists (mxa/EventStreamer/
  eventlogs, files, filters, syslog), written by the console with
  JSON.stringify and their quotes escaped by the server. The console only
  shows a list whose JSON is shorter than 2820 characters: a longer one is
  cut after its last complete row when the policy is opened (the next save
  loses the other rows) and a list longer than 3072 characters once stored
  is truncated by the server and stops the console from opening the policy
  (both checked on the lab). The library refuses them.
- Unchecking "Send event data to Trellix Helix" clears the Helix settings,
  as the console does.
- The console saves mxa/EventStreamer/dxl/compression as
  mxa/EventStreamer/dxl/compressioned (a bug of the extension 50.3, no
  field of the page); the library leaves both untouched.
"""

import json
import re
import urllib.parse

from ..validators import is_ip_or_hostname
from .policy import EDRFPolicy, CHECK, NUMBER, SELECT, TEXT, LIST

T = 'UEDR/TraceScanner/'
ES = 'mxa/EventStreamer/'
MAX_TABLE_LENGTH = 2820            # JSON length the console shows without cutting it
MAX_FIELD_LENGTH = 256             # maxlength of the Event streamer dialog fields


def _check_text(label, value, max_length=MAX_FIELD_LENGTH, required=True):
    """
    Check a field of an Event streamer dialog.
    """
    if not isinstance(value, str):
        raise ValueError('{}: a text is expected: {!r}'.format(label, value))
    if required and not value.strip():
        raise ValueError('{} is required.'.format(label))
    if len(value) > max_length:
        raise ValueError('{}: {} characters max.'.format(label, max_length))
    EDRFPolicy.check_bmp(value)


class EDRFEventLog():
    """
    A Windows event log streamed by the Event streamer (Windows Events Logs).

    :param: display_name: Event Name (unique).
    :param: name: Source name, e.g. 'Microsoft-Windows-Sysmon/Operational'.
    :param: ids: Event IDs, e.g. '1, 3, 11'.
    :param: enabled: Enabled.
    """

    def __init__(self, display_name, name, ids='', enabled=True):
        self.display_name = display_name
        self.name = name
        self.ids = ids
        self.enabled = enabled

    def __repr__(self):
        return 'EDRFEventLog({!r}, {!r}, {!r}, enabled={!r})'.format(
            self.display_name, self.name, self.ids, self.enabled)

    def __eq__(self, other):
        return isinstance(other, EDRFEventLog) and self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, item):
        return cls(item.get('displayName', ''), item.get('name', ''), item.get('ids', ''),
                   item.get('enabled', True))

    def to_dict(self):
        return {'enabled': bool(self.enabled), 'displayName': self.display_name.strip(),
                'name': self.name, 'ids': self.ids}

    def key(self):
        return self.display_name.strip()

    def check(self):
        """
        Raise ValueError if the console would refuse the event log.
        """
        _check_text('Event Name', self.display_name)
        _check_text('Source name', self.name, required=False)
        _check_text('Event IDs', self.ids, 3072, required=False)


class EDRFFileEvent():
    """
    A log file streamed by the Event streamer (Windows File Event).

    :param: name: Display Name (unique).
    :param: type: File Type, see TYPES.
    :param: path: File path, e.g. 'C:\\Windows\\System32\\dhcp\\*.log'.
    :param: enabled: Enabled.
    """
    TYPES = {'MSFT_DHCP': 'DHCP', 'MSFT_DNS': 'DNS', 'EXCHANGE': 'Exchange', 'IIS': 'IIS',
             'NETLOGON': 'Net Logon'}

    def __init__(self, name, type, path, enabled=True):
        self.name = name
        self.type = type
        self.path = path
        self.enabled = enabled

    def __repr__(self):
        return 'EDRFFileEvent({!r}, {!r}, {!r}, enabled={!r})'.format(
            self.name, self.type, self.path, self.enabled)

    def __eq__(self, other):
        return isinstance(other, EDRFFileEvent) and self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, item):
        return cls(item.get('name', ''), item.get('type', ''), item.get('path', ''),
                   item.get('enabled', True))

    def to_dict(self):
        return {'enabled': bool(self.enabled), 'name': self.name.strip(), 'type': self.type,
                'path': self.path}

    def key(self):
        return self.name.strip()

    def check(self):
        """
        Raise ValueError if the console would refuse the file event.
        """
        _check_text('Display Name', self.name)
        if self.type not in self.TYPES:
            raise ValueError('File Type must be within {}.'.format(list(self.TYPES)))
        _check_text('File path', self.path, required=False)


class EDRFFilterCondition():
    """
    A condition of an event filter.

    :param: field: Field name, e.g. 'EventID'.
    :param: value: Value (a regular expression when type is 'regex').
    :param: action: 'include' or 'exclude'.
    :param: type: 'match' or 'regex' (the console default).
    """
    ACTIONS = {'include': 'Include', 'exclude': 'Exclude'}
    TYPES = {'match': 'Match', 'regex': 'Regex'}

    def __init__(self, field, value, action='include', type='regex'):
        self.field = field
        self.value = value
        self.action = action
        self.type = type

    def __repr__(self):
        return 'EDRFFilterCondition({!r}, {!r}, {!r}, {!r})'.format(
            self.field, self.value, self.action, self.type)

    def __eq__(self, other):
        return isinstance(other, EDRFFilterCondition) and self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, item):
        return cls(item.get('name', ''), item.get('value', ''), item.get('includeExclude', ''),
                   item.get('type', ''))

    def to_dict(self):
        return {'name': self.field, 'value': self.value, 'includeExclude': self.action,
                'type': self.type}

    def check(self):
        """
        Raise ValueError if the console would refuse the condition.
        """
        _check_text('Field name', self.field)
        _check_text('Value', self.value)
        if self.action not in self.ACTIONS:
            raise ValueError('The condition action must be within {}.'.format(list(self.ACTIONS)))
        if self.type not in self.TYPES:
            raise ValueError('The condition type must be within {}.'.format(list(self.TYPES)))


class EDRFEventFilter():
    """
    An event filter of the Event streamer (Filters): the events of a source
    are dropped or allowed by default, the conditions select the others.

    :param: name: Name (unique).
    :param: source: Source, see SOURCES.
    :param: conditions: List of EDRFFilterCondition (one at least).
    :param: os: 'windows', or 'macos' / 'linux' for the OS Events source.
    :param: default_action: 'drop' or 'allow'.
    :param: enabled: Enabled.
    """
    SOURCES = {'ms_dhcp_es': 'DHCP', 'ms_dns_es': 'DNS', 'ms_windows_event': 'Event Log',
               'ms_exchange_es': 'Exchange', 'ms_iis_es': 'IIS', 'ms_netlogon_es': 'Net Logon',
               'xagt_realtime_evt': 'OS Events'}
    OS = {'windows': 'Windows', 'macos': 'MacOS', 'linux': 'Linux'}
    DEFAULT_ACTIONS = {'drop': 'Drop', 'allow': 'Allow'}

    def __init__(self, name, source, conditions, os='windows', default_action='drop',
                 enabled=True):
        self.name = name
        self.source = source
        self.conditions = list(conditions)
        self.os = os
        self.default_action = default_action
        self.enabled = enabled

    def __repr__(self):
        return 'EDRFEventFilter({!r}, {!r}, {!r}, os={!r}, default_action={!r}, ' \
               'enabled={!r})'.format(self.name, self.source, self.conditions, self.os,
                                      self.default_action, self.enabled)

    def __eq__(self, other):
        return isinstance(other, EDRFEventFilter) and self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, item):
        return cls(item.get('name', ''), item.get('type', ''),
                   [EDRFFilterCondition.from_dict(condition)
                    for condition in item.get('conditions', [])],
                   item.get('os', ''), item.get('defaultaction', ''), item.get('enabled', True))

    def to_dict(self):
        return {'enabled': bool(self.enabled), 'name': self.name.strip(), 'type': self.source,
                'os': self.os, 'defaultaction': self.default_action,
                'conditions': [condition.to_dict() for condition in self.conditions]}

    def key(self):
        return self.name.strip()

    def check(self):
        """
        Raise ValueError if the console would refuse the filter.
        """
        _check_text('Name', self.name)
        if self.source not in self.SOURCES:
            raise ValueError('Source must be within {}.'.format(list(self.SOURCES)))
        if self.os != 'windows' and not (self.source == 'xagt_realtime_evt' and self.os in self.OS):
            raise ValueError('OS must be "windows" ("macos" and "linux" are only available for '
                             'the OS Events source).')
        if self.default_action not in self.DEFAULT_ACTIONS:
            raise ValueError('Default behavior must be within {}.'.format(
                list(self.DEFAULT_ACTIONS)))
        if not self.conditions:
            raise ValueError('A filter needs one condition at least.')
        for condition in self.conditions:
            condition.check()


class EDRFSyslogServer():
    """
    A syslog server receiving the Event streamer data (Server Log).

    :param: name: Name (unique).
    :param: ip: Server (IP address or DNS host name).
    :param: port: TCP Port (1-65535).
    :param: priority: 'P1' to 'P4'.
    :param: tls: Enable SSL.
    :param: enabled: Enabled.
    """
    PRIORITIES = ['P1', 'P2', 'P3', 'P4']

    def __init__(self, name, ip, port, priority='P1', tls=False, enabled=True):
        self.name = name
        self.ip = ip
        self.port = port
        self.priority = priority
        self.tls = tls
        self.enabled = enabled

    def __repr__(self):
        return 'EDRFSyslogServer({!r}, {!r}, {!r}, priority={!r}, tls={!r}, enabled={!r})'.format(
            self.name, self.ip, self.port, self.priority, self.tls, self.enabled)

    def __eq__(self, other):
        return isinstance(other, EDRFSyslogServer) and self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, item):
        return cls(item.get('name', ''), item.get('ip', ''), item.get('port', ''),
                   item.get('priority', ''), item.get('tls', False), item.get('enabled', True))

    def to_dict(self):
        return {'enabled': bool(self.enabled), 'name': self.name.strip(),
                'priority': self.priority, 'ip': self.ip, 'port': str(self.port),
                'tls': bool(self.tls)}

    def key(self):
        return self.name.strip()

    def check(self):
        """
        Raise ValueError if the console would refuse the server.
        """
        _check_text('Name', self.name)
        if self.priority not in self.PRIORITIES:
            raise ValueError('Priority must be within {}.'.format(self.PRIORITIES))
        _check_text('Server', self.ip)
        if not is_ip_or_hostname(self.ip):
            raise ValueError('Please enter a valid IP Address or DNS Hostname: {!r}'.format(
                self.ip))
        if not re.fullmatch(r'\d{1,5}', str(self.port)) or not 1 <= int(self.port) <= 65535:
            raise ValueError('TCP Port: enter a number between 1 and 65535.')


class EDRFPolicyStreaming(EDRFPolicy):
    """
    The EDRFPolicyStreaming class can be used to edit the Trellix EDR with
    Forensics policy: Streaming.
    """
    MD_CATEGORY = 'Streaming'
    TYPE = 'Streaming'
    LOG_LEVELS = {'1': 'Debug', '2': 'Trace', '3': 'Info', '4': 'Warning', '5': 'Error'}

    OPTIONS = {
        # Trace - Trace Scanning
        'trace': (T + 'enabled', 'Enable Trace', CHECK),
        'log_level': (T + 'log_level', 'Log level', SELECT, LOG_LEVELS),
        'report_connectivity': (T + 'report_connectivity_status',
                                'Report internal reputation failures to Trellix ePO', CHECK),
        'deep_inspection': (T + 'injectcore_enabled',
                            'Enable deep inspection of Windows API calls', CHECK),
        'etw_ti_inspection': (T + 'etw_ti_enabled',
                              'Enable ETW-TI inspection of Windows API calls', CHECK),
        'trace_storage': (T + 'max_db_size_mb', 'Maximum size (MB) of the device storage that '
                          'can be used by the Traces', NUMBER, 0, 8192),
        # The console checks 10-1800 (its error message says 30-1800).
        'cloud_interval': (T + 'bulk_time', 'Interval to send trace events to DXL Broker '
                           '(seconds)', NUMBER, 10, 1800),
        # Trace - Destination for Trace data
        'send_to_cloud': (T + 'send_traces_to_edr_cloud', 'Send trace events to DXL Broker',
                          CHECK),
        'send_to_s3': (T + 'send_traces_to_s3_bucket', 'Send traces to S3 bucket (Windows only)',
                       CHECK),
        's3_region': (T + 's3_default_region_name', 'S3 default Region Name', TEXT, 45),
        's3_bucket': (T + 's3_bucket_name', 'S3 bucket Name', TEXT, 63),
        's3_interval': (T + 's3_push_frequency_seconds',
                        'Interval (in seconds) to send trace events to S3 bucket', NUMBER, 10, 1800),
        's3_use_endpoint': (T + 's3_use_endpoint', 'Specify (optional) S3 endpoint', CHECK),
        's3_endpoint': (T + 's3_endpoint', 'S3 endpoint', TEXT, 255),
        # Trace - Exclusion
        'windows_process_exclusions': (T + 'ignored_process',
                                       'Exclude process(es) by full path (Windows)', LIST, True),
        'windows_disabled_rules': (T + 'disabled_rules', 'Disabled trace rules (Windows)', LIST,
                                   False),
        'linux_process_exclusions': (T + 'ignored_process_linux',
                                     'Exclude process(es) by full path (Linux)', LIST, False),
        'linux_disabled_rules': (T + 'disabled_rules_linux', 'Disabled trace rules (Linux)', LIST,
                                 False),
        'linux_file_exclusions': (T + 'ignored_exact_files_linux', 'Exclude file(s) (Linux)', LIST,
                                  False),
        'linux_folder_exclusions': (T + 'ignored_exact_folders_linux',
                                    'Exclude folder(s) (Linux)', LIST, False),
        'mac_process_exclusions': (T + 'ignored_process_mac',
                                   'Exclude process(es) by full path (Mac)', LIST, False),
        'mac_disabled_rules': (T + 'disabled_rules_mac', 'Disabled trace rules (Mac)', LIST, False),
        # Event streamer (extension 50.3) - OS Events (Real-time Indicator Detection required)
        'event_streamer': ('mxa/container/EventStreamer/enabled', 'Event streamer', CHECK),
        'os_process_events': (ES + 'osevents/processEvent', 'Process Event', CHECK),
        'os_network_events': (ES + 'osevents/ipv4NetworkEvent', 'IPv4 or IPv6 network events',
                              CHECK),
        'os_address_events': (ES + 'osevents/addressNotificationEvent',
                              'Network address notification events', CHECK),
        'os_dns_events': (ES + 'osevents/dnsLookupEvent', 'Network DNS events', CHECK),
        'os_file_write_events': (ES + 'osevents/fileWriteEvent', 'File write events', CHECK),
        'os_image_load_events': (ES + 'osevents/imageLoadEvent', 'Image load events', CHECK),
        'os_url_events': (ES + 'osevents/urlMonitorEvent', 'URLs visited', CHECK),
        'os_registry_events': (ES + 'osevents/regKeyEvent', 'Registry events', CHECK),
        # Event streamer - Module Settings
        'delete_batch_size': (ES + 'deleteBatchCount', 'Delete batch size', NUMBER, 1, 500),
        'send_interval': (ES + 'sendEventsTimeout', 'Data Transmission frequency (Seconds)',
                          NUMBER, 2, 60),
        'batch_max_events': (ES + 'numConsecutiveBatches',
                             'Maximum number of events sent in a batch', NUMBER, 2, 500),
        'vacuum_frequency': (ES + 'vacuumOnDeleteCount', 'Database vacuum frequency', NUMBER,
                             500, 10000),
        'max_events_in_db': (ES + 'maxEventsInDB', 'Maximum number of events stored in database',
                             NUMBER, 5000, 25000),
        'events_in_memory': (ES + 'inmemorydb', 'Store events in memory only', CHECK),
        'send_on_events': (ES + 'sendOnEvents', 'Send on number of events in memory AND on time',
                           CHECK),
        'send_on_num_events': (ES + 'sendOnNumEvents', 'Number of events to send on', NUMBER,
                               5, 500),
        # Event streamer - Destination for Event data
        'events_to_dxl': (ES + 'dxl/enabled', 'Send event data to DXL Broker', CHECK),
        'events_to_helix': (ES + 'send2Helix', 'Send event data to Trellix Helix', CHECK),
        'helix_id': (ES + 'helixId', 'Helix ID', TEXT, 128),
        'helix_server': (ES + 'helixURL', 'Helix server', TEXT, 128),
        'helix_path': (ES + 'helixPath', 'Helix event path', TEXT, 128),
        'events_to_syslog': (ES + 'syslog/enable', 'Send event data to Syslog Server', CHECK),
        # Alerts
        'ioc_alerts': ('mxa/eventor/ioc_alerts_to_edr_epp_enabled',
                       'Alerts streamed to DXL Broker: IOC', CHECK),
        # Process Tracker
        'process_tracker': ('mxa/container/ProcessTracker/enabled',
                            'Enable Process Tracker on the host', CHECK),
        # Logon Tracker
        'logon_tracker': ('mxa/container/LogonTracker/enabled', 'Enable Logon Tracker for hosts',
                          CHECK),
        'logon_backfill': ('mxa/LogonTracker/backfill_events', 'Backfill events', CHECK),
        'logon_timeout': ('mxa/LogonTracker/logon_timeout_minutes', 'Logon timeout (minutes)',
                          NUMBER, 0, 525600),
        'logon_disable_enrichment': ('mxa/LogonTracker/disable_enrichment',
                                     'Disable event enrichment', CHECK),
        'logon_max_events': ('mxa/LogonTracker/max_memory_cache_size',
                             'Maximum number of events', NUMBER, 0, 9999999),
        'logon_ignore_addresses': ('mxa/LogonTracker/ignore_addr', 'Addresses', LIST, False),
        'logon_ignore_hosts': ('mxa/LogonTracker/ignore_hosts', 'Hosts', LIST, False),
        'logon_ignore_accounts': ('mxa/LogonTracker/ignore_accounts', 'Accounts', LIST, False),
        'logon_ignore_categories': ('mxa/LogonTracker/ignore_categories', 'Categories', LIST,
                                    False),
        'logon_ignore_status': ('mxa/LogonTracker/ignore_status', 'Status', LIST, False),
        'logon_filter_tunneled': ('mxa/LogonTracker/filter_tunneled', 'Filter Tunneled Logons',
                                  CHECK),
    }
    # Event streamer tables: name -> (setting, console label, row class).
    TABLES = {
        'event_logs': (ES + 'eventlogs', 'Windows Events Logs', EDRFEventLog),
        'file_events': (ES + 'files', 'Windows File Event', EDRFFileEvent),
        'event_filters': (ES + 'filters', 'Filters', EDRFEventFilter),
        'syslog_servers': (ES + 'syslog', 'Server Log', EDRFSyslogServer),
    }
    DEFAULT_EVENT_LOGS = [EDRFEventLog(name, source, ids) for name, source, ids in [
        ('Security', 'Security',
         '1102, 4610, 4611, 4614, 4622, 4624, 4652, 4657, 4663, 4688, 4689, 4697, 4698, 4699, '
         '4702, 4704, 4719, 4720, 4728, 4732, 4756, 4768, 4769, 4771, 4776, 4946, 4947, 4948, '
         '4950, 4951, 4952, 4953, 4954, 4957, 4958, 5025, 5027, 5028, 5029, 5030, 5031, 5034, '
         '5035, 5037, 5038, 5050, 5145, 5152, 6281'),
        ('System', 'System',
         '6, 20, 24, 25, 31, 34, 35, 41, 100, 104, 219, 1125, 1127, 1129, 7022, 7023, 7024, '
         '7026, 7031, 7032, 7034, 7036, 7040, 7045'),
        ('TerminalServicesLocalSessionManager',
         'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', '21, 22, 23, 24, 25'),
        ('TerminalServicesRemoteConnectionManager',
         'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', '1149'),
        ('TaskScheduler', 'Microsoft-Windows-TaskScheduler/Operational', '106, 200, 203'),
        ('PowerShell', 'Microsoft-Windows-PowerShell/Operational', '4103, 4104'),
        ('Windows Defender', 'Microsoft-Windows-Windows Defender/Operational',
         '1005, 1006, 1010, 2001, 2003, 2004, 3002, 5008'),
        ('Application Experience', 'Microsoft-Windows-Application-Experience/Program-Inventory',
         '903, 904'),
        ('Application', 'Application', '1, 2, 1001, 1033, 4097, 8194, 11707'),
        ('AppLocker EXE and DLL', 'Microsoft-Windows-AppLocker/EXE and DLL', '8003, 8004'),
        ('AppLocker MSI and Script', 'Microsoft-Windows-AppLocker/MSI and Script', '8005, 8006'),
        ('PrintService', 'Microsoft-Windows-PrintService/Operational', '307')]]
    # Console defaults of the settings added by recent extension versions.
    DEFAULTS = {
        T + 'etw_ti_enabled': 'true', T + 's3_use_endpoint': 'false', T + 's3_endpoint': '',
        T + 's3_default_region_name': '', T + 's3_bucket_name': '',
        'mxa/container/ProcessTracker/enabled': 'false',
        'mxa/container/LogonTracker/enabled': 'false',
        'mxa/LogonTracker/backfill_events': 'false', 'mxa/LogonTracker/logon_timeout_minutes': '1440',
        'mxa/LogonTracker/disable_enrichment': 'false',
        'mxa/LogonTracker/max_memory_cache_size': '5000000',
        'mxa/LogonTracker/ignore_addr': '<IPV4ADDR>;127.0.0.1;::1;<IPV6ADDR>;',
        'mxa/LogonTracker/ignore_hosts': 'localhost;<HOSTNAME>;',
        'mxa/LogonTracker/ignore_accounts': '<HOSTNAME>$;<SYSTEM ACCOUNTS>;<COMPUTER>;"";',
        'mxa/LogonTracker/ignore_categories': 'local;', 'mxa/LogonTracker/ignore_status': '',
        'mxa/LogonTracker/filter_tunneled': 'false',
        # Event streamer (extension 50.3)
        'mxa/container/EventStreamer/enabled': 'false',
        ES + 'deleteBatchCount': '100', ES + 'sendEventsTimeout': '20',
        ES + 'numConsecutiveBatches': '250', ES + 'vacuumOnDeleteCount': '1000',
        ES + 'maxEventsInDB': '10000', ES + 'inmemorydb': 'true', ES + 'sendOnEvents': 'true',
        ES + 'sendOnNumEvents': '100', ES + 'dxl/enabled': 'false', ES + 'send2Helix': 'false',
        ES + 'helixId': '', ES + 'helixURL': '', ES + 'helixPath': '',
        ES + 'syslog/enable': 'false', ES + 'syslog': '', ES + 'filters': '', ES + 'files': '',
        ES + 'eventlogs': json.dumps([log.to_dict() for log in DEFAULT_EVENT_LOGS],
                                     separators=(',', ':')),
    }
    DEFAULTS.update({spec[0]: 'false' for spec in OPTIONS.values()
                     if spec[0].startswith(ES + 'osevents/')})
    ESCAPE_QUOTES = True
    DOUBLE_BACKSLASHES = tuple(T + name for name in [
        'ignored_process', 'disabled_rules', 'ignored_process_linux', 'disabled_rules_linux',
        'ignored_exact_files_linux', 'ignored_exact_folders_linux', 'ignored_process_mac',
        'disabled_rules_mac'])
    CHUNKED = DOUBLE_BACKSLASHES + tuple('mxa/LogonTracker/' + name for name in [
        'ignore_status', 'ignore_hosts', 'ignore_categories', 'ignore_addr', 'ignore_accounts'])
    SECRETS = {'send_to_s3': T + 's3_bucket_aws_access_key_id'}
    S3_OPTIONS = ['s3_region', 's3_bucket', 's3_interval', 's3_use_endpoint', 's3_endpoint']
    HELIX_OPTIONS = ['helix_id', 'helix_server', 'helix_path']

    def set_option(self, name, value):
        """
        Set an option, checked as in the console (see EDRFPolicy.set_option):
        S3 bucket names and endpoints are checked too, " is refused in the
        text settings.
        """
        if self.OPTIONS[name][2] == TEXT and '"' in str(value):
            raise ValueError('{}: " is not supported (the console shows it as \\" and adds a '
                             'backslash at each save).'.format(self.OPTIONS[name][1]))
        if name == 's3_bucket' and value:
            if not re.fullmatch(r'(?!xn--)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', value) or \
                    value.endswith(('-s3alias', '--ol-s3')) or '..' in value or \
                    re.fullmatch(r'\d+\.\d+\.\d+\.\d+', value):
                raise ValueError('Invalid S3 bucket name (3-63 lowercase letters, numbers, dots '
                                 'and hyphens): {!r}'.format(value))
        if name == 's3_endpoint' and value:
            url = urllib.parse.urlparse(value)
            if re.search(r'[?*#\[\] \n\t\r<>,"{}^`~]', value) or not (url.scheme and url.netloc):
                raise ValueError('Invalid URL entered: {!r}'.format(value))
        if name in self.S3_OPTIONS and self.get_option('send_to_s3') != '1':
            raise ValueError('{}: enable "Send traces to S3 bucket" first (in the ePO console, '
                             'which defines the bucket keys).'.format(self.OPTIONS[name][1]))
        if name in self.HELIX_OPTIONS and self.get_option('events_to_helix') != '1':
            raise ValueError('{}: enable "Send event data to Trellix Helix" first.'.format(
                self.OPTIONS[name][1]))
        before = self.get_option(name)
        result = super(EDRFPolicyStreaming, self).set_option(name, value)
        if name == 'send_to_s3' and before == '1' and self.get_option('send_to_s3') == '0':
            # The console clears the S3 settings when the option is unchecked.
            for setting in ['s3_bucket_aws_access_key_id', 's3_bucket_aws_secret_access_key',
                            's3_default_region_name', 's3_bucket_name', 's3_endpoint']:
                self._set(T + setting, '')
            self._set(T + 's3_use_endpoint', 'false')
            self._set(T + 's3_push_frequency_seconds', '30')
        if name == 'events_to_helix' and before == '1' and self.get_option(name) == '0':
            # The console clears the Helix settings when the option is unchecked.
            for option in self.HELIX_OPTIONS:
                self._set(self.OPTIONS[option][0], '')
        return result

    # ------------------------------ Event streamer tables ------------------------------
    def get_table(self, name):
        """
        Get an Event streamer table as a list of rows: 'event_logs'
        (EDRFEventLog), 'file_events' (EDRFFileEvent), 'event_filters'
        (EDRFEventFilter) or 'syslog_servers' (EDRFSyslogServer).
        """
        setting, _, row_class = self.TABLES[name]
        value = self._get(setting)
        if not value:
            return []
        return [row_class.from_dict(item) for item in json.loads(value)]

    def set_table(self, name, rows):
        """
        Set an Event streamer table (see get_table), checked as in the
        console: valid rows, unique names, JSON shorter than 2820 characters
        (the console cuts a longer list).
        """
        setting, label, row_class = self.TABLES[name]
        keys = set()
        for row in rows:
            if not isinstance(row, row_class):
                raise ValueError('{}: {} rows are expected.'.format(label, row_class.__name__))
            row.check()
            if row.key() in keys:
                raise ValueError('{}: duplicate name {!r}.'.format(label, row.key()))
            keys.add(row.key())
        value = json.dumps([row.to_dict() for row in rows], separators=(',', ':'),
                           ensure_ascii=False)
        if len(value) >= MAX_TABLE_LENGTH:
            raise ValueError('{}: the list is too long ({} characters, the console only shows '
                             '{} characters and loses the other rows).'.format(
                                 label, len(value), MAX_TABLE_LENGTH - 1))
        return self._set(setting, value)

    def add_to_table(self, name, row):
        """
        Add a row to an Event streamer table (Add button of the console).
        """
        return self.set_table(name, self.get_table(name) + [row])

    def remove_from_table(self, name, key):
        """
        Remove a row from an Event streamer table by its name (Event Name
        for the event logs).
        """
        rows = self.get_table(name)
        kept = [row for row in rows if row.key() != key]
        if len(kept) == len(rows):
            raise ValueError('{}: no row {!r}.'.format(self.TABLES[name][1], key))
        return self.set_table(name, kept)

    # ------------------------------ Markdown export ------------------------------
    def md_event_streamer(self):
        """
        Returns the Event streamer group box as Markdown.
        """
        rows = self.md_rows(['event_streamer'])
        if self.get_option('event_streamer') != '1':
            return self.md_settings(rows)
        text = self.md_settings(rows)
        text += '\n### Windows Events Logs\n\n' + self.md_table(
            ['Enabled', 'Event Name', 'Source name', 'Event IDs'],
            [[self.md_check('1' if row.enabled else '0'), row.display_name, row.name, row.ids]
             for row in self.get_table('event_logs')])
        text += '\n### Windows File Event\n\n' + self.md_table(
            ['Enabled', 'Display Name', 'File Type', 'File path'],
            [[self.md_check('1' if row.enabled else '0'), row.name,
              EDRFFileEvent.TYPES.get(row.type, row.type), row.path]
             for row in self.get_table('file_events')])
        text += '\n### OS Events\n\n' + self.md_settings(self.md_rows(
            ['os_process_events', 'os_network_events', 'os_address_events', 'os_dns_events',
             'os_file_write_events', 'os_image_load_events', 'os_url_events',
             'os_registry_events']))
        rows = []
        for row in self.get_table('event_filters'):
            conditions = '; '.join('{} {} {} {}'.format(
                EDRFFilterCondition.ACTIONS.get(condition.action, condition.action),
                condition.field, EDRFFilterCondition.TYPES.get(condition.type, condition.type),
                condition.value) for condition in row.conditions)
            rows.append([self.md_check('1' if row.enabled else '0'), row.name,
                         EDRFEventFilter.SOURCES.get(row.source, row.source),
                         EDRFEventFilter.OS.get(row.os, row.os),
                         EDRFEventFilter.DEFAULT_ACTIONS.get(row.default_action,
                                                             row.default_action), conditions])
        text += '\n### Filters\n\n' + self.md_table(
            ['Enabled', 'Name', 'Source', 'OS', 'Default behavior', 'Conditions'], rows)
        text += '\n### Module Settings\n\n' + self.md_settings(self.md_rows(
            ['delete_batch_size', 'send_interval', 'batch_max_events', 'vacuum_frequency',
             'max_events_in_db', 'events_in_memory', 'send_on_events', 'send_on_num_events']))
        rows = self.md_rows(['events_to_dxl', 'events_to_helix'])
        if self.get_option('events_to_helix') == '1':
            rows += self.md_rows(self.HELIX_OPTIONS)
        rows += self.md_rows(['events_to_syslog'])
        text += '\n### Destination for Event data\n\n' + self.md_settings(rows)
        if self.get_option('events_to_syslog') == '1':
            text += '\n' + self.md_table(
                ['Enabled', 'Name', 'Priority', 'Server', 'TCP Port', 'Enable SSL'],
                [[self.md_check('1' if row.enabled else '0'), row.name, row.priority, row.ip,
                  row.port, self.md_check('1' if row.tls else '0')]
                 for row in self.get_table('syslog_servers')])
        return text

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console group box (see Policy.to_markdown).
        """
        text = '### Trace Scanning\n\n' + self.md_settings(self.md_rows(
            ['trace', 'log_level', 'report_connectivity', 'deep_inspection', 'etw_ti_inspection',
             'trace_storage', 'cloud_interval']))
        text += '\n### Exclusion\n\n' + self.md_table(
            ['Platform', 'Exclusion', 'Items'],
            [[platform, label, '; '.join(self.get_list(name))] for platform, label, name in [
                ('Windows', 'Exclude process(es) by full path', 'windows_process_exclusions'),
                ('Windows', 'Disabled trace rules', 'windows_disabled_rules'),
                ('Linux', 'Exclude process(es) by full path', 'linux_process_exclusions'),
                ('Linux', 'Disabled trace rules', 'linux_disabled_rules'),
                ('Linux', 'Exclude file(s)', 'linux_file_exclusions'),
                ('Linux', 'Exclude folder(s)', 'linux_folder_exclusions'),
                ('Mac', 'Exclude process(es) by full path', 'mac_process_exclusions'),
                ('Mac', 'Disabled trace rules', 'mac_disabled_rules')]])
        rows = self.md_rows(['send_to_cloud', 'send_to_s3'])
        if self.get_option('send_to_s3') == '1':
            rows += [['Access Key ID and Secret Access Key',
                      'Defined in the ePO console (encrypted)']]
            rows += self.md_rows(['s3_region', 's3_bucket', 's3_interval', 's3_use_endpoint'])
            if self.get_option('s3_use_endpoint') == '1':
                rows += self.md_rows(['s3_endpoint'])
        text += '\n### Destination for Trace data\n\n' + self.md_settings(rows)
        sections = [('Trace', text),
                    ('Event streamer', self.md_event_streamer()),
                    ('Alerts', self.md_settings(self.md_rows(['ioc_alerts']))),
                    ('Process Tracker', self.md_settings(self.md_rows(['process_tracker'])))]
        rows = self.md_rows(['logon_tracker'])
        if self.get_option('logon_tracker') == '1':
            rows += self.md_rows(['logon_backfill', 'logon_timeout', 'logon_disable_enrichment',
                                  'logon_max_events', 'logon_ignore_addresses',
                                  'logon_ignore_hosts', 'logon_ignore_accounts',
                                  'logon_ignore_categories', 'logon_ignore_status',
                                  'logon_filter_tunneled'])
        sections.append(('Logon Tracker', self.md_settings(rows)))
        return sections
