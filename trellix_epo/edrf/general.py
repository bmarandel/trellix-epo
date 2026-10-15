# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class EDRFPolicyGeneral (Trellix EDR with
Forensics: General), all settings including those shown by "Show Advanced".

Storage learnt from a test policy changed in the ePO 5.10 console
(extension XCLIENT_META 2.1.2.270; the General page is unchanged in 50.3.0):

- "Report every" (health) and the proxy "Retry Delay" are shown in minutes
  and stored in seconds (mxa/health/report_interval, mxa/proxy/failed_retry_delay).
- Storage mode (mxa/eventor/storage_mode) sets four SQLite settings
  (STORAGE_MODES): Conventional = WAL journal, NORMAL synchronous; In-memory
  = MEMORY journal, in-memory DB, OFF synchronous; Memory-mapped I/O = MEMORY
  journal, memory-mapped DB, OFF; Memory-mapped I/O with log = WAL journal,
  memory-mapped DB, NORMAL; page size 4096 in every mode.
- Component Logging: the four checkboxes (libuv_enabled, ssl_enabled,
  queue_enabled, job_enabled) are also stored as a mask, mxa/log/mask =
  "UVPROC:SSLPROC:QUEUE:JOB" (checked items only). With no item checked the
  console keeps the last part of the previous mask (a bug of the extension);
  the library writes an empty mask.
- Log storage radio buttons: max_count_enabled / max_days_enabled; by event
  count, the console sets mxa/log/max_days to 0.
- Proxy: unchecking "Enable Proxy" stores mxa/proxy/type = "none" (the
  other proxy settings are kept).
- Forensics(HX) server: selecting a server registered in ePO (Server
  Settings) copies its configuration into the policy (mxs/* settings:
  certificates, private key, servers, mxa/fips/enabled); "No HX server"
  ("none") clears them. The library cannot read the ePO server registry:
  use copy_hx_server() from a policy where the server was selected in the
  console, or clear_hx_server().
- The uninstall password is hashed with a random salt by the ePO server
  and the proxy password is not set by the library either (see the README).
- The General page of the console embeds the stored values in its script
  without escaping them (a JavaScript template literal): a value with \\
  (e.g. a proxy user name LAB\\user) or " stops the console from opening
  the policy (checked on the lab). The library refuses them in the text
  settings, with ` and ${ that end or alter the template literal.
- Field lengths of the console: proxy name and user name 100 characters,
  proxy exclusion list 3072 characters (the General settings are not split
  by the ePO server).
"""

from .policy import EDRFPolicy, CHECK, NUMBER, SELECT, TEXT, LIST


class EDRFPolicyGeneral(EDRFPolicy):
    """
    The EDRFPolicyGeneral class can be used to edit the Trellix EDR with
    Forensics policy: General.
    """
    MD_CATEGORY = 'General'
    TYPE = 'General'
    MAX_LIST_LENGTH = 3072
    # Characters that stop the console from opening the policy.
    FORBIDDEN = ['\\', '"', '`', '${']

    STORAGE_MODES = {
        # mode: (label, journal mode, in memory, memory mapped, synchronous)
        'highintegrity': ('Conventional(Default)', 'WAL', 'false', 'false', 'NORMAL'),
        'inmemory': ('In-memory', 'MEMORY', 'true', 'false', 'OFF'),
        'mmapio': ('Memory-mapped I/O', 'MEMORY', 'false', 'true', 'OFF'),
        'mmapiowithlog': ('Memory-mapped I/O with log', 'WAL', 'false', 'true', 'NORMAL'),
    }
    PRIORITIES = {'idle': 'Idle(Default)', 'highest': 'Highest', 'high': 'High',
                  'above': 'Above normal', 'normal': 'Normal', 'below': 'Below normal'}
    LOG_LEVELS = {'INFO': 'Information(Default)', 'DEBUG': 'Debug(highest)',
                  'WARNING': 'Warning', 'ERROR': 'Error'}
    SERVICE_LOG_FORMATS = {'none': 'None', 'file': 'File'}
    SERVICE_LOG_LEVELS = {'1': 'Debug', '2': 'Trace', '3': 'Info', '4': 'Warning', '5': 'Error'}
    PROXY_TYPES = {'system': 'Operating System', 'manual': 'User Defined'}
    # Component Logging checkboxes and their mask names, in the mask order.
    COMPONENT_MASKS = [('log_libuv', 'UVPROC'), ('log_ssl', 'SSLPROC'), ('log_queue', 'QUEUE'),
                       ('log_job', 'JOB')]
    # Settings copied from the registered Forensics(HX) server.
    HX_SETTINGS = ['mxs/hx_enabled', 'mxs/ca/pem', 'mxs/clusters', 'mxs/pki/distro/crl',
                   'mxs/provo/cert', 'mxs/provo/key', 'mxs/provo/key_overflow',
                   'mxs/provo/keysize', 'mxs/provo/servers', 'mxa/fips/enabled']

    OPTIONS = {
        # Self Protection
        'self_protection': ('mxa/process/protection_enabled', 'Enable Self Protection', CHECK),
        'uninstall_password': ('mxa/process/uninstall_password_enabled',
                               'Enable password to uninstall', CHECK),
        # EDR Content Updates
        'content_updates': ('UEDR/General/unattended_update_enabled', 'Enable Content Updates',
                            CHECK),
        'content_update_interval': ('UEDR/General/unattended_update_timeout',
                                    'Check for content updates every (minutes)', NUMBER, 60, 1440),
        # Forensics(HX) Server
        'poll_interval': ('mxs/poll_agents', 'Poll interval (seconds)', NUMBER, 60, 86400),
        'fastpoll_interval': ('mxs/fastpoll_agents', 'Fastpoll interval (seconds)', NUMBER,
                              20, 86400),
        # Trellix EDR with Forensics Health (advanced)
        'health_report': ('mxa/health/report', 'Report health status', CHECK),
        'health_interval': ('mxa/health/report_interval', 'Report every (minutes)', NUMBER,
                            1, 60, 60),
        # Performance Management (advanced)
        'cpu_limit': ('mxa/process/cpu_limit', 'Acquisition CPU usage limit (Minimum of 10%)',
                      NUMBER, 10, 100),
        'event_storage': ('mxa/eventor/max_db_size', 'Event storage (10-500 MB)', NUMBER, 10, 500),
        'storage_mode': ('mxa/eventor/storage_mode', 'Storage mode', SELECT,
                         {mode: spec[0] for mode, spec in STORAGE_MODES.items()}),
        'priority': ('mxa/process/priority', 'Priority Scheduling', SELECT, PRIORITIES),
        # Trellix EDR with cloud (advanced)
        'edr_module': ('mxa/container/UnifiedEdr/enabled', 'Enable EDR module', CHECK),
        # Trellix EDR with Forensics Logging (advanced)
        'logging': ('mxa/log/enabled', 'Enable logging', CHECK),
        'log_level': ('mxa/log/level', 'Log level', SELECT, LOG_LEVELS),
        'log_per_module': ('mxa/log/per_module', 'Separate log per module', CHECK),
        # Component Logging (advanced)
        'log_libuv': ('libuv_enabled', 'Calls to libuv read and write', CHECK),
        'log_ssl': ('ssl_enabled', 'SSL functions', CHECK),
        'log_queue': ('queue_enabled', 'Internal queue usage', CHECK),
        'log_job': ('job_enabled', 'Job-related', CHECK),
        # EDR Service Logging (advanced)
        'service_log_format': ('UEDR/MarLogger/storage_format', 'Logger format', SELECT,
                               SERVICE_LOG_FORMATS),
        'service_log_level': ('UEDR/MarLogger/log_level', 'Log level', SELECT,
                              SERVICE_LOG_LEVELS),
        'service_log_buffer': ('UEDR/MarLogger/buffer_size', 'Buffer size', NUMBER, 1, 120),
        'service_log_max_size': ('UEDR/MarLogger/max_file_size',
                                 'Maximum size (MB) of the log file', NUMBER, 10, 100),
        # Proxy Settings for EDR with Forensics (advanced): see set_proxy().
        'proxy_host': ('mxa/proxy/host', 'Proxy name', TEXT, 100),
        'proxy_port': ('mxa/proxy/port', 'Port', NUMBER, 1, 65000),
        'proxy_exclude_hosts': ('mxa/proxy/exclude_hosts', 'Excluded hosts', LIST, False),
        'proxy_exclude_local': ('mxa/proxy/exclude_local_host', 'Exclude Local/Simple Host Names',
                                CHECK),
        'proxy_username': ('mxa/proxy/username', 'Username', TEXT, 100),
        'proxy_retry_delay': ('mxa/proxy/failed_retry_delay', 'Retry Delay (minutes)', NUMBER,
                              2, 64800, 60),
    }
    # Console defaults of the settings that may be missing from a policy.
    DEFAULTS = {'HXServerName': '', 'mxa/fips/enabled': 'false', 'mxa/log/mask': '',
                'max_count_enabled': 'true', 'max_days_enabled': 'false',
                'mxa/log/max_count': '100000', 'mxa/log/max_days': '0',
                'mxa/proxy': 'true', 'mxa/proxy/type': 'system', 'mxa/proxy/host': '',
                'mxa/proxy/port': '80', 'mxa/proxy/exclude_hosts': '',
                'mxa/proxy/exclude_local_host': 'false', 'mxa/proxy/username': '',
                'mxa/proxy/failed_retry_delay': '1200'}
    SECRETS = {'uninstall_password': 'mxa/process/uninstall_password'}

    def set_option(self, name, value):
        """
        Set an option, checked as in the console (see EDRFPolicy.set_option).
        Storage mode also sets its SQLite settings; the Component Logging
        checkboxes update the log mask, as the console does.
        """
        if self.OPTIONS[name][2] in (TEXT, LIST):
            for text in (value if self.OPTIONS[name][2] == LIST else [value]):
                if any(chars in str(text) for chars in self.FORBIDDEN):
                    raise ValueError('{}: \\, ", ` and ${{ are not supported (the console cannot '
                                     'open the policy any more): {!r}'.format(
                                         self.OPTIONS[name][1], text))
        before = self.get_option(name)
        result = super(EDRFPolicyGeneral, self).set_option(name, value)
        if name == 'storage_mode':
            _, journal, in_memory, mapped, synchronous = self.STORAGE_MODES[value]
            self._set('mxa/eventor/db_journal_mode', journal)
            self._set('mxa/eventor/db_in_memory', in_memory)
            self._set('mxa/eventor/db_memory_mapped', mapped)
            self._set('mxa/eventor/db_synchronous', synchronous)
            self._set('mxa/eventor/db_page_size', '4096')
        elif name in dict(self.COMPONENT_MASKS) and before != self.get_option(name):
            self._set('mxa/log/mask', ':'.join(mask for option, mask in self.COMPONENT_MASKS
                                               if self.get_option(option) == '1'))
        return result

    # ------------------------------ Forensics(HX) Server ------------------------------
    def get_hx_server(self):
        """
        Get the registered Forensics(HX) server name ('' if no server).
        """
        name = self._get('HXServerName')
        return '' if name in (None, 'none') else name

    hx_server = property(get_hx_server)

    def clear_hx_server(self):
        """
        Select "No HX server" (the server settings are cleared as in the console).
        """
        self._set('HXServerName', 'none')
        for setting in self.HX_SETTINGS:
            self._set(setting, 'false' if setting in ('mxs/hx_enabled', 'mxa/fips/enabled') else '')
        return True

    def copy_hx_server(self, policy):
        """
        Select the Forensics(HX) server of another General policy (an
        EDRFPolicyGeneral where the server was selected in the console):
        its name and its configuration (certificates, key, servers) are copied.
        """
        if not policy.get_hx_server():
            raise ValueError('The policy "{}" has no Forensics(HX) server.'.format(
                policy.get_name()))
        self._set('HXServerName', policy.get_hx_server())
        for setting in self.HX_SETTINGS:
            self._set(setting, policy._get(setting) or '')
        return True

    # ------------------------------ Log storage ------------------------------
    def get_log_storage(self):
        """
        Get the log storage: ('count', events) or ('days', days).
        """
        if self._get('max_days_enabled') == 'true':
            return 'days', int(self._get('mxa/log/max_days'))
        return 'count', int(self._get('mxa/log/max_count'))

    def set_log_storage(self, kind, value):
        """
        Set the log storage: by event count ('count', 10000-5000000 events)
        or by calendar days ('days', 1-365).
        """
        if kind == 'count':
            if not 10000 <= int(value) <= 5000000:
                raise ValueError('Enter a number between 10000 and 5000000.')
            self._set('mxa/log/max_count', int(value))
            self._set('mxa/log/max_days', '0')
        elif kind == 'days':
            if not 1 <= int(value) <= 365:
                raise ValueError('Enter a number between 1 and 365.')
            self._set('mxa/log/max_days', int(value))
        else:
            raise ValueError('The log storage must be "count" or "days".')
        self._set('max_count_enabled', 'true' if kind == 'count' else 'false')
        self._set('max_days_enabled', 'true' if kind == 'days' else 'false')
        return True

    # ------------------------------ Proxy ------------------------------
    def get_proxy(self):
        """
        Get the proxy type: None (proxy disabled), 'system' (Operating
        System) or 'manual' (User Defined).
        """
        if self._get('mxa/proxy') != 'true' or self._get('mxa/proxy/type') == 'none':
            return None
        return self._get('mxa/proxy/type')

    def set_proxy(self, proxy_type, host=None, port=None, exclude_hosts=None,
                  exclude_local=None, username=None, retry_delay=None):
        """
        Set the proxy: None (disabled), 'system' (Operating System) or
        'manual' (User Defined, with a proxy name and a port; optional
        excluded hosts list, exclude local/simple host names '1'/'0',
        username and retry delay in minutes). The proxy password can only
        be defined in the ePO console.
        """
        if proxy_type is None:
            self._set('mxa/proxy', 'false')
            return self._set('mxa/proxy/type', 'none')
        if proxy_type not in self.PROXY_TYPES:
            raise ValueError('The proxy type must be None, "system" or "manual".')
        if proxy_type == 'manual':
            if not (host or self._get('mxa/proxy/host')):
                raise ValueError('A user defined proxy needs a proxy name.')
            for name, value in [('proxy_host', host), ('proxy_port', port),
                                ('proxy_exclude_hosts', exclude_hosts),
                                ('proxy_exclude_local', exclude_local),
                                ('proxy_username', username), ('proxy_retry_delay', retry_delay)]:
                if value is not None:
                    self.set_option(name, value)
        self._set('mxa/proxy', 'true')
        return self._set('mxa/proxy/type', proxy_type)

    proxy = property(get_proxy, set_proxy)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console group box, the "Show Advanced" ones included (see
        Policy.to_markdown).
        """
        sections = []
        rows = self.md_rows(['self_protection', 'uninstall_password'])
        if self.get_option('uninstall_password') == '1':
            rows.append(['Password', 'Defined in the ePO console (not exported)'])
        sections.append(('Self Protection', self.md_settings(rows)))
        sections.append(('EDR Content Updates', self.md_settings(
            self.md_rows(['content_updates', 'content_update_interval']))))
        sections.append(('Forensics(HX) Server', self.md_settings(
            [['Registered Forensics(HX) server', self.get_hx_server() or 'No HX server'],
             ['HX servers', self._get('mxs/provo/servers') if self.get_hx_server() else None]] +
            self.md_rows(['poll_interval', 'fastpoll_interval']))))
        sections.append(('Trellix EDR with Forensics Health (advanced)', self.md_settings(
            self.md_rows(['health_report', 'health_interval']))))
        sections.append(('Performance Management (advanced)', self.md_settings(
            self.md_rows(['cpu_limit', 'event_storage', 'storage_mode', 'priority']))))
        sections.append(('Trellix EDR with cloud (advanced)', self.md_settings(
            self.md_rows(['edr_module']))))
        kind, value = self.get_log_storage()
        sections.append(('Trellix EDR with Forensics Logging (advanced)', self.md_settings(
            self.md_rows(['logging', 'log_level']) +
            [['Log storage', '{} events'.format(value) if kind == 'count'
              else '{} days'.format(value)]] + self.md_rows(['log_per_module']))))
        sections.append(('Component Logging (advanced)', self.md_settings(
            self.md_rows([option for option, _ in self.COMPONENT_MASKS]))))
        sections.append(('EDR Service Logging (advanced)', self.md_settings(
            self.md_rows(['service_log_format', 'service_log_level', 'service_log_buffer',
                          'service_log_max_size']))))
        proxy = self.get_proxy()
        rows = [['Enable Proxy', self.md_check('1' if proxy else '0')]]
        if proxy:
            rows.append(['Proxy Settings', self.PROXY_TYPES[proxy]])
        if proxy == 'manual':
            rows += self.md_rows(['proxy_host', 'proxy_port', 'proxy_exclude_hosts',
                                  'proxy_exclude_local', 'proxy_username', 'proxy_retry_delay'])
        sections.append(('Proxy Settings for EDR with Forensics (advanced)',
                         self.md_settings(rows)))
        return sections
