# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2020 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESFWPolicyRules and the objects of its rule
tree: FWRule, FWGroup, FWNetwork, FWApplication, FWExecutable, FWLocation
and FWAddress.

Storage (learnt from rules, groups, networks, applications and a location
created in the ePO 5.10 console): every rule and group is an
EPOPolicySettings (param_int 101) holding its own settings; every group has
a sequence (param_int 100, RuleListID = group GUID) listing the GUIDs of its
rules in evaluation order, the root sequence has no RuleListID; the named
networks, the executables and the locations are aggregates (param_int 104)
referenced by the rule (AggRef). A rule holds its applications (App*
settings) whose AppExeSet gives the index range of their executables
among the executable aggregates of the rule.
"""

import copy
import re
import uuid
import datetime as dt
import ipaddress as ip
import xml.etree.ElementTree as et
from .protocols import InternetProtocols, MessageTypes, MessageTypesv6, NetworkProtocols
from ...policies import Policy
from ...validators import (check_int, check_setting_length, is_fw_host, is_fw_single_ip,
                           is_fw_port, is_fw_file_path, is_fw_registry_key, is_fw_fqdn,
                           is_fw_dns_suffix, is_x500_name)


def _new_guid():
    return str(uuid.uuid4())


def _now():
    # Format of the console, e.g. 2026-10-03T22:15:45.807+02:00
    return dt.datetime.now().astimezone().isoformat(timespec='milliseconds')


def _get_list(values, key):
    """
    Returns the list stored as _<key> (count) and +<key>#<n> (items).
    """
    count = int(values.get('_' + key, '0') or '0')
    return [values.get('+{}#{}'.format(key, row), '') for row in range(count)]


def _set_list(values, key, items):
    """
    Stores a list as _<key> and +<key>#<n>; an empty list is not stored,
    as in the console exports.
    """
    for name in [name for name in values if _base_key(name) == key]:
        del values[name]
    if items:
        values['_' + key] = str(len(items))
        for row, item in enumerate(items):
            values['+{}#{}'.format(key, row)] = item


def _check_length(what, value, maximum):
    """
    Checks a value against the maximum length of its console field: ePO
    imports a longer value but the console then fails to open the policy
    ("An unexpected error occurred.", seen with a 101 characters rule name).
    """
    if value and len(value) > maximum:
        raise ValueError('{} is too long ({} characters, {} at most): {}'.format(
            what, len(value), maximum, value))


# Maximum lengths of the console fields (ePO 5.10 rule, group, network,
# application, executable and location dialogs).
NAME_MAX = 100
NOTES_MAX = 3000


def _is_unchanged(obj, unchanged):
    """
    True if obj is one of unchanged (same type and same attributes).
    """
    return any(type(obj) is type(other) and vars(obj) == vars(other) for other in unchanged)


def _base_key(name):
    if name.startswith('+'):
        return name[1:].split('#')[0]
    if name.startswith('_'):
        return name[1:]
    return name


def _extra(values, managed):
    """
    Returns the settings not managed by an object (kept as is on save).
    """
    return {name: value for name, value in values.items() if _base_key(name) not in managed}


class FWAddress():
    """
    Converts the addresses of networks and locations between the console
    form (10.1.2.3, 10.10.0.0/16, 10.20.0.1-10.20.0.50, server.example.com,
    2001:db8::1...) and the stored form (IPv6, IPv4 mapped into IPv6).
    """

    # Special entries of the console "Address type" list.
    LOCAL_SUBNET = 'Local subnet'
    TRUSTED = 'Defined Networks (Not trusted)'
    ANY_IPV4 = 'Any IPv4 address'
    ANY_IPV6 = 'Any IPv6 address'
    ANY_LOCAL_IP = 'Any local IP address'
    SPECIAL = {
        ANY_LOCAL_IP: '[local]',
        LOCAL_SUBNET: '0000:0000:0000:0000:0000:ffff:0000:0000',
        TRUSTED: '[trusted]',
        ANY_IPV4: '0000:0000:0000:0000:0000:ffff:0000:0000-'
                  '0000:0000:0000:0000:0000:ffff:ffff:ffff',
        ANY_IPV6: '0000:0000:0000:0000:0000:0000:0000:0000-'
                  'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff',
    }

    @staticmethod
    def __ip(value):
        try:
            return ip.ip_address(value.strip())
        except ValueError:
            return None

    @classmethod
    def __store_ip(cls, address):
        if address.version == 4:
            address = ip.IPv6Address('::ffff:' + str(address))
        # 8 groups of 4 hex digits (exploded would keep an IPv4 mapped
        # address dotted: ...:ffff:10.0.0.1).
        packed = address.packed
        return ':'.join('{:02x}{:02x}'.format(packed[row], packed[row + 1])
                        for row in range(0, 16, 2))

    @staticmethod
    def __console_ip(address):
        return str(address.ipv4_mapped) if address.ipv4_mapped is not None else str(address)

    @classmethod
    def to_epo(cls, value):
        """
        Returns the stored form of a console address.
        """
        if value in cls.SPECIAL:
            return cls.SPECIAL[value]
        if '-' in value:
            first, last = value.split('-', 1)
            if cls.__ip(first) is not None and cls.__ip(last) is not None:
                return '{}-{}'.format(cls.__store_ip(cls.__ip(first)),
                                      cls.__store_ip(cls.__ip(last)))
        if '/' in value:
            try:
                network = ip.ip_network(value.strip(), strict=False)
            except ValueError:
                network = None
            if network is not None:
                prefix = network.prefixlen + (96 if network.version == 4 else 0)
                return '{}/{}'.format(cls.__store_ip(network.network_address), prefix)
        address = cls.__ip(value)
        if address is not None:
            return cls.__store_ip(address)
        # Fully qualified domain name: stored in lower case by the console.
        return value.lower()

    @classmethod
    def from_epo(cls, value):
        """
        Returns the console form of a stored address.
        """
        for name, stored in cls.SPECIAL.items():
            if value == stored:
                return name
        if '-' in value:
            first, last = value.split('-', 1)
            if cls.__ip(first) is not None and cls.__ip(last) is not None:
                return '{}-{}'.format(cls.__console_ip(cls.__ip(first)),
                                      cls.__console_ip(cls.__ip(last)))
        if '/' in value:
            first, prefix = value.split('/', 1)
            address = cls.__ip(first)
            if address is not None and prefix.isdigit():
                if address.ipv4_mapped is not None:
                    return '{}/{}'.format(address.ipv4_mapped, int(prefix) - 96)
                return '{}/{}'.format(address, prefix)
        address = cls.__ip(value)
        if address is not None:
            return cls.__console_ip(address)
        return value


class _FWAggregate():
    """
    Common part of the objects stored as aggregates (param_int 104).
    """
    TYPE = ''
    KIND = ''
    MANAGED = ['GUID', 'LastModified', 'LastModifyingUsername', 'Note', 'Type']

    def __init__(self, notes='', aggregate_id=None):
        self.id = aggregate_id or _new_guid()
        self.notes = notes
        self.modified = ''
        self.modified_by = ''
        self._extra = {}
        # Stored form of the addresses read, kept when unchanged.
        self._stored = {}

    def copy(self):
        """
        Returns a copy with new IDs, e.g. to use a network of a rule in
        another rule (the console never shares them).
        """
        other = copy.deepcopy(self)
        other.id = _new_guid()
        if hasattr(other, 'remote_id'):
            other.remote_id = None
        return other

    def _store(self, address):
        return self._stored.get(address) or FWAddress.to_epo(address)

    def _console(self, stored):
        address = FWAddress.from_epo(stored)
        self._stored[address] = stored
        return address

    def _read_common(self, values):
        self.id = values.get('GUID', self.id)
        self.notes = values.get('Note', '')
        self.modified = values.get('LastModified', '')
        self.modified_by = values.get('LastModifyingUsername', '')
        self._extra = _extra(values, self.MANAGED)

    def _common_values(self):
        values = dict(self._extra)
        values.update({'GUID': self.id, 'LastModified': self.modified,
                       'LastModifyingUsername': self.modified_by, 'Note': self.notes,
                       'Type': self.TYPE})
        return values

    def settings_name(self, policy_name):
        """
        Name of the EPOPolicySettings of a new aggregate, as the console does.
        """
        return '{}:{}:{}'.format(policy_name, self.KIND, self.id)


class FWExecutable(_FWAggregate):
    """
    An executable of an application (console "Executable" dialog): name,
    file name or path (wildcards allowed), file description, MD5 hash and
    signer ('' no digital signature check, FWExecutable.ANY_SIGNATURE "Allow
    any signature" or the distinguished name of the signer).
    """
    ANY_SIGNATURE = '*'
    TYPE = '65547'
    KIND = 'Executable'
    NO_HASH = '0' * 32
    MANAGED = _FWAggregate.MANAGED + ['AppName', 'AppPath', 'AppHash', 'AppSigner',
                                      'AppDescription']

    def __init__(self, name, path='', md5='', signer='', description='', notes='',
                 executable_id=None):
        super(FWExecutable, self).__init__(notes, executable_id)
        self.name = name
        self.path = path
        self.md5 = md5
        self.signer = signer
        self.description = description

    def __repr__(self):
        return 'FWExecutable({!r}, path={!r})'.format(self.name, self.path)

    def check(self):
        """
        Raise ValueError if the console refuses the executable (Firewall
        26.8): name of 100 characters, file name or path of 257 (see
        mcafee_epo_policies.validators.is_fw_file_path), file description
        255, MD5 hash of 32 hexadecimal digits, signer of 1024 characters
        (ANY_SIGNATURE or a distinguished name accepted by the ePO server, see
        mcafee_epo_policies.validators.is_x500_name),
        notes 3000; one of file description, path, MD5 hash or signer is
        required.
        """
        if not self.name or not self.name.strip():
            raise ValueError('An executable needs a name.')
        if not (self.description.strip() or self.path.strip() or self.md5 or self.signer):
            raise ValueError('Executable "{}": a file description, a path, an MD5 hash or a '
                             'signer is required.'.format(self.name))
        for what, value, maximum in [('Executable name', self.name, NAME_MAX),
                                     ('File name or path', self.path, 257),
                                     ('File description', self.description, 255),
                                     ('MD5 hash', self.md5, 32),
                                     ('Signer', self.signer, 1024),
                                     ('Executable notes', self.notes, NOTES_MAX)]:
            _check_length(what, value, maximum)
        if self.path and not is_fw_file_path(self.path):
            raise ValueError('Executable "{}": invalid file name or path: {!r}'.format(
                self.name, self.path))
        if self.md5 and not re.fullmatch(r'[0-9a-fA-F]{32}', self.md5):
            raise ValueError('Executable "{}": the MD5 hash is 32 hexadecimal digits: '
                             '{!r}'.format(self.name, self.md5))
        if self.signer not in ['', self.ANY_SIGNATURE] and not is_x500_name(self.signer):
            raise ValueError('Executable "{}": the signer is a distinguished name (e.g. '
                             'CN=Contoso, O=Contoso, C=US): {!r}'.format(self.name, self.signer))

    @classmethod
    def from_values(cls, values):
        exe = cls.__new__(cls)
        _FWAggregate.__init__(exe)
        exe._read_common(values)
        first = lambda key: (_get_list(values, key) or [''])[0]
        exe.name = first('AppName')
        exe.path = first('AppPath')
        exe.md5 = first('AppHash').strip('0') and first('AppHash')
        exe.signer = first('AppSigner')
        exe.description = first('AppDescription')
        return exe

    def to_values(self):
        values = self._common_values()
        _set_list(values, 'AppDescription', [self.description])
        _set_list(values, 'AppHash', [self.md5 or self.NO_HASH])
        _set_list(values, 'AppName', [self.name])
        _set_list(values, 'AppPath', [self.path])
        _set_list(values, 'AppSigner', [self.signer])
        return values


class FWApplication():
    """
    An application of a rule (console "Application" dialog): a name, notes
    and one or more executables (FWExecutable).
    """

    def __init__(self, name, executables=None, notes='', application_id=None):
        self.name = name
        self.executables = list(executables or [])
        self.notes = notes
        self.id = application_id or _new_guid()
        self.modified = ''
        self.modified_by = ''

    def __repr__(self):
        return 'FWApplication({!r}, {!r})'.format(self.name, self.executables)

    def check(self, unchanged=()):
        if not self.name:
            raise ValueError('An application needs a name.')
        if not self.executables:
            raise ValueError('Application "{}" needs at least one executable.'.format(self.name))
        _check_length('Application name', self.name, NAME_MAX)
        _check_length('Application notes', self.notes, NOTES_MAX)
        for exe in self.executables:
            if not _is_unchanged(exe, unchanged):
                exe.check()


class FWNetwork(_FWAggregate):
    """
    A named network of a rule (console "Network" dialog): a name, notes and
    addresses in the console form (see FWAddress). The same object type is
    used for the local and the remote networks of a rule.
    """
    LOCAL, REMOTE = 'Local', 'Remote'
    TYPES = {'65541': LOCAL, '65546': REMOTE}
    KIND = 'NamedNetwork'
    MANAGED = _FWAggregate.MANAGED + ['Name', 'LocalAddress', 'RemoteAddress', 'RemoteNetID']

    def __init__(self, name, addresses=None, notes='', network_id=None):
        super(FWNetwork, self).__init__(notes, network_id)
        self.name = name
        self.addresses = list(addresses or [])
        # A remote network has a second ID (RemoteNetID), given when saved.
        self.remote_id = None

    def __repr__(self):
        return 'FWNetwork({!r}, {!r})'.format(self.name, self.addresses)

    def check(self):
        """
        Raise ValueError if the console refuses the network (Firewall 26.8):
        name of 100 characters, notes 3000, addresses of 255 characters (see
        mcafee_epo_policies.validators.is_fw_host) or the special entries of
        FWAddress.
        """
        if not self.name or not self.name.strip():
            raise ValueError('A network needs a name.')
        if not self.addresses:
            raise ValueError('Network "{}" needs at least one address.'.format(self.name))
        _check_length('Network name', self.name, NAME_MAX)
        _check_length('Network notes', self.notes, NOTES_MAX)
        for address in self.addresses:
            if address not in FWAddress.SPECIAL and not is_fw_host(address):
                raise ValueError('Network "{}": invalid address: {!r} (an IPv4 or IPv6 '
                                 'address, a network, a range first-last or a domain '
                                 'name)'.format(self.name, address))

    @classmethod
    def from_values(cls, values):
        network = cls.__new__(cls)
        _FWAggregate.__init__(network)
        network._read_common(values)
        network.name = values.get('Name', '')
        kind = cls.TYPES.get(values.get('Type'), cls.LOCAL)
        network.addresses = [network._console(value)
                             for value in _get_list(values, kind + 'Address')]
        network.remote_id = values.get('RemoteNetID', None)
        return network

    def to_values(self, kind):
        """
        Returns the settings of the network used as a local or remote
        (FWNetwork.LOCAL/REMOTE) network.
        """
        values = self._common_values()
        values['Type'] = [code for code, name in self.TYPES.items() if name == kind][0]
        values['Name'] = self.name
        _set_list(values, kind + 'Address', [self._store(address) for address in self.addresses])
        if kind == self.REMOTE:
            self.remote_id = self.remote_id or _new_guid()
            values['RemoteNetID'] = self.remote_id
        return values

    def remote_settings_name(self, policy_name):
        return '{}:{}:{}:Remote'.format(policy_name, self.KIND, self.remote_id)


class FWLocation(_FWAggregate):
    """
    The location of a group (console "Enable location awareness"): name,
    connection isolation, ePO reachability and the location criteria.
    """
    TYPE = '65543'
    KIND = 'Location'
    # (attribute, setting, address)
    CRITERIA = [('dns_suffixes', 'DnsSuffix', False),
                ('default_gateways', 'DefaultGateway', True),
                ('dhcp_servers', 'DhcpServer', True),
                ('dns_servers', 'DnsServer', True),
                ('primary_wins', 'PrimaryWINS', True),
                ('secondary_wins', 'SecondaryWINS', True),
                ('domains_reachable', 'DomainReachable', False)]
    MANAGED = _FWAggregate.MANAGED + ['Name', 'Isolated', 'RequireEpoReachable', 'RegKey'] + \
        [setting for _, setting, _ in CRITERIA]

    def __init__(self, name, isolated=False, require_epo_reachable=False, dns_suffixes=None,
                 default_gateways=None, dhcp_servers=None, dns_servers=None, primary_wins=None,
                 secondary_wins=None, domains_reachable=None, registry_key='', notes='',
                 location_id=None):
        super(FWLocation, self).__init__(notes, location_id)
        self.name = name
        self.isolated = isolated
        self.require_epo_reachable = require_epo_reachable
        self.dns_suffixes = list(dns_suffixes or [])
        self.default_gateways = list(default_gateways or [])
        self.dhcp_servers = list(dhcp_servers or [])
        self.dns_servers = list(dns_servers or [])
        self.primary_wins = list(primary_wins or [])
        self.secondary_wins = list(secondary_wins or [])
        self.domains_reachable = list(domains_reachable or [])
        # Registry key and value, e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Key\Value=data
        self.registry_key = registry_key

    def __repr__(self):
        return 'FWLocation({!r})'.format(self.name)

    # Console check of each criterion (location dialog).
    __VALIDATORS = {'dns_suffixes': is_fw_dns_suffix, 'domains_reachable': is_fw_fqdn}

    def check(self):
        """
        Raise ValueError if the console refuses the location (Firewall 26.8):
        name of 100 characters, criteria of 100 characters (DNS suffixes:
        is_fw_dns_suffix, domains reachable: is_fw_fqdn, gateways, DHCP, DNS
        and WINS servers: one IP address, is_fw_single_ip), registry key and
        value of 1499 characters each, the key checked by is_fw_registry_key
        (see mcafee_epo_policies.validators).
        """
        if not self.name or not self.name.strip():
            raise ValueError('A location needs a name.')
        if not (self.registry_key or any(getattr(self, attr) for attr, _, _ in self.CRITERIA)):
            raise ValueError('Location "{}" needs at least one criterion.'.format(self.name))
        _check_length('Location name', self.name, NAME_MAX)
        for attr, _, _ in self.CRITERIA:
            valid = self.__VALIDATORS.get(attr, is_fw_single_ip)
            for value in getattr(self, attr):
                _check_length('Location criterion', value, 100)
                if not valid(value):
                    raise ValueError('Location "{}": invalid {}: {!r}'.format(
                        self.name, attr.replace('_', ' '), value))
        # Registry key and value fields: 1499 characters each.
        parts = self.registry_key.split('=', 1)
        for part in parts:
            _check_length('Registry key', part, 1499)
        if self.registry_key and not is_fw_registry_key(parts[0]):
            raise ValueError('Location "{}": invalid registry key: {!r}'.format(
                self.name, parts[0]))

    @classmethod
    def from_values(cls, values):
        location = cls.__new__(cls)
        _FWAggregate.__init__(location)
        location._read_common(values)
        location.name = values.get('Name', '')
        location.isolated = values.get('Isolated') == '1'
        location.require_epo_reachable = values.get('RequireEpoReachable') == '1'
        for attr, setting, is_address in cls.CRITERIA:
            items = _get_list(values, setting)
            setattr(location, attr, [location._console(item) for item in items]
                    if is_address else items)
        location.registry_key = (_get_list(values, 'RegKey') or [''])[0]
        return location

    def to_values(self):
        values = self._common_values()
        values['Name'] = self.name
        values['Isolated'] = '1' if self.isolated else '0'
        values['RequireEpoReachable'] = '1' if self.require_epo_reachable else '0'
        for attr, setting, is_address in self.CRITERIA:
            items = getattr(self, attr)
            _set_list(values, setting, [self._store(item) for item in items]
                      if is_address else list(items))
        _set_list(values, 'RegKey', [self.registry_key] if self.registry_key else [])
        return values


class FWRule():
    """
    A firewall rule (console "Add Rule" dialog). Networks, applications and
    the schedule are set with the attributes:

    - network_protocols: [] (Any protocol) or FWRule.IPV4/IPV6 (IP protocol)
      or other EtherType codes (Non-IP protocol);
    - connection_types: [] (all) or FWRule.WIRED/WIRELESS/VIRTUAL;
    - transport_protocol: None (All Protocols) or an IP protocol number
      (FWRule.TCP, UDP, ICMP, ICMPV6...), local_ports/remote_ports for
      TCP/UDP (e.g. ['80', '1000-2000']), message_type for ICMP;
    - local_networks/remote_networks: lists of FWNetwork;
    - applications: list of FWApplication;
    - schedule: set_schedule(days, start, end) or schedule_enabled = False.
    """
    ALLOW, BLOCK, JUMP = 'ALLOW', 'BLOCK', 'JUMP'
    EITHER, IN, OUT = 'EITHER', 'IN', 'OUT'
    IPV4, IPV6 = '2048', '34525'
    WIRED, WIRELESS, VIRTUAL = 'WIRED', 'WIRELESS', 'VPN'
    ICMP, TCP, UDP, ICMPV6 = '1', '6', '17', '58'
    # WeekMask bits (checked in the console: Sunday is 1).
    DAYS = [(1, 'Sunday'), (2, 'Monday'), (4, 'Tuesday'), (8, 'Wednesday'),
            (16, 'Thursday'), (32, 'Friday'), (64, 'Saturday')]
    # Name shown by the console in "Last Changed: By ..." for the changes
    # made with this library.
    MODIFIED_BY = 'mcafee_epo_policies'
    # Settings of a new rule, as written by the console.
    DEFAULTS = {'Invert': '0', 'OffHours': 'NONE', 'ScheduleDisableDuringTime': '0',
                'StartTime': '0:00', 'EndTime': '23:59', 'ViewOnly': '0',
                '_TcpFlags': '1', '+TcpFlags#0': '0'}
    MANAGED = ['Action', 'ClickTimeout', 'Direction', 'Enabled', 'GUID', 'Intrusion',
               'LastModified', 'LastModifyingUsername', 'Logged', 'Name', 'Note',
               'ScheduleEnabled', 'ScheduleEndHours', 'ScheduleEndMinutes',
               'ScheduleStartHours', 'ScheduleStartMinutes', 'WeekMask', 'AggRef',
               'AppExeSet', 'AppGUID', 'AppLastModified', 'AppLastModifyingUsername',
               'AppName', 'AppNote', 'LocalPort', 'RemotePort', 'MessageType',
               'NetworkProtocol', 'PhysicalMedium', 'TransportProtocol']
    is_group = False

    def __init__(self, name, action=ALLOW, direction=EITHER, enabled=True, intrusion=False,
                 log=False, notes='', network_protocols=None, connection_types=None,
                 transport_protocol=None, local_ports=None, remote_ports=None,
                 local_networks=None, remote_networks=None, applications=None,
                 rule_id=None):
        self.name = name
        self.action = action
        self.direction = direction
        self.enabled = enabled
        self.intrusion = intrusion
        self.log = log
        self.notes = notes
        # The console checks "IPv4 protocol" for a new rule.
        self.network_protocols = [self.IPV4] if network_protocols is None \
            else list(network_protocols)
        self.connection_types = list(connection_types or [])
        self.transport_protocol = transport_protocol
        self.local_ports = list(local_ports or [])
        self.remote_ports = list(remote_ports or [])
        self.message_type = None
        self.local_networks = list(local_networks or [])
        self.remote_networks = list(remote_networks or [])
        self.applications = list(applications or [])
        self.schedule_enabled = False
        self.schedule_days = []
        self.schedule_start = '00:00'
        self.schedule_end = '23:59'
        self.id = rule_id or _new_guid()
        self.modified = ''
        self.modified_by = ''
        self.view_only = False
        self._timeout = '0'
        self._extra = dict(self.DEFAULTS)
        self._aggref = []

    def __repr__(self):
        return '{}({!r})'.format(type(self).__name__, self.name)

    def set_schedule(self, days, start='00:00', end='23:59'):
        """
        Enable the schedule: days (e.g. ['Monday', 'Friday']), start and end
        time (HH:MM, 24 h).
        """
        known = [day for _, day in self.DAYS]
        for day in days:
            if day not in known:
                raise ValueError('Unknown day: {}'.format(day))
        self.schedule_enabled = True
        self.schedule_days = [day for day in known if day in days]
        self.schedule_start = start
        self.schedule_end = end

    def all_aggregates(self):
        """
        Returns the aggregates of the rule as (object, kind) in the stored
        order: executables, local networks, remote networks.
        """
        items = [(exe, FWExecutable.KIND) for app in self.applications
                 for exe in app.executables]
        items += [(network, FWNetwork.LOCAL) for network in self.local_networks]
        items += [(network, FWNetwork.REMOTE) for network in self.remote_networks]
        return items

    def check(self, unchanged=()):
        """
        Raise ValueError if the console refuses the rule. The objects of
        unchanged (networks, executables, location as read from the policy)
        are not checked again: some Trellix-defined rules hold values the
        console dialogs refuse (e.g. the network address ::).
        """
        if not self.name or not self.name.strip():
            raise ValueError('A rule needs a name.')
        _check_length('Rule name', self.name, NAME_MAX)
        _check_length('Rule notes', self.notes, NOTES_MAX)
        if self.action not in [self.ALLOW, self.BLOCK, self.JUMP]:
            raise ValueError('Unknown action: {}'.format(self.action))
        if self.direction not in [self.EITHER, self.IN, self.OUT]:
            raise ValueError('Unknown direction: {}'.format(self.direction))
        for medium in self.connection_types:
            if medium not in [self.WIRED, self.WIRELESS, self.VIRTUAL]:
                raise ValueError('Unknown connection type: {}'.format(medium))
        if (self.local_ports or self.remote_ports) and \
                self.transport_protocol not in [self.TCP, self.UDP]:
            raise ValueError('Rule "{}": ports need the TCP or UDP transport '
                             'protocol.'.format(self.name))
        for port in self.local_ports + self.remote_ports:
            _check_length('Port', port, 100)
            if not port.strip() or not is_fw_port(port):
                raise ValueError('Rule "{}": invalid port: {!r} (1-65535 or a range first-last '
                                 'with first < last)'.format(self.name, port))
        for ports in [self.local_ports, self.remote_ports]:
            check_setting_length('Ports', ', '.join(ports))
        self.__check_protocols()
        start, end = [self.__split_time(time) for time in [self.schedule_start,
                                                            self.schedule_end]]
        if self.schedule_enabled and end <= start:
            raise ValueError('Rule "{}": the schedule end time must be after the start '
                             'time.'.format(self.name))
        for network in self.local_networks + self.remote_networks:
            if not _is_unchanged(network, unchanged):
                network.check()
        for app in self.applications:
            app.check(unchanged)

    def __check_protocols(self):
        """
        Network protocol of the console: Any protocol ([]), IP protocol
        (IPv4 and/or IPv6) or one Non-IP protocol (an EtherType, 4
        hexadecimal digits at most in the console, stored in decimal).
        """
        protocols = self.network_protocols
        if not protocols or set(protocols) <= {self.IPV4, self.IPV6}:
            return
        if len(protocols) != 1 or not re.fullmatch('[0-9]+', protocols[0]) or \
                int(protocols[0]) > 0xFFFF:
            raise ValueError('Rule "{}": network protocols are [] (any), IPv4 and/or IPv6, or one '
                             'Non-IP EtherType (0-65535): {}'.format(self.name, protocols))

    @staticmethod
    def __split_time(time):
        try:
            hours, minutes = [int(part) for part in time.split(':')]
        except (ValueError, AttributeError):
            raise ValueError('Wrong time (HH:MM expected): {}'.format(time))
        if not (0 <= hours <= 23 and 0 <= minutes <= 59):
            raise ValueError('Wrong time (HH:MM expected): {}'.format(time))
        return hours, minutes

    @staticmethod
    def __ports(values, key):
        return [port.strip() for port in (_get_list(values, key) or [''])[0].split(',')
                if port.strip()]

    @classmethod
    def from_values(cls, values, aggregates):
        """
        Returns the rule (or group) of the settings of a rule, aggregates
        being the settings of the aggregates of the policy by GUID.
        """
        rule = cls.__new__(cls)
        FWRule.__init__(rule, '')
        if rule.is_group:
            rule.location = None
            rule.rules = []
        rule._extra = _extra(values, cls.MANAGED)
        rule.name = values.get('Name', '')
        rule.action = values.get('Action', cls.ALLOW)
        rule.direction = values.get('Direction', cls.EITHER)
        rule.enabled = values.get('Enabled', '1') == '1'
        rule.intrusion = values.get('Intrusion') == '1'
        rule.log = values.get('Logged') == '1'
        rule.notes = values.get('Note', '')
        rule.id = values.get('GUID', rule.id)
        rule.modified = values.get('LastModified', '')
        rule.modified_by = values.get('LastModifyingUsername', '')
        rule.view_only = values.get('ViewOnly') == '1'
        rule._timeout = values.get('ClickTimeout', '0')
        rule.network_protocols = _get_list(values, 'NetworkProtocol')
        rule.connection_types = _get_list(values, 'PhysicalMedium')
        rule.transport_protocol = (_get_list(values, 'TransportProtocol') or [None])[0]
        rule.local_ports = cls.__ports(values, 'LocalPort')
        rule.remote_ports = cls.__ports(values, 'RemotePort')
        rule.message_type = (_get_list(values, 'MessageType') or [None])[0]
        rule.schedule_enabled = values.get('ScheduleEnabled') == '1'
        mask = int(values.get('WeekMask', '0') or '0')
        rule.schedule_days = [day for bit, day in cls.DAYS if mask & bit]
        rule.schedule_start = '{:02d}:{:02d}'.format(int(values.get('ScheduleStartHours', '0')),
                                                     int(values.get('ScheduleStartMinutes', '0')))
        rule.schedule_end = '{:02d}:{:02d}'.format(int(values.get('ScheduleEndHours', '0')),
                                                   int(values.get('ScheduleEndMinutes', '0')))
        # Aggregates
        rule._aggref = _get_list(values, 'AggRef')
        executables = []
        for ref in rule._aggref:
            agg = aggregates.get(ref, {})
            agg_type = agg.get('Type')
            if agg_type == FWExecutable.TYPE:
                executables.append(FWExecutable.from_values(agg))
            elif agg_type in FWNetwork.TYPES:
                network = FWNetwork.from_values(agg)
                if FWNetwork.TYPES[agg_type] == FWNetwork.LOCAL:
                    rule.local_networks.append(network)
                else:
                    rule.remote_networks.append(network)
            elif agg_type == FWLocation.TYPE and rule.is_group:
                rule.location = FWLocation.from_values(agg)
        for row, app_id in enumerate(_get_list(values, 'AppGUID')):
            app = FWApplication(_get_list(values, 'AppName')[row], [],
                                _get_list(values, 'AppNote')[row], app_id)
            app.modified = _get_list(values, 'AppLastModified')[row]
            app.modified_by = _get_list(values, 'AppLastModifyingUsername')[row]
            for index in cls.__indexes(_get_list(values, 'AppExeSet')[row]):
                if index < len(executables):
                    app.executables.append(executables[index])
            rule.applications.append(app)
        return rule

    @staticmethod
    def __indexes(exe_set):
        """
        Returns the indexes of an AppExeSet value ('0', '0-7').
        """
        indexes = []
        for part in exe_set.split(','):
            if '-' in part:
                first, last = part.split('-')
                indexes += list(range(int(first), int(last) + 1))
            elif part.strip():
                indexes.append(int(part))
        return indexes

    def _aggregate_order(self):
        """
        Returns the aggregates in the order to store; the order read is kept
        when the rule still references the same aggregates.
        """
        items = self.all_aggregates()
        by_id = {obj.id: (obj, kind) for obj, kind in items}
        if sorted(by_id) == sorted(self._aggref) and len(items) == len(self._aggref):
            ordered = [by_id[ref] for ref in self._aggref]
            kinds = [kind for _, kind in ordered]
            exes = [obj.id for obj, kind in ordered if kind == FWExecutable.KIND]
            canonical = [exe.id for app in self.applications for exe in app.executables]
            # The executables must stay first and in the application order.
            if kinds[:len(exes)] == [FWExecutable.KIND] * len(exes) and exes == canonical:
                return ordered
        return items

    def to_values(self):
        """
        Returns the settings of the rule.
        """
        values = dict(self._extra)
        start = self.__split_time(self.schedule_start)
        end = self.__split_time(self.schedule_end)
        mask = sum(bit for bit, day in self.DAYS if day in self.schedule_days)
        values.update({'Action': self.action, 'ClickTimeout': self._timeout,
                       'Direction': self.direction, 'Enabled': '1' if self.enabled else '0',
                       'GUID': self.id, 'Intrusion': '1' if self.intrusion else '0',
                       'LastModified': self.modified, 'LastModifyingUsername': self.modified_by,
                       'Logged': '1' if self.log else '0', 'Name': self.name,
                       'Note': self.notes,
                       'ScheduleEnabled': '1' if self.schedule_enabled else '0',
                       'ScheduleStartHours': str(start[0]), 'ScheduleStartMinutes': str(start[1]),
                       'ScheduleEndHours': str(end[0]), 'ScheduleEndMinutes': str(end[1]),
                       'WeekMask': str(mask)})
        _set_list(values, 'AggRef', [obj.id for obj, _ in self._aggregate_order()])
        exes = [obj.id for obj, kind in self._aggregate_order() if kind == FWExecutable.KIND]
        exe_sets = []
        for app in self.applications:
            indexes = [exes.index(exe.id) for exe in app.executables]
            exe_sets.append(str(indexes[0]) if len(indexes) == 1 else
                            '{}-{}'.format(indexes[0], indexes[-1]))
        for key, attr in [('AppGUID', 'id'), ('AppLastModified', 'modified'),
                          ('AppLastModifyingUsername', 'modified_by'), ('AppName', 'name'),
                          ('AppNote', 'notes')]:
            _set_list(values, key, [getattr(app, attr) for app in self.applications])
        _set_list(values, 'AppExeSet', exe_sets)
        # The console stores an empty port list for TCP and UDP.
        with_ports = self.transport_protocol in [self.TCP, self.UDP]
        _set_list(values, 'LocalPort', [', '.join(self.local_ports)]
                  if self.local_ports or with_ports else [])
        _set_list(values, 'RemotePort', [', '.join(self.remote_ports)]
                  if self.remote_ports or with_ports else [])
        _set_list(values, 'MessageType', [self.message_type]
                  if self.message_type is not None else [])
        _set_list(values, 'NetworkProtocol', list(self.network_protocols))
        _set_list(values, 'PhysicalMedium', list(self.connection_types))
        _set_list(values, 'TransportProtocol', [self.transport_protocol]
                  if self.transport_protocol is not None else [])
        return values

    def settings_name(self, policy_name):
        return '{}:{}:{}'.format(policy_name, 'Group' if self.is_group else 'Rule', self.id)

    def touch(self, user=None):
        """
        Sets the last change date/user of the rule and of its new objects.
        """
        now = _now()
        self.modified, self.modified_by = now, user or self.MODIFIED_BY
        objects = [obj for obj, _ in self.all_aggregates()] + self.applications
        for obj in objects:
            if not obj.modified:
                obj.modified, obj.modified_by = now, user or self.MODIFIED_BY


class FWGroup(FWRule):
    """
    A group of rules (console "Add Group" dialog): the rules of the group
    (rules, list of FWRule/FWGroup), a location (FWLocation, Windows & Mac
    only), the timed group setting (timed_minutes: "Disable schedule and
    enable the group from the Trellix system tray icon", Windows only) and
    the same network, transport, application and schedule settings as a rule.
    """
    is_group = True

    def __init__(self, name, direction=FWRule.EITHER, enabled=True, notes='', location=None,
                 timed_minutes=0, rules=None, group_id=None, **kwargs):
        super(FWGroup, self).__init__(name, FWRule.JUMP, direction, enabled, notes=notes,
                                      rule_id=group_id, **kwargs)
        self.location = location
        self.timed_minutes = timed_minutes
        self.rules = list(rules or [])

    @property
    def timed_minutes(self):
        return int(self._timeout or '0')

    @timed_minutes.setter
    def timed_minutes(self, minutes):
        self._timeout = str(int(minutes or 0))

    def all_aggregates(self):
        items = super(FWGroup, self).all_aggregates()
        if self.location is not None:
            items.insert(0, (self.location, FWLocation.KIND))
        return items

    def check(self, unchanged=()):
        super(FWGroup, self).check(unchanged)
        # Console field "Number of minutes to enable the group" (Timed
        # group): 1-60 when enabled, 0 when not.
        if self.timed_minutes:
            check_int('Group "{}": timed group minutes'.format(self.name), self.timed_minutes,
                      1, 60)
        if self.location is not None and not _is_unchanged(self.location, unchanged):
            self.location.check()

    def walk(self):
        """
        Yields the rules and groups of the group, at all levels.
        """
        for rule in self.rules:
            yield rule
            if rule.is_group:
                for child in rule.walk():
                    yield child


class ESFWPolicyRules(Policy):
    """
    The ESFWPolicyRules class can be used to edit the Endpoint Security
    Firewall policy: Rules.
    """

    def __init__(self, policy_from_esfwpolicies=None):
        super(ESFWPolicyRules, self).__init__(policy_from_esfwpolicies)
        if policy_from_esfwpolicies is not None:
            if self.get_type() != 'FireCore_FW_Rules':
                raise ValueError('Wrong policy! Policy type must be "FireCore_FW_Rules".')
        self.seq = dict()
        self.rul = dict()
        self.agg = dict()

    MD_PRODUCT = 'Endpoint Security Firewall'
    MD_CATEGORY = 'Rules'

    def __repr__(self):
        return 'ESFWPolicyRules()'

    def load_policy(self):
        self.seq = dict()
        self.rul = dict()
        self.agg = dict()
        policy_obj = self.root.find('EPOPolicyObject')
        for policy_ref in policy_obj.findall('PolicySettings'):
            policy_set = self.root.find('./EPOPolicySettings[@name="{}"]'.format(policy_ref.text))
            set_type = int(policy_set.get('param_int'))
            if set_type == 100:
                self.__load_sequence(policy_set)
            elif set_type == 101:
                self.__load_rule(policy_set)
            elif set_type == 104:
                self.__load_aggreagate(policy_set)
            else:
                raise ValueError('Unknown param_int value int policy:{}'.format(set_type))
        return True

    def __load_sequence(self, policy_settings):
        # Enter in the sequence section
        section_obj = policy_settings.find('Section[@name="{}"]'.format(
                                           policy_settings.get('param_str')))
        # Determine the GUID of that sequence
        setting_obj = section_obj.find('Setting[@name="{}"]'.format('RuleListID'))
        # If the sequence has no value, it's the root sequence
        if setting_obj is not None:
            seq_key = setting_obj.get('value')
        else:
            seq_key = 'root'
        # Build the sequence list with respect of the order
        seq_list = list()
        # An empty group has no _RuleIDSequence setting.
        count_obj = section_obj.find('Setting[@name="_RuleIDSequence"]')
        max_rows = int(count_obj.get('value')) if count_obj is not None else 0
        for row in range(max_rows):
            seq_list.append(section_obj.find('Setting[@name="{}{}"]'.format(
                                             '+RuleIDSequence#', row)).get('value'))
        # Add the sequence ID with all sub sequences to the main dict
        self.seq[seq_key] = seq_list

    def __load_rule(self, policy_settings):
        # Enter in the rule section
        section_obj = policy_settings.find('Section[@name="{}"]'.format(
                                           policy_settings.get('param_str')))
        # Determine the GUID of that rule
        rul_key = section_obj.find('Setting[@name="{}"]'.format('GUID')).get('value')
        # Build the rule with all properties
        rul_props = dict()
        prop_keys = section_obj.findall('Setting')
        for prop in prop_keys:
            prop_key = prop.get('name')
            # If it's a simple property, get its value
            if prop_key[0] != "+" and prop_key[0] != "_":
                rul_props[prop_key] = prop.get('value')
            # If it's a list, get all possible values
            if prop_key[0] == "_":
                prop_val = list()
                max_rows = int(prop.get('value'))
                for row in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="+{}#{}"]'.format(
                                                    prop_key[1:], row))
                    prop_val.append(setting_obj.get('value'))
                rul_props[prop_key[1:]] = prop_val
        # Add the rule ID with all properties to the main dict
        self.rul[rul_key] = rul_props

    def __load_aggreagate(self, policy_settings):
        # Enter in the aggregate section
        section_obj = policy_settings.find('Section[@name="{}"]'.format(
                                            policy_settings.get('param_str')))
        # Determine the GUID of that aggregate
        agg_key = section_obj.find('Setting[@name="{}"]'.format('GUID')).get('value')
        # Build the aggregate with all properties
        agg_props = dict()
        prop_keys = section_obj.findall('Setting')
        for prop in prop_keys:
            prop_key = prop.get('name')
            # If it's a simple property, get its value
            if prop_key[0] != "+" and prop_key[0] != "_":
                agg_props[prop_key] = prop.get('value')
            # If it's a list, get all possible values
            if prop_key[0] == "_":
                prop_val = list()
                max_rows = int(prop.get('value'))
                for row in range(max_rows):
                    setting_obj = section_obj.find('Setting[@name="+{}#{}"]'.format(
                                                    prop_key[1:], row))
                    prop_val.append(setting_obj.get('value'))
                agg_props[prop_key[1:]] = prop_val
        # Add the rule ID with all properties to the main dict
        self.agg[agg_key] = agg_props

    # ------------------------------ Rule tree editing ------------------------------
    # Same workflow as the console: get_rules() returns the rule tree (FWRule
    # and FWGroup objects), add/update/remove/move_rule() change it. Rules
    # and groups whose ViewOnly setting is set (e.g. "Trellix core
    # networking", shown with a "View" link only in the console) can't be
    # changed, nor the content of such groups.

    @staticmethod
    def __values(settings_obj):
        section_obj = settings_obj.find('Section')
        return {setting.get('name'): setting.get('value')
                for setting in section_obj.findall('Setting')} if section_obj is not None else {}

    def __index(self):
        """
        Returns the EPOPolicySettings of the rules/groups and aggregates by
        GUID, and of the sequences by group GUID ('root' for the root).
        """
        rules, aggregates, sequences = {}, {}, {}
        policy_obj = self.root.find('EPOPolicyObject')
        names = set(ref.text for ref in policy_obj.findall('PolicySettings'))
        for settings_obj in self.root.findall('EPOPolicySettings'):
            if settings_obj.get('name') not in names:
                continue
            values = self.__values(settings_obj)
            param = settings_obj.get('param_int')
            if param == '100':
                sequences[values.get('RuleListID', 'root')] = settings_obj
            elif param == '101':
                rules[values.get('GUID')] = settings_obj
            elif param == '104':
                aggregates[values.get('GUID')] = settings_obj
        return rules, aggregates, sequences

    def __sequence(self, sequences, key):
        if key not in sequences:
            return []
        return _get_list(self.__values(sequences[key]), 'RuleIDSequence')

    def get_rules(self):
        """
        Returns the rule tree: the rules and groups of the root, in the
        evaluation order (FWRule/FWGroup, a group holding its rules).
        """
        rules, aggregates, sequences = self.__index()
        agg_values = {guid: self.__values(obj) for guid, obj in aggregates.items()}

        def build(key):
            items = []
            for guid in self.__sequence(sequences, key):
                if guid not in rules:
                    continue
                values = self.__values(rules[guid])
                if values.get('Action') == FWRule.JUMP:
                    item = FWGroup.from_values(values, agg_values)
                    item.rules = build(guid)
                else:
                    item = FWRule.from_values(values, agg_values)
                items.append(item)
            return items
        return build('root')

    def get_all_rules(self):
        """
        Returns the rules and groups of all levels, in evaluation order.
        """
        return list(FWGroup('root', rules=self.get_rules()).walk())

    def get_rule(self, name_or_id):
        """
        Returns the first rule or group with this GUID or name (None if
        not found).
        """
        for rule in self.get_all_rules():
            if rule.id == name_or_id or rule.name.strip() == name_or_id.strip():
                return rule
        return None

    def __parent(self, sequences, guid):
        for key in sequences:
            if guid in self.__sequence(sequences, key):
                return key
        return None

    def __view_only(self, rules, key):
        return key != 'root' and key in rules and \
            self.__values(rules[key]).get('ViewOnly') == '1'

    def __group_key(self, rules, group):
        """
        Returns the GUID of a group given as FWGroup, name or GUID ('root'
        when None).
        """
        if group is None:
            return 'root'
        if isinstance(group, FWRule):
            group = group.id
        if group not in rules:
            found = self.get_rule(group)
            if found is None:
                raise ValueError('Group not found: {}'.format(group))
            group = found.id
        if self.__values(rules[group]).get('Action') != FWRule.JUMP:
            raise ValueError('Not a group: {}'.format(group))
        return group

    def __new_settings(self, name, param, values):
        policy_obj = self.root.find('EPOPolicyObject')
        section = {'100': '100', '101': '101', '104': 'AggregateCriterion'}[param]
        attrib = {'name': name, 'featureid': policy_obj.get('featureid'),
                  'categoryid': policy_obj.get('categoryid'), 'typeid': policy_obj.get('typeid'),
                  'param_int': param, 'param_str': section}
        settings_obj = et.Element('EPOPolicySettings', attrib)
        settings_obj.text = '\n'
        settings_obj.tail = '\n'
        et.SubElement(settings_obj, 'Section', {'name': section})
        self.__write_values(settings_obj, values)
        # The settings are listed before the EPOPolicyObject, as in exports.
        self.root.insert(list(self.root).index(policy_obj), settings_obj)
        et.SubElement(policy_obj, 'PolicySettings').text = name
        policy_obj[-1].tail = '\n'
        return settings_obj

    @staticmethod
    def __write_values(settings_obj, values):
        section_obj = settings_obj.find('Section')
        for setting in list(section_obj):
            section_obj.remove(setting)
        section_obj.text = '\n'
        section_obj.tail = '\n'
        for name in sorted(values):
            setting = et.SubElement(section_obj, 'Setting', {'name': name, 'value': values[name]})
            setting.tail = '\n'

    def __remove_settings(self, settings_obj):
        policy_obj = self.root.find('EPOPolicyObject')
        for ref in policy_obj.findall('PolicySettings'):
            if ref.text == settings_obj.get('name'):
                policy_obj.remove(ref)
        self.root.remove(settings_obj)

    def __write_sequence(self, sequences, key, guids):
        values = {} if key == 'root' else {'RuleListID': key}
        _set_list(values, 'RuleIDSequence', guids)
        if key in sequences:
            self.__write_values(sequences[key], values)
        else:
            name = '{}:Sequence:{}'.format(self.get_name(), key) if key != 'root' else \
                '{}::Settings ({})'.format(self.get_name(), _new_guid().upper())
            sequences[key] = self.__new_settings(name, '100', values)

    def __write_rule(self, rule, rules, aggregates, sequences):
        """
        Writes a rule/group and its aggregates; removes the aggregates it
        doesn't reference any more.
        """
        policy_name = self.get_name()
        old_refs = []
        if rule.id in rules:
            old_refs = _get_list(self.__values(rules[rule.id]), 'AggRef')
        for obj, kind in rule.all_aggregates():
            values = obj.to_values(kind) if isinstance(obj, FWNetwork) else obj.to_values()
            if obj.id in aggregates:
                self.__write_values(aggregates[obj.id], values)
            else:
                name = obj.remote_settings_name(policy_name) if kind == FWNetwork.REMOTE \
                    else obj.settings_name(policy_name)
                aggregates[obj.id] = self.__new_settings(name, '104', values)
        new_refs = [obj.id for obj, _ in rule.all_aggregates()]
        for ref in old_refs:
            if ref not in new_refs and ref in aggregates:
                self.__remove_settings(aggregates.pop(ref))
        if rule.id in rules:
            self.__write_values(rules[rule.id], rule.to_values())
        else:
            rules[rule.id] = self.__new_settings(rule.settings_name(policy_name), '101',
                                                 rule.to_values())
        rule._aggref = _get_list(rule.to_values(), 'AggRef')
        if rule.is_group and rule.id not in sequences:
            self.__write_sequence(sequences, rule.id, [])

    def __check_ids(self, rule, rules, aggregates, own_refs=()):
        """
        The GUIDs of a new rule and of its aggregates must not be used
        elsewhere in the policy.
        """
        for obj, _ in rule.all_aggregates():
            if obj.id in aggregates and obj.id not in own_refs:
                raise ValueError('"{}" is already used by another rule of the policy: '
                                 'add a copy (copy()) instead.'.format(obj.name))
        ids = [obj.id for obj, _ in rule.all_aggregates()]
        if len(ids) != len(set(ids)):
            raise ValueError('Rule "{}" uses the same object twice.'.format(rule.name))

    def add_rule(self, rule, group=None, position=None):
        """
        Add a rule or a group (FWRule/FWGroup, with the rules of the group)
        to the root or to a group (FWGroup, name or GUID), at a position
        (index in the group, at the end by default).
        """
        rules, aggregates, sequences = self.__index()
        key = self.__group_key(rules, group)
        if self.__view_only(rules, key):
            raise ValueError('The rules of a view only group cannot be changed.')
        items = [rule] + (list(rule.walk()) if rule.is_group else [])
        known = set(rules)
        for item in items:
            item.check()
            if item.id in known:
                raise ValueError('A rule with the ID {} already exists.'.format(item.id))
            known.add(item.id)
            self.__check_ids(item, rules, aggregates)
        for item in items:
            item.view_only = False
            item._extra['ViewOnly'] = '0'
            item.touch()
            self.__write_rule(item, rules, aggregates, sequences)
            if item.is_group:
                self.__write_sequence(sequences, item.id, [child.id for child in item.rules])
        guids = self.__sequence(sequences, key)
        guids.insert(len(guids) if position is None else position, rule.id)
        self.__write_sequence(sequences, key, guids)
        self.load_policy()
        return True

    def update_rule(self, rule):
        """
        Save a rule or group read with get_rules()/get_rule() and changed
        (its settings, networks, applications, location; not the rules of a
        group: see add/remove/move_rule).
        """
        rules, aggregates, sequences = self.__index()
        if rule.id not in rules:
            return False
        current = self.__values(rules[rule.id])
        if current.get('ViewOnly') == '1':
            raise ValueError('Rule "{}" is view only.'.format(rule.name))
        if (current.get('Action') == FWRule.JUMP) != rule.is_group:
            raise ValueError('A rule cannot become a group (or a group a rule).')
        stored = self.get_rule(rule.id)
        rule.check([obj for obj, _ in stored.all_aggregates()] if stored is not None else ())
        self.__check_ids(rule, rules, aggregates, _get_list(current, 'AggRef'))
        rule.touch()
        self.__write_rule(rule, rules, aggregates, sequences)
        self.load_policy()
        return True

    def __remove_tree(self, guid, rules, aggregates, sequences):
        for child in self.__sequence(sequences, guid):
            self.__remove_tree(child, rules, aggregates, sequences)
        if guid in sequences:
            self.__remove_settings(sequences.pop(guid))
        if guid in rules:
            for ref in _get_list(self.__values(rules[guid]), 'AggRef'):
                if ref in aggregates:
                    self.__remove_settings(aggregates.pop(ref))
            self.__remove_settings(rules.pop(guid))

    def remove_rule(self, rule):
        """
        Remove a rule or a group with all its rules (FWRule/FWGroup, name or
        GUID).
        """
        rules, aggregates, sequences = self.__index()
        guid = rule.id if isinstance(rule, FWRule) else rule
        if guid not in rules:
            found = self.get_rule(guid)
            if found is None:
                return False
            guid = found.id
        parent = self.__parent(sequences, guid)
        if self.__view_only(rules, parent):
            raise ValueError('The rules of a view only group cannot be changed.')
        if parent is not None:
            self.__write_sequence(sequences, parent, [item for item in
                                                      self.__sequence(sequences, parent)
                                                      if item != guid])
        self.__remove_tree(guid, rules, aggregates, sequences)
        self.load_policy()
        return True

    def move_rule(self, rule, group=None, position=None):
        """
        Move a rule or a group (FWRule/FWGroup, name or GUID) to the root or
        to a group (FWGroup, name or GUID), at a position (index in the
        group, at the end by default).
        """
        rules, aggregates, sequences = self.__index()
        guid = rule.id if isinstance(rule, FWRule) else rule
        if guid not in rules:
            found = self.get_rule(guid)
            if found is None:
                raise ValueError('Rule not found: {}'.format(guid))
            guid = found.id
        key = self.__group_key(rules, group)
        parent = self.__parent(sequences, guid)
        if self.__view_only(rules, parent) or self.__view_only(rules, key):
            raise ValueError('The rules of a view only group cannot be changed.')
        # A group can't be moved into itself or into one of its groups.
        ancestor = key
        while ancestor not in [None, 'root']:
            if ancestor == guid:
                raise ValueError('A group cannot be moved into itself.')
            ancestor = self.__parent(sequences, ancestor)
        self.__write_sequence(sequences, parent, [item for item in
                                                  self.__sequence(sequences, parent)
                                                  if item != guid])
        guids = self.__sequence(sequences, key)
        guids.insert(len(guids) if position is None else position, guid)
        self.__write_sequence(sequences, key, guids)
        self.load_policy()
        return True

    def print_info(self):
        """
        Print information about the current loaded policy object.
        """
        print('Policy {} has {} sequences, {} rules and {} aggregates.'.format(
              self.get_name(), len(self.seq), len(self.rul), len(self.agg)))

    def print_sequences(self, seq_id = 'root', level = 0, header = ''):
        """
        DRAFT - Print the current firewall policy.
        """
        seq_list = self.seq[seq_id]
        for seq in seq_list:
            intf = self.rul[seq].get('PhysicalMedium', 'All')
            if intf != 'All':
                if len(intf) == 3:
                    intf = 'All'
                else:
                    intf = ','.join(intf)
            if self.rul[seq]['Action'] == "JUMP":
                print('{}+-- {}/'.format(header, self.rul[seq]['Name']))
                agg_ref = self.rul[seq].get('AggRef', None)
                if agg_ref is not None:
                    agg_ref = agg_ref[0]
                    print('{}--> Name: {}, Direction: {}, Interfaces: {}'.format(header+'|   ',
                            self.agg[agg_ref]['Name'], self.rul[seq]['Direction'], intf))
            else:
                print('{}+-- {}'.format(header, self.rul[seq]['Name']))
                print('{}--> Action: {}, Direction: {}'.format(
                      header+'|   ', self.rul[seq]['Action'], self.rul[seq]['Direction']))
                print('{}--> Interfaces: {} Protocol: {}'.format(
                      header+'|   ', intf, self.rul[seq].get('TransportProtocol', 'Any')))
            if self.seq.__contains__(seq):
                self.print_sequences(seq, level+1, header+'|   ')

    def get_sequences(self, seq_id = 'root'):
        """
        DRAFT - Return all the rules within a global Json dictionary.
        """
        if seq_id == 'root':
            item = dict()
            item['Action'] = 'ROOT'
            children = list()
            for seq in self.seq[seq_id]:
                children.append(self.get_sequences(seq))
            item['Children'] = children
        else:
            item = self.rul[seq_id]
            # Does this rule contains Aggregate references, if so proceed in consequence
            agg_ref = item.get('AggRef', None)
            if agg_ref is not None:
                aggregates = list()
                for ref in agg_ref:
                    aggregates.append(self.agg[ref])
                item['AggRef'] = aggregates
            # If this sequence contains other sequences so proceeed in consequence
            if self.seq.__contains__(seq_id):
                children = list()
                for seq in self.seq[seq_id]:
                    children.append(self.get_sequences(seq))
                item['Children'] = children
        return item

    def get_toc(self, seq_id = 'root', level = 0, header = ''):
        """
        DRAFT - Return the table of content in Markdown format.
        """
        toc = ''
        seq_list = self.seq[seq_id]
        for seq in seq_list:
            rul = self.rul[seq]
            toc += '{}- [{}](#{})'.format(header, self.md_heading(rul['Name']), rul['GUID'])
            if rul['Action'] == "JUMP":
                toc += '/'
            toc += '\r\n'
            if self.seq.__contains__(seq):
                toc += self.get_toc(seq, level+1, header+'  ')
        return toc

    def __get_connection_type(self, rul_seq):
        intf = self.rul[rul_seq].get('PhysicalMedium', 'All')
        if intf != 'All':
            if len(intf) == 3:
                intf = 'All'
            elif len(intf) == 2:
                intf = ' or '.join(intf)
            else:
                intf = intf[0]
        if intf == 'All':
            intf = 'All types (Wired, Wireless, Virtual)'
        return intf

    def __get_last_changed(self, rul_seq):
        txt = 'By ' + self.rul[rul_seq]['LastModifyingUsername'] + ' on '
        dt_str = self.rul[rul_seq]['LastModified']
        dt_obj = dt.datetime.strptime(dt_str, '%Y-%m-%dT%H:%M:%S.%f%z')
        txt += dt_obj.strftime('%Y/%m/%d at %H:%M:%S %Z.')
        return txt

    def __get_protocol(self, rul_seq):
        # TransportProtocol (example: '6')
        #   Users can select only one TransportProtocol
        tp = self.rul[rul_seq].get('TransportProtocol', 'All Protocols')
        if not tp == 'All Protocols':
            ips = InternetProtocols()
            tp = ips.get_name(tp[0])

        # NetworkProtocol (example: '2048', '34525')
        #   Users can select only one NetworkProtocol
        #   except for IPv4 and IPv6
        np = self.rul[rul_seq].get('NetworkProtocol', 'Any')
        if not np == 'Any':
            nps = NetworkProtocols()
            txt = tp + '/' + nps.get_name(np[0])
            if len(np) == 2:
                txt += ', ' + tp + '/' + nps.get_name(np[1])
        else:
            txt = tp + '/Any'

        # In case of ICMP or ICMPv6 MessageType is defined.
        #   The value is empty when All messages are defined.
        #   Users can select only one MessageType
        mt = self.rul[rul_seq].get('MessageType')
        if tp == 'ICMP' or tp == 'ICMPv6':
            txt += '\r\nMessage Type: ' + self.__get_message_type(tp, mt)

        return txt

    def __get_message_type(self, transport, message_type):
        # No MessageType setting, an empty value or '255' (checked in the
        # ePO 5.10 rule editor): all message types. Unknown codes are shown as is.
        if not message_type or message_type[0] in ['', '255']:
            return 'All'
        mts = MessageTypes() if transport == 'ICMP' else MessageTypesv6()
        name = mts.get_name(message_type[0])
        return name if name != 'None' else 'Type {}'.format(message_type[0])

    def __get_ipaddress(self, str_ip):
        txt = str_ip
        if str_ip.isalnum():
            # This is a hostname
            pass
        elif len(str_ip.split('.')) > 1:
            # This is a domain
            pass
        elif str_ip == '[trusted]':
            # This is an internal object
            txt = 'Defined Networks (trusted)'
        elif len(str_ip.split('/')) > 1:
            # This is subnet
            ip1, sub = str_ip.split('/')
            ip1_addr = ip.ip_address(ip1)
            if ip1_addr.ipv4_mapped is not None:
                txt = str(ip1_addr.ipv4_mapped) + '/' + str(int(sub)-96)
        elif len(str_ip.split('-')) > 1:
            # This is a subnet range
            ip1, ip2 = str_ip.split('-')
            ip1_addr = ip.ip_address(ip1)
            ip2_addr = ip.ip_address(ip2)
            if ip1_addr.ipv4_mapped is not None:
                txt = str(ip1_addr.ipv4_mapped) + '-' + str(ip2_addr.ipv4_mapped)
        else:
            # This is a single ip
            ip_addr = ip.ip_address(str_ip)
            if ip_addr.ipv4_mapped is not None:
                txt = str(ip_addr.ipv4_mapped)
        return txt

    def __get_location(self, agg_ref):
        txt = ''
        agg = self.agg[agg_ref]
        txt = '  - Name: ' + self.md_heading(agg['Name']) + '\r\n'
        txt += '  - Isolated: '
        txt += 'Yes\r\n' if agg['Isolated'] == '1' else 'No\r\n'
        txt += '  - Require ePO Reachability: '
        txt += 'Yes\r\n' if agg['RequireEpoReachable'] == '1' else 'No\r\n'
        # Print Default Gateway
        dgs = agg.get('DefaultGateway', None)
        if dgs is not None:
            txt += '  - Default Gateway:\r\n'
            for dg in dgs:
                txt += '    - ' + self.md_heading(self.__get_ipaddress(dg)) + '\r\n'
        # Print DHCP Server
        dss = agg.get('DhcpServer', None)
        if dss is not None:
            txt += '  - DHCP Server:\r\n'
            for ds in dss:
                txt += '    - ' + self.md_heading(self.__get_ipaddress(ds)) + '\r\n'
        # Print DNS Server
        dns = agg.get('DnsServer', None)
        if dns is not None:
            txt += '  - DNS Server:\r\n'
            for ds in dns:
                txt += '    - ' + self.md_heading(self.__get_ipaddress(ds)) + '\r\n'
        # Print DNS Suffix
        dsu = agg.get('DnsSuffix', None)
        if dsu is not None:
            txt += '  - DNS Suffix:\r\n'
            for ds in dsu:
                txt += '    - ' + self.md_heading(ds) + '\r\n'
        # Print Primary WINS Server
        pws = agg.get('PrimaryWINS', None)
        if pws is not None:
            txt += '  - Primary WINS Server:\r\n'
            for ds in pws:
                txt += '    - ' + self.md_heading(self.__get_ipaddress(ds)) + '\r\n'
        # Print Secondary WINS Server
        sws = agg.get('SecondaryWINS', None)
        if sws is not None:
            txt += '  - Secondary WINS Server:\r\n'
            for ds in sws:
                txt += '    - ' + self.md_heading(self.__get_ipaddress(ds)) + '\r\n'
        # Print Domain reachability (HTTPS)
        drs = agg.get('DomainReachable', None)
        if drs is not None:
            txt += '  - Domain reachability (HTTPS):\r\n'
            for ds in drs:
                txt += '    - ' + self.md_heading(ds) + '\r\n'
        # Print Registry Key/Value
        reg_key = agg.get('RegKey', None)
        if reg_key is not None:
            txt += '  - Registry Key: ' + self.md_heading(reg_key[0]) + '\r\n'
        return txt

    def __get_local_networks(self, agg_ref):
        txt = ''
        is_local = False
        if agg_ref is not None:
            tmp = ''
            for ref in agg_ref:
                obj = self.agg[ref]
                lns = obj.get('LocalAddress', None)
                if lns is not None:
                    is_local = True
                    tmp += '  - ' + self.md_heading(obj['Name']) + ':\r\n'
                    for ln in lns:
                        tmp += '    - ' + self.md_heading(self.__get_ipaddress(ln)) + '\r\n'
        if is_local:
            txt = 'Local networks:\r\n' + tmp
        return txt

    def __get_local_port(self, seq):
        txt = ''
        lp = self.rul[seq].get('LocalPort', None)
        if lp is not None:
            txt += 'Local port: ' + self.md_heading(lp[0]) + '\r\n'
        return txt

    def __get_remote_networks(self, agg_ref):
        txt = ''
        is_remote = False
        if agg_ref is not None:
            tmp = ''
            for ref in agg_ref:
                obj = self.agg[ref]
                rns = obj.get('RemoteAddress', None)
                if rns is not None:
                    is_remote = True
                    tmp += '  - ' + self.md_heading(obj['Name']) + ':\r\n'
                    for rn in rns:
                        tmp += '    - ' + self.md_heading(self.__get_ipaddress(rn)) + '\r\n'
        if is_remote:
            txt = 'Remote networks:\r\n' + tmp
        return txt

    def __get_remote_port(self, seq):
        txt = ''
        rp = self.rul[seq].get('RemotePort', None)
        if rp is not None:
            txt += 'Remote port: ' + self.md_heading(rp[0]) + '\r\n'
        return txt

    def __get_scheduled(self, seq):
        txt = ''
        # Does a schedule is defined?
        rul = self.rul[seq]
        if rul.get('ScheduleEnabled') == '1':
            # Print Scheduled status
            txt += 'Scheduled status: Enabled\r\n'
            # Print Scheduled days (WeekMask bits, Sunday = 1)
            mask = int(rul.get('WeekMask', '0'))
            days = [day for bit, day in FWRule.DAYS[1:] + FWRule.DAYS[:1] if mask & bit]
            txt += 'Scheduled days: ' + ', '.join(days) + '\r\n'
            # Print Start time
            txt += 'Start time: ' + self.__schedule_time(rul, 'Start') + '\r\n'
            # Print End time
            txt += 'End time: ' + self.__schedule_time(rul, 'End') + '\r\n'
        return txt

    @staticmethod
    def __schedule_time(rul, which):
        # StartTime/EndTime are not used by the console (always 0:00/23:59).
        return '{:02d}:{:02d}'.format(int(rul.get('Schedule{}Hours'.format(which), '0')),
                                      int(rul.get('Schedule{}Minutes'.format(which), '0')))

    def get_content(self, seq_id = 'root', level = 0, header = '', toc = False):
        """
        DRAFT - Get the content of a policy in Markdown format.
        """
        txt = ''
        seq_list = self.seq[seq_id]
        for seq in seq_list:
            rul = self.rul[seq]
            # Print Title
            if toc:
                txt += '<div id="{}" />\r\n'.format(rul['GUID'])
            txt += '#' + '#'*level + ' '  #-- Heading is computed based on the level
            txt += self.md_heading(rul['Name'])

            # Is it a folder?
            if rul['Action'] == "JUMP":
                # This is a folder so print a slash at the end
                txt += '/\r\n\r\n'
            else:
                # This is a rule so print the rule settings
                txt += '\r\n\r\n'
                txt += 'Status: '
                txt += 'Enabled\r\n' if rul['Enabled'] == '1' else 'Disabled\r\n'
                txt += 'Action: ' + rul['Action'] + '\r\n'
                txt += 'Treat match as intrusion: '
                txt += 'Yes\r\n' if rul['Intrusion'] == '1' else 'No\r\n'
                txt += 'Log matching traffic: '
                txt += 'Yes\r\n' if rul['Logged'] == '1' else 'No\r\n'

            # Print the common section
            txt += 'Direction: ' + rul['Direction'] + '\r\n'
            txt += 'Connection type: ' + self.__get_connection_type(seq) + '\r\n'
            txt += 'Protocol: ' + self.__get_protocol(seq) + '\r\n'

            agg_ref = rul.get('AggRef', None)
            # Is it a folder?
            if rul['Action'] == "JUMP":
                # This is a folder so, check if a location is defined
                if agg_ref is not None:
                    # Print the location
                    txt += 'Location:\r\n' + self.__get_location(agg_ref[0])
            else:
                # This is a rule, continu to print settings
                # Print Local networks
                txt += self.__get_local_networks(agg_ref)
                # Print Local port
                txt += self.__get_local_port(seq)
                # Print Remote networks
                txt += self.__get_remote_networks(agg_ref)
                # Print Remote port
                txt += self.__get_remote_port(seq)
                # Is this rule a scheduled one
                txt += self.__get_scheduled(seq)

            # Print end of the common section
            txt += 'Note: ' + self.md_escape(rul['Note']) + '\r\n'
            txt += 'Last Changed: ' + self.md_heading(self.__get_last_changed(seq)) + '\r\n'
            txt += '\r\n'

            #  Is there a child sequence under the current one ?
            if self.seq.__contains__(seq):
                # If yes, run recurcively the function to display all the children.
                txt += self.get_content(seq, level+1, header+'  ')
        return txt

    # ------------------------------ Markdown export ------------------------------
    # Rule base documented as a firewall review: a summary table numbering
    # the groups/rules in evaluation order (1, 1.1, 1.2...), then one detail
    # card per group/rule. See Policy.to_markdown().
    # Monday first, as in the console rule editor (WeekMask: Sunday = 1).
    __MD_DAYS = FWRule.DAYS[1:] + FWRule.DAYS[:1]

    def __md_walk(self, seq_id='root', prefix=''):
        """
        Returns the (number, rule GUID, depth) of every group/rule, in
        evaluation order.
        """
        items = []
        for index, seq in enumerate(self.seq.get(seq_id, []), 1):
            number = '{}{}'.format(prefix, index)
            items.append((number, seq, number.count('.')))
            if seq in self.seq:
                items += self.__md_walk(seq, number + '.')
        return items

    def __md_aggregates(self, rul, key):
        """
        Returns the aggregates (network/application objects) of a rule
        holding the property key, e.g. 'LocalAddress', 'RemoteAddress', 'AppName'.
        """
        return [self.agg[ref] for ref in rul.get('AggRef', []) or []
                if ref in self.agg and key in self.agg[ref]]

    def __md_networks(self, rul, key):
        """
        Returns the local/remote networks of a rule ('Any' if none).
        """
        networks = ['{}: {}'.format(agg['Name'], ', '.join(self.__get_ipaddress(addr)
                                                           for addr in agg[key]))
                    for agg in self.__md_aggregates(rul, key)]
        return '\n'.join(networks) if networks else 'Any'

    def __md_ports(self, rul, key):
        ports = [port for port in rul.get(key, None) or [] if port]
        return ', '.join(ports) if ports else 'Any'

    def __md_applications(self, rul):
        """
        Returns the applications of a rule: name, then path, signer and
        MD5 hash when defined ('All' if none).
        """
        apps = []
        for agg in self.__md_aggregates(rul, 'AppName'):
            for index, name in enumerate(agg['AppName']):
                details = []
                for key, label in [('AppPath', 'path'), ('AppSigner', 'signer'),
                                   ('AppHash', 'MD5')]:
                    values = agg.get(key, [])
                    value = values[index] if index < len(values) else ''
                    if value and value.strip('0'):
                        details.append('{}: {}'.format(label, value))
                apps.append('{} ({})'.format(name, ', '.join(details)) if details else name)
        return '\n'.join(apps) if apps else 'All'

    def __md_protocols(self, rul):
        """
        Returns (network protocol, transport protocol) labels.
        """
        # Labels of the console rule editor ("Any protocol", "IPv4 protocol"...).
        network = rul.get('NetworkProtocol', None)
        names = [NetworkProtocols().get_name(ref) for ref in network or []]
        network = 'Any protocol' if not names else ', '.join(
            name + ' protocol' if name in ['IPv4', 'IPv6'] else name for name in names)
        transport = rul.get('TransportProtocol', None)
        transport = 'All Protocols' if not transport else InternetProtocols().get_name(
            transport[0])
        if transport in ['ICMP', 'ICMPv6']:
            message = self.__get_message_type(transport, rul.get('MessageType', None))
            transport += ' (all message types)' if message == 'All' else ' ({})'.format(message)
        return network, transport

    def __md_schedule(self, rul):
        if rul.get('ScheduleEnabled') != '1':
            return 'No'
        mask = int(rul.get('WeekMask', '0'))
        days = [day for bit, day in self.__MD_DAYS if mask & bit]
        return '{} from {} to {}'.format(', '.join(days), self.__schedule_time(rul, 'Start'),
                                         self.__schedule_time(rul, 'End'))

    def __md_location(self, agg):
        """
        Returns the rows of a location (group aggregate), its name being in
        the header line of the group card.
        """
        check = self.md_check
        rows = [['Isolate this connection', check(agg.get('Isolated'))],
                ['Require ePO reachability', check(agg.get('RequireEpoReachable'))]]
        for key, label in [('DnsSuffix', 'Connection-specific DNS suffix'),
                           ('DefaultGateway', 'Default gateway'),
                           ('DhcpServer', 'DHCP server'), ('DnsServer', 'DNS server'),
                           ('PrimaryWINS', 'Primary WINS server'),
                           ('SecondaryWINS', 'Secondary WINS server'),
                           ('DomainReachable', 'Domain reachability (HTTPS)'),
                           ('RegKey', 'Registry key')]:
            values = agg.get(key, None)
            if values:
                if key in ['DefaultGateway', 'DhcpServer', 'DnsServer', 'PrimaryWINS',
                           'SecondaryWINS']:
                    values = [self.__get_ipaddress(value) for value in values]
                rows.append([label, '\n'.join(values)])
        return rows

    def __md_card(self, header, items):
        """
        Returns the detail card of a group or rule as one compact two-column
        table, to keep the document short: the two main settings in the
        header line (e.g. "Status: Enabled | Action: Allow"), then the other
        settings two per line, each cell "**Label:** value" (Markdown tables
        can't span columns). A None item leaves its cell empty.
        """
        cell = lambda item: '' if item is None else '**{}:** {}'.format(
            item[0], self.md_escape(item[1])).rstrip()
        lines = ['| ' + ' | '.join(self.md_escape(value) for value in header) + ' |', '|---|---|']
        for index in range(0, len(items), 2):
            pair = list(items[index:index + 2]) + [None]
            lines.append('| {} | {} |'.format(cell(pair[0]), cell(pair[1])).replace('|  |', '| |'))
        return '\n'.join(lines) + '\n'

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples:
        rules summary and rule details (see Policy.to_markdown).
        """
        if not self.seq:
            self.load_policy()
        walk = self.__md_walk()
        summary = []
        details = ''
        for number, seq, depth in walk:
            rul = self.rul[seq]
            is_group = rul['Action'] == 'JUMP'
            name = rul['Name'].strip()
            network, transport = self.__md_protocols(rul)
            status = 'Enabled' if rul.get('Enabled', '1') == '1' else 'Disabled'
            if is_group:
                summary.append([number, '[Group] {}'.format(name), status, '',
                                rul['Direction'].capitalize(), network, transport,
                                '', '', '', ''])
            else:
                local = self.__md_networks(rul, 'LocalAddress')
                remote = self.__md_networks(rul, 'RemoteAddress')
                summary.append([number, name, status, rul['Action'].capitalize(),
                                rul['Direction'].capitalize(), network, transport,
                                '{} (port {})'.format(local, self.__md_ports(rul, 'LocalPort')),
                                '{} (port {})'.format(remote, self.__md_ports(rul, 'RemotePort')),
                                self.__md_applications(rul), self.md_check(rul.get('Logged'))])
            details += '\n### {} {}{}\n\n'.format(number, self.md_heading(name),
                                                     ' (group)' if is_group else '')
            direction = rul['Direction'].capitalize()
            protocols = [('Network protocol', network), ('Transport protocol', transport)]
            last = [('Notes', rul.get('Note', '')),
                    ('Last changed', self.__get_last_changed(seq).rstrip('.'))]
            if is_group:
                locations = [self.agg[ref] for ref in rul.get('AggRef', []) or []
                             if ref in self.agg and 'Isolated' in self.agg[ref]]
                rules = len([item for item in walk if item[0].startswith(number + '.')
                             and self.rul[item[1]]['Action'] != 'JUMP'])
                header = ['Status: ' + status, 'Direction: ' + direction]
                items = [('Location', ', '.join(agg['Name'] for agg in locations) or 'None'),
                         ('Rules', rules),
                         ('Connection types', self.__get_connection_type(seq))] + protocols
                for agg in locations:
                    items += [tuple(row) for row in self.__md_location(agg)]
                if len(items) % 2:
                    items.append(None)  # Notes and Last changed on the same line
            else:
                header = ['Status: ' + status, 'Action: ' + rul['Action'].capitalize()]
                items = [('Direction', direction), ('Log', self.md_check(rul.get('Logged'))),
                         ('Treat match as intrusion', self.md_check(rul.get('Intrusion'))),
                         ('Connection types', self.__get_connection_type(seq))] + protocols + [
                    ('Local networks', self.__md_networks(rul, 'LocalAddress')),
                    ('Local port', self.__md_ports(rul, 'LocalPort')),
                    ('Remote networks', self.__md_networks(rul, 'RemoteAddress')),
                    ('Remote port', self.__md_ports(rul, 'RemotePort')),
                    ('Applications', self.__md_applications(rul)),
                    ('Schedule', self.__md_schedule(rul))]
            details += self.__md_card(header, items + last)
        groups = len([item for item in walk if self.rul[item[1]]['Action'] == 'JUMP'])
        text = 'Rules are evaluated from top to bottom; the first rule matching the ' \
               'traffic applies. {} rule(s) in {} group(s).\n\n'.format(
                   len(walk) - groups, groups)
        text += self.md_table(['#', 'Name', 'Status', 'Action', 'Direction', 'Network protocol',
                               'Transport protocol', 'Local', 'Remote', 'Applications', 'Log'],
                              summary)
        platforms = 'Treat match as intrusion and Schedule: Windows & Linux only. ' \
                    'Applications: Windows & Mac only.\n\n'
        return [('Rules summary', text), ('Rule details', platforms + details.lstrip('\n'))]
