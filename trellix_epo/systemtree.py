# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the System Tree of ePO as objects, without a server:
System (a managed system, read from system.find or system.find.multiple),
Group (a System Tree group, read from system.findGroups or the
EPOBranchNode table) and the group paths ("My Organization\\Workstations").

>>> system = System.from_json({'EPOComputerProperties.ParentID': 4,
...     'EPOComputerProperties.ComputerName': 'PC01', 'EPOBranchNode.AutoID': 6,
...     'EPOLeafNode.Tags': 'Escalated, Workstation', 'EPOLeafNode.ManagedState': 1,
...     'EPOComputerProperties.OSBitMode': 1, 'EPOComputerProperties.UserProperty1': 'PROD'})
>>> system
<System PC01 (4, group 6)>
>>> system.tags, system.managed, system.is_64bit, system.custom1
(['Escalated', 'Workstation'], True, True, 'PROD')
>>> normalize_path('\\\\Workstations\\\\')
'My Organization\\\\Workstations'

PROPERTIES is the reference of the library for the system properties (SQUID
key, console label, kind, drop-down values): the Computer Properties of the
tag criteria (tagcatalog) are built from it; criteria_property('custom1') is
the TagProperty to tag the systems on the Custom 1 field.

The operations on a server (epo.systems: find, add, move, properties,
delete; epo.groups: list, systems, create) are in the eposystemtree module.

Two rules of the System Tree:
- a system id (EPOLeafNode.AutoID, the ParentID of EPOComputerProperties)
  and a group id (EPOBranchNode.AutoID) are two separate sequences: system
  13 and group 13 can both exist;
- nothing is created in or moved to Lost and Found or its subgroups: the
  server fills it with the systems deployed outside the console at their
  first connection (check_destination()).
"""

import datetime

from .policies import Policy

# Root group of the System Tree, and the "Lost and Found" group directly
# under it, which the EPOBranchNode table (and the assignment rule
# expressions) write with its internal name.
ROOT_GROUP = 'My Organization'
LOST_AND_FOUND = 'Lost and Found'
LOST_AND_FOUND_INTERNAL = 'Lost&Found'

# Group types (EPOBranchNode.Type).
GLOBAL_ROOT = 7
ROOT_TYPE = 4
LOST_AND_FOUND_TYPE = 5
GROUP_TYPE = 3

# Kinds of property, named after the console display types of the tag
# criteria builder (tagcatalog.KINDS gives their operators).
ENUM = 'enum'                   # drop-down list of numbers (0 No, 1 Yes, -1 Unknown...)
TEXT = 'text'                   # free text, 100 characters
INTEGER = 'integer'             # number, 10 digits
LOOKUP = 'lookup'               # free text with a list of known values, 255 characters
STRING_ENUM = 'string_enum'     # drop-down list of texts (languages, management types)
MEGABYTES = 'megabytes'         # size stored in MB (disk space)
BYTES = 'bytes'                 # size stored in bytes (memory)
IPV4 = 'ipv4'                   # IPv4 address (deprecated ePO column)
IPV6 = 'ipv6'                   # IPv6 or IPv4 address
TIMESTAMP = 'timestamp'         # date and time
VERSION2 = 'version2'           # "Product Version (Fast)": version stored as a number
VERSION = 'version'             # product version text, compared part by part

# The system properties: (attribute of System, SQUID key, console label,
# kind, offered by the tag criteria builder). This is the reference of the
# library for the system properties: the "Computer Properties" of the tag
# criteria (tagcatalog.PROPERTIES) are built from it, in this order (the
# order of the criteria builder), so a property added here is known by the
# tags too. The labels are the ones of the console (criteria builder, or
# core.executeQuery with :output=verbose for the others).
PROPERTIES = (
    ('agent_handler', 'EPOComputerProperties.LastAgentHandler', 'Agent Handler', ENUM, True),
    ('cpu_serial_number', 'EPOComputerProperties.CPUSerialNumber', 'CPU Serial Number', TEXT, True),
    ('cpu_speed', 'EPOComputerProperties.CPUSpeed', 'CPU Speed (MHz)', INTEGER, True),
    ('cpu_type', 'EPOComputerProperties.CPUType', 'CPU Type', LOOKUP, True),
    ('custom1', 'EPOComputerProperties.UserProperty1', 'Custom 1', TEXT, True),
    ('custom2', 'EPOComputerProperties.UserProperty2', 'Custom 2', TEXT, True),
    ('custom3', 'EPOComputerProperties.UserProperty3', 'Custom 3', TEXT, True),
    ('custom4', 'EPOComputerProperties.UserProperty4', 'Custom 4', TEXT, True),
    ('custom5', 'EPOComputerProperties.UserProperty5', 'Custom 5', TEXT, True),
    ('custom6', 'EPOComputerProperties.UserProperty6', 'Custom 6', TEXT, True),
    ('custom7', 'EPOComputerProperties.UserProperty7', 'Custom 7', TEXT, True),
    ('custom8', 'EPOComputerProperties.UserProperty8', 'Custom 8', TEXT, True),
    ('default_language', 'EPOComputerProperties.DefaultLangID', 
     'Default Language', STRING_ENUM, True),
    ('description', 'EPOComputerProperties.Description', 'Description', TEXT, True),
    ('dns_name', 'EPOComputerProperties.IPHostName', 'DNS Name', TEXT, True),
    ('domain_name', 'EPOComputerProperties.DomainName', 'Domain Name', LOOKUP, True),
    ('email_address', 'EPOComputerProperties.EmailAddress', 'Email Address', TEXT, True),
    ('free_c_space', 'EPOComputerProperties.Free_Space_of_Drive_C', 
     'Free C Drive Space', MEGABYTES, True),
    ('free_disk_space', 'EPOComputerProperties.FreeDiskSpace', 'Free Disk Space', MEGABYTES, True),
    ('free_memory', 'EPOComputerProperties.FreeMemory', 'Free Memory', BYTES, True),
    ('ipv4_number', 'EPOComputerProperties.IPV4x', 'IP4 Address (deprecated)', IPV4, True),
    ('ipv6_address', 'EPOComputerProperties.IPV6', 'IP address', IPV6, True),
    ('ipx_address', 'EPOComputerProperties.IPXAddress', 'IPX Address', TEXT, True),
    ('is_64bit', 'EPOComputerProperties.OSBitMode', 'Is 64-bit OS', ENUM, True),
    ('is_laptop', 'EPOComputerProperties.IsPortable', 'Is Laptop', ENUM, True),
    ('last_communication_text', 'EPOComputerProperties.LastUpdate', 
     'Last Communication', TEXT, True),
    ('last_boot_time', 'EPOComputerProperties.SystemBootTime', 
     'Last System Boot Time', TIMESTAMP, True),
    ('mac_address', 'EPOComputerProperties.NetAddress', 'MAC Address', TEXT, True),
    ('management_type', 'EPOComputerProperties.ManagementType', 
     'Management Type', STRING_ENUM, True),
    ('cpu_count', 'EPOComputerProperties.NumOfCPU', 'Number Of CPUs', INTEGER, True),
    ('ethernet_mac_count', 'EPOComputerProperties.EthernetMacAddressCount', 
     'Number of Ethernet MAC Address', INTEGER, True),
    ('hard_drive_count', 'EPOComputerProperties.NumOfHardDrives', 
     'Number of Hard Drives', INTEGER, True),
    ('other_mac_count', 'EPOComputerProperties.OtherMacAddressCount', 
     'Number of Other MAC Address', INTEGER, True),
    ('wireless_mac_count', 'EPOComputerProperties.WirelessMacAddressCount', 
     'Number of Wireless MAC Address', INTEGER, True),
    ('os_build_number', 'EPOComputerProperties.OSBuildNum', 'OS Build Number', INTEGER, True),
    ('os_oem_id', 'EPOComputerProperties.OSOEMID', 'OS OEM Identifier', LOOKUP, True),
    ('os_platform', 'EPOComputerProperties.OSPlatform', 'OS Platform', LOOKUP, True),
    ('os_service_pack', 'EPOComputerProperties.OSCsdVersion', 
     'OS Service Pack Version', LOOKUP, True),
    ('os_type', 'EPOComputerProperties.OSType', 'OS Type', LOOKUP, True),
    ('os_version', 'EPOComputerProperties.OSVersion', 'OS Version', LOOKUP, True),
    ('platform_id', 'EPOComputerProperties.PlatformID', 'Platform ID', TEXT, True),
    ('reboot_pending', 'EPOComputerProperties.SystemRebootPending', 'Reboot Pending', ENUM, True),
    ('smbios_uuid', 'EPOComputerProperties.SMBiosUUID', 'SMBios UUID', TEXT, True),
    ('ipv6_subnet', 'EPOComputerProperties.IPSubnet', 'Subnet Address', IPV6, True),
    ('subnet_address', 'EPOComputerProperties.SubnetAddress', 
     'Subnet Address (deprecated)', TEXT, True),
    ('ipv6_subnet_mask', 'EPOComputerProperties.IPSubnetMask', 'Subnet Mask', IPV6, True),
    ('subnet_mask', 'EPOComputerProperties.SubnetMask', 'Subnet Mask (deprecated)', TEXT, True),
    ('system_description', 'EPOComputerProperties.ComputerDescription', 
     'System Description', TEXT, True),
    ('system_manufacturer', 'EPOComputerProperties.SystemManufacturer', 
     'System Manufacturer', TEXT, True),
    ('system_model', 'EPOComputerProperties.SystemModel', 'System Model', TEXT, True),
    ('name', 'EPOComputerProperties.ComputerName', 'System Name', TEXT, True),
    ('system_serial_number', 'EPOComputerProperties.SystemSerialNumber', 
     'System Serial Number', TEXT, True),
    ('time_zone', 'EPOComputerProperties.TimeZone', 'Time Zone', LOOKUP, True),
    ('total_c_space', 'EPOComputerProperties.Total_Space_of_Drive_C', 
     'Total C Drive Space', MEGABYTES, True),
    ('total_disk_space', 'EPOComputerProperties.TotalDiskSpace', 
     'Total Disk Space', MEGABYTES, True),
    ('total_memory', 'EPOComputerProperties.TotalPhysicalMemory', 
     'Total Physical Memory', BYTES, True),
    ('user_name', 'EPOComputerProperties.UserName', 'User Name', TEXT, True),
    ('vdi', 'EPOComputerProperties.Vdi', 'VDI', ENUM, True),
    ('id', 'EPOComputerProperties.ParentID', 'System ID', INTEGER, False),
    ('ip_address', 'EPOComputerProperties.IPAddress', 'IP address', TEXT, False),
    ('tags', 'EPOLeafNode.Tags', 'Tags', TEXT, False),
    ('excluded_tags', 'EPOLeafNode.ExcludedTags', 'Excluded Tags', TEXT, False),
    ('last_communication', 'EPOLeafNode.LastUpdate', 'Last Communication', TIMESTAMP, False),
    ('managed_state', 'EPOLeafNode.ManagedState', 'Managed State', ENUM, False),
    ('agent_guid', 'EPOLeafNode.AgentGUID', 'Trellix Agent GUID', TEXT, False),
    ('agent_version', 'EPOLeafNode.AgentVersion', 'Agent Version', LOOKUP, False),
    ('group_id', 'EPOBranchNode.AutoID', 'Group', INTEGER, False),
    ('products', 'EPOProductPropertyProducts.Products', 'Installed Products', TEXT, False),
    ('installed', 'EPOProductProperties.lastInstalled', 
     'Product list last installation time', TEXT, False),
    ('is_domain_controller', 'EPOExtendedComputerPropsVw.PropValue', 
     'isDomainController', TEXT, False),
)

# The fields of system.find (ePO 5.10 Update 6 and later), in its order:
# attribute of System -> SQUID key. The other properties (email_address,
# system_model, reboot_pending...) are given by core.executeQuery only.
_KEYS = {attribute: key for attribute, key, _, _, _ in PROPERTIES}
FIELDS = {attribute: _KEYS[attribute] for attribute in (
    'id', 'name', 'description', 'system_description', 'time_zone', 'default_language',
    'user_name', 'domain_name', 'dns_name', 'ipv6_address', 'ip_address', 'ipv6_subnet',
    'ipv6_subnet_mask', 'ipv4_number', 'ipx_address', 'subnet_address', 'subnet_mask',
    'mac_address', 'os_type', 'os_version', 'os_service_pack', 'os_build_number', 'os_oem_id',
    'cpu_type', 'cpu_speed', 'cpu_count', 'cpu_serial_number', 'total_memory', 'free_memory',
    'free_disk_space', 'total_disk_space', 'is_laptop', 'vdi', 'is_64bit', 'agent_handler',
    'custom1', 'custom2', 'custom3', 'custom4', 'custom5', 'custom6', 'custom7', 'custom8',
    'free_c_space', 'total_c_space', 'tags', 'excluded_tags', 'last_communication',
    'managed_state', 'agent_guid', 'agent_version', 'group_id', 'os_platform', 'products',
    'installed', 'is_domain_controller')}

# All the attributes of System: the fields of system.find first, then the
# other properties.
ATTRIBUTES = tuple(FIELDS) + tuple(attribute for attribute, *_ in PROPERTIES
                                   if attribute not in FIELDS)

# Fields of system.find.multiple (flat, without the table names) -> attribute.
FLAT_FIELDS = {
    'LeafNodeId': 'id', 'ComputerName': 'name', 'DomainName': 'domain_name',
    'NetAddress': 'mac_address', 'OSType': 'os_type', 'UserName': 'user_name',
    'LastUpdate': 'last_communication', 'ManagedState': 'managed_state',
    'InstalledProducts': 'installed', 'DomainController': 'is_domain_controller',
}

# Values of the ENUM system properties (number -> console label). Agent Handler
# (LastAgentHandler) takes the id of an Agent Handler of the server.
_YES_NO = {0: 'No', 1: 'Yes', -1: 'Unknown'}
ENUM_VALUES = {
    'EPOComputerProperties.OSBitMode': _YES_NO,
    'EPOComputerProperties.IsPortable': _YES_NO,
    'EPOComputerProperties.Vdi': _YES_NO,
    'EPOComputerProperties.SystemRebootPending': {0: 'False', 1: 'True', -1: 'Unknown'},
}

# Management Type values (STRING_ENUM).
MANAGEMENT_TYPES = {'MJAL': 'Java Agent Library', 'SAAS': 'Security as a Service',
                    'EPOAGENTMETA': 'Trellix Agent'}

# Language values (Default Language, also used by tagcatalog for the
# "Language" product properties):
# Windows language id in hexadecimal, 4 digits. The product lists of the
# console also offer the values found in the database (e.g. "409").
LANGUAGES = {
    '0436': 'Afrikaans', '041c': 'Albanian', '1401': 'Arabic (Algeria)',
    '3c01': 'Arabic (Bahrain)', '0c01': 'Arabic (Egypt)', '0801': 'Arabic (Iraq)',
    '2c01': 'Arabic (Jordan)', '3401': 'Arabic (Kuwait)', '3001': 'Arabic (Lebanon)',
    '1001': 'Arabic (Libya)', '1801': 'Arabic (Morocco)', '2001': 'Arabic (Oman)',
    '4001': 'Arabic (Qatar)', '0401': 'Arabic (Saudi Arabia)', '2801': 'Arabic (Syria)',
    '1c01': 'Arabic (Tunisia)', '3801': 'Arabic (United Arab Emirates)', '2401': 'Arabic (Yemen)',
    '042b': 'Armenian', '082c': 'Azerbaijani (Cyrillic)', '042c': 'Azerbaijani (Latin)',
    '042d': 'Basque', '0423': 'Belarusian', '0402': 'Bulgarian', '0403': 'Catalan',
    '0c04': 'Chinese (Hong Kong SAR China)', '1404': 'Chinese (Macao SAR China)',
    '0804': 'Chinese (Simplified)', '1004': 'Chinese (Singapore)',
    '0404': 'Chinese (Traditional)', '041a': 'Croatian', '0405': 'Czech', '0406': 'Danish',
    '0813': 'Dutch (Belgium)', '0413': 'Dutch (Netherlands)', '0c09': 'English (Australia)',
    '2809': 'English (Belize)', '2409': 'English (British Virgin Islands)',
    '1009': 'English (Canada)', '4009': 'English (India)', '1809': 'English (Ireland)',
    '2009': 'English (Jamaica)', '1409': 'English (New Zealand)', '3409': 'English (Philippines)',
    '1c09': 'English (South Africa)', '2c09': 'English (Trinidad & Tobago)',
    '0809': 'English (United Kingdom)', '0409': 'English (United States)',
    '3009': 'English (Zimbabwe)', '0425': 'Estonian', '0438': 'Faroese', '040b': 'Finnish',
    '080c': 'French (Belgium)', '0c0c': 'French (Canada)', '040c': 'French (France)',
    '140c': 'French (Luxembourg)', '180c': 'French (Monaco)', '100c': 'French (Switzerland)',
    '0437': 'Georgian', '0c07': 'German (Austria)', '0407': 'German (Germany)',
    '1407': 'German (Liechtenstein)', '1007': 'German (Luxembourg)',
    '0807': 'German (Switzerland)', '0408': 'Greek', '040d': 'Hebrew', '0439': 'Hindi',
    '040e': 'Hungarian', '040f': 'Icelandic', '0421': 'Indonesian', '0410': 'Italian (Italy)',
    '0810': 'Italian (Switzerland)', '0411': 'Japanese', '043f': 'Kazakh', '0457': 'Konkani',
    '0412': 'Korean', '0426': 'Latvian', '0427': 'Lithuanian', '042f': 'Macedonian',
    '083e': 'Malay (Brunei)', '043e': 'Malay (Malaysia)', '044e': 'Marathi', '0000': 'Neutral',
    '0414': 'Norwegian (Norway)', '0814': 'Norwegian Bokmål (Norway,Nynorsk)', '0429': 'Persian',
    '0415': 'Polish', '0416': 'Portuguese (Brazil)', '0816': 'Portuguese (Portugal)',
    '0418': 'Romanian', '0818': 'Romanian (Moldova)', '0419': 'Russian',
    '0819': 'Russian (Moldova)', '044f': 'Sanskrit', '0c1a': 'Serbian (Cyrillic)',
    '081a': 'Serbian (Latin)', '041b': 'Slovak', '0424': 'Slovenian',
    '2c0a': 'Spanish (Argentina)', '400a': 'Spanish (Bolivia)', '340a': 'Spanish (Chile)',
    '240a': 'Spanish (Colombia)', '140a': 'Spanish (Costa Rica)',
    '1c0a': 'Spanish (Dominican Republic)', '300a': 'Spanish (Ecuador)',
    '440a': 'Spanish (El Salvador)', '100a': 'Spanish (Guatemala)', '480a': 'Spanish (Honduras)',
    '080a': 'Spanish (Mexico)', '4c0a': 'Spanish (Nicaragua)', '180a': 'Spanish (Panama)',
    '3c0a': 'Spanish (Paraguay)', '280a': 'Spanish (Peru)', '500a': 'Spanish (Puerto Rico)',
    '040a': 'Spanish (Spain, Traditional)', '0c0a': 'Spanish (Spain,Modern)',
    '380a': 'Spanish (Uruguay)', '200a': 'Spanish (Venezuela)', '0441': 'Swahili',
    '041d': 'Swedish', '081d': 'Swedish (Finland)', '0449': 'Tamil', '0444': 'Tatar',
    '041e': 'Thai', '041f': 'Turkish', '0422': 'Ukrainian', '0420': 'Urdu',
    '0843': 'Uzbek (Cyrillic)', '0443': 'Uzbek (Latin)', '042a': 'Vietnamese',
}

# Yes/no fields: 1 yes, 0 no, -1 or "NA" unknown (None); shown with the
# labels of ENUM_VALUES (Yes/No for isDomainController).
FLAGS = ('is_laptop', 'vdi', 'is_64bit', 'reboot_pending', 'is_domain_controller')

# Managed State of the console (EPOLeafNode.ManagedState).
MANAGED_STATES = {0: 'Unmanaged', 1: 'Managed'}

# Custom fields that system.setUserProperties sets (customField1-4).
CUSTOM_FIELDS = ('custom1', 'custom2', 'custom3', 'custom4')

# Default columns of the Systems page of the System Tree.
DEFAULT_COLUMNS = ('name', 'managed_state', 'tags', 'ip_address', 'user_name',
                   'last_communication', 'agent_version')


def _property(attribute):
    """
    Returns the entry of PROPERTIES of an attribute.

    >>> _property('custom1')
    ('custom1', 'EPOComputerProperties.UserProperty1', 'Custom 1', 'text', True)
    """
    for entry in PROPERTIES:
        if entry[0] == attribute:
            return entry
    raise ValueError('Unknown system properties: {}.'.format(attribute))


def label(attribute):
    """
    Returns the console label of a System attribute.

    >>> label('custom1'), label('dns_name'), label('managed_state')
    ('Custom 1', 'DNS Name', 'Managed State')
    """
    return _property(attribute)[2]


def criteria_property(attribute):
    """
    Returns the tag criteria property (TagProperty) of a System attribute,
    to tag the systems on a property read here, or None when the criteria
    builder doesn't offer it (tags, managed state, group...).

    >>> criteria_property('custom1')
    <TagProperty EPOComputerProperties.UserProperty1 (Custom 1, text)>
    >>> criteria_property('tags') is None
    True
    """
    # Imported here: tags imports tagcatalog, which imports this module.
    from .tags import TagProperty
    _, key, text, kind, criteria = _property(attribute)
    return TagProperty(key, text, 'Computer Properties', kind) if criteria else None


def normalize_path(path):
    """
    Returns a group path from "My Organization", with backslashes as
    separators, without empty parts, and "Lost and Found" under its console
    name.

    >>> normalize_path('\\\\Workstations\\\\')
    'My Organization\\\\Workstations'
    >>> normalize_path('my organization')
    'My Organization'
    >>> normalize_path('Lost&Found\\\\(none)')
    'My Organization\\\\Lost and Found\\\\(none)'
    """
    parts = [part.strip() for part in path.split('\\') if part.strip()]
    if parts and parts[0].lower() == ROOT_GROUP.lower():
        parts = parts[1:]
    if parts and parts[0] == LOST_AND_FOUND_INTERNAL:
        parts[0] = LOST_AND_FOUND
    return '\\'.join([ROOT_GROUP] + parts)


def is_lost_and_found(path):
    """
    True for Lost and Found and its subgroups.

    >>> is_lost_and_found('My Organization\\\\Lost and Found\\\\(none)')
    True
    >>> is_lost_and_found('Workstations')
    False
    """
    parts = normalize_path(path).split('\\')
    return len(parts) > 1 and parts[1].lower() == LOST_AND_FOUND.lower()


def check_destination(path):
    """
    Checks a group where systems or groups are added or moved: not Lost and
    Found or one of its subgroups, which the server fills by itself with the
    systems deployed outside the console at their first connection.

    Valid / invalid:

    >>> check_destination('My Organization\\\\Workstations')
    >>> check_destination('Lost and Found\\\\(none)')
    Traceback (most recent call last):
    ...
    ValueError: Nothing is added to or moved into Lost and Found (My Organization\\Lost and Found\\(none)): the server fills it with the systems deployed outside the console.
    """
    if is_lost_and_found(path):
        raise ValueError('Nothing is added to or moved into {} ({}): the server fills it with the '
                         'systems deployed outside the console.'.format(LOST_AND_FOUND,
                                                                        normalize_path(path)))


def check_name(name):
    """
    Checks a system or group name of an import file: not empty, no
    backslash (the path separator) and no line break.

    Valid / invalid:

    >>> check_name('PC01')
    >>> check_name('A\\\\B')
    Traceback (most recent call last):
    ...
    ValueError: A name can't be empty or contain a backslash or a line break: 'A\\\\B'.
    """
    if not name or not name.strip() or any(char in name for char in '\\\r\n'):
        raise ValueError("A name can't be empty or contain a backslash or a line break: "
                         '{!r}.'.format(name))


def import_file(lines):
    """
    Returns the text file of system.importSystem (uploadFile): one line per
    entry, "Group\\Subgroup\\System" from the group of branchNodeID; a line
    ending with a backslash creates the groups only (checked on ePO 5.10
    Update 7: "A\\Empty\\" creates the empty group Empty, no system).

    :param: lines: The entries, as lists of names (groups then the system,
                   or groups then '' for an empty group) or texts.

    >>> import_file([['Servers', 'SRV01'], ['Servers', 'Paris', '']])
    'Servers\\\\SRV01\\r\\nServers\\\\Paris\\\\\\r\\n'
    """
    text = []
    for line in lines:
        parts = line.split('\\') if isinstance(line, str) else list(line)
        for part in parts[:-1]:
            check_name(part)
        if parts[-1]:
            check_name(parts[-1])
        text.append('\\'.join(parts) + '\r\n')
    return ''.join(text)


def _list(text):
    """
    Returns the items of a comma separated field (Tags, Installed Products).

    >>> _list('DXLBROKER, Server'), _list(None)
    (['DXLBROKER', 'Server'], [])
    """
    return [item.strip() for item in (text or '').split(',') if item.strip()]


def _installed(text):
    """
    Returns the products of "Product list last installation time" as
    (product, date) pairs; the date is the text of the server.

    >>> _installed('[Agent | 2024-09-17 11:47:43], [SIR | 2024-11-18 21:49:37]')
    [('Agent', '2024-09-17 11:47:43'), ('SIR', '2024-11-18 21:49:37')]
    """
    pairs = []
    for item in (text or '').split('],'):
        item = item.strip().strip('[]').strip()
        if item:
            product, _, date = item.partition('|')
            pairs.append((product.strip(), date.strip()))
    return pairs


def _flag(value):
    """
    Returns True, False or None (unknown) of a yes/no field.

    >>> _flag(1), _flag('0'), _flag(-1), _flag('NA'), _flag(None)
    (True, False, None, None, None)
    """
    if value in (1, '1', True):
        return True
    if value in (0, '0', False):
        return False
    return None


def _date(text):
    """
    Returns the datetime of a Last Communication: ISO with time zone in
    system.find, "YYYY-MM-DD hh:mm:ss.mmm" in UTC in system.find.multiple.

    >>> _date('2026-10-17T13:58:53+02:00').isoformat()
    '2026-10-17T13:58:53+02:00'
    >>> _date('2026-10-17 11:58:53.82').isoformat()
    '2026-10-17T11:58:53.820000+00:00'
    >>> _date(None) is None
    True
    """
    if not text:
        return None
    if 'T' in text:
        return datetime.datetime.fromisoformat(text)
    pattern = '%Y-%m-%d %H:%M:%S.%f' if '.' in text else '%Y-%m-%d %H:%M:%S'
    return datetime.datetime.strptime(text, pattern).replace(tzinfo=datetime.timezone.utc)


class System():
    """
    A system of the System Tree, with the properties of system.find
    (FIELDS: name, description, custom1-8, ip_address, os_type, tags,
    last_communication, agent_version, group_id...). A system read from
    system.find.multiple has the FLAT_FIELDS only, the others are None.

    >>> System('PC01', id=4, group_id=6)
    <System PC01 (4, group 6)>
    """

    def __init__(self, name, **fields):
        """
        :param: name: The System Name.
        :param: fields: The other properties (ATTRIBUTES), e.g.
                        id=4, group_id=6, tags=['Server'].
        """
        unknown = set(fields) - set(ATTRIBUTES)
        if unknown:
            raise ValueError('Unknown system properties: {}.'.format(', '.join(sorted(unknown))))
        for attribute in ATTRIBUTES:
            setattr(self, attribute, fields.get(attribute))
        # The properties the library uses, declared for the readers and tools.
        self.id = fields.get('id')
        self.group_id = fields.get('group_id')
        self.managed_state = fields.get('managed_state')
        self.name = name
        for attribute in ('tags', 'excluded_tags', 'products', 'installed'):
            if getattr(self, attribute) is None:
                setattr(self, attribute, [])
        self.raw = {}

    @classmethod
    def from_json(cls, data):
        """
        Returns the system of a line of system.find or epogroup.findSystems.

        >>> System.from_json({'EPOComputerProperties.ParentID': 3,
        ...     'EPOComputerProperties.ComputerName': 'SRV01', 'EPOBranchNode.AutoID': 4,
        ...     'EPOLeafNode.LastUpdate': '2026-10-17T13:58:53+02:00'}).last_communication.day
        17
        """
        # The fields of system.find, and the other properties of a query row.
        fields = {attribute: data.get(_KEYS[attribute]) for attribute in ATTRIBUTES}
        system = cls(fields.pop('name') or '', **cls._convert(fields))
        system.raw = data
        return system

    @classmethod
    def from_flat(cls, data):
        """
        Returns the system of a line of system.find.multiple (fewer fields).

        >>> system = System.from_flat({'LeafNodeId': 4, 'ComputerName': 'PC01',
        ...     'LastUpdate': '2026-10-14 14:35:02.377', 'DomainController': 'NA'})
        >>> system, system.last_communication.hour, system.is_domain_controller
        (<System PC01 (4, group None)>, 14, None)
        """
        fields = {attribute: data.get(key) for key, attribute in FLAT_FIELDS.items()}
        system = cls(fields.pop('name') or '', **cls._convert(fields))
        system.raw = data
        return system

    @staticmethod
    def _convert(fields):
        """
        Returns the fields of the Web API as attribute values: lists for the
        tags and products, datetime, True/False/None for the yes/no fields.

        >>> System._convert({'tags': 'A, B', 'vdi': 0, 'managed_state': 1})
        {'tags': ['A', 'B'], 'vdi': False, 'managed_state': 1}
        """
        converted = dict(fields)
        for attribute in ('tags', 'excluded_tags', 'products'):
            if attribute in converted:
                converted[attribute] = _list(converted[attribute])
        if 'installed' in converted:
            converted['installed'] = _installed(converted['installed'])
        if 'last_communication' in converted:
            converted['last_communication'] = _date(converted['last_communication'])
        for attribute in FLAGS:
            if attribute in converted:
                converted[attribute] = _flag(converted[attribute])
        return converted

    def __repr__(self):
        """
        Shows the name, the id and the group id.
        """
        return '<System {} ({}, group {})>'.format(self.name, self.id, self.group_id)

    def __eq__(self, other):
        """
        Two systems are equal when their ids and names are.
        """
        return isinstance(other, System) and (self.id, self.name) == (other.id, other.name)

    @property
    def managed(self):
        """
        True when the agent manages the system (Managed State).

        >>> System('PC01', managed_state=1).managed, System('PC02', managed_state=0).managed
        (True, False)
        """
        return self.managed_state == 1

    @property
    def custom_fields(self):
        """
        The Custom 1 to 4 fields (set with epo.systems.set_properties()).

        >>> System('PC01', custom1='PROD').custom_fields
        {'custom1': 'PROD', 'custom2': None, 'custom3': None, 'custom4': None}
        """
        return {attribute: getattr(self, attribute) for attribute in CUSTOM_FIELDS}

    def value(self, attribute):
        """
        Returns a property as the console shows it: lists joined with
        commas, the values of the drop-down lists of tagcatalog (Yes/No,
        languages), the Managed State label, the date as "YYYY-MM-DD hh:mm",
        '' when empty.

        >>> System('PC01', tags=['A', 'B'], is_64bit=True, managed_state=1).value('tags')
        'A, B'
        >>> System('PC01', is_64bit=True).value('is_64bit')
        'Yes'
        >>> System('PC01', default_language='040c').value('default_language')
        'French (France)'
        """
        value = getattr(self, attribute)
        if value is None:
            return ''
        if attribute == 'installed':
            return ', '.join('{} ({})'.format(*pair) for pair in value)
        if isinstance(value, list):
            return ', '.join(value)
        if attribute in FLAGS:
            return ENUM_VALUES.get(_KEYS[attribute], _YES_NO)[1 if value else 0]
        if attribute == 'default_language':
            return LANGUAGES.get(value.lower(), value)
        if attribute == 'managed_state':
            return MANAGED_STATES.get(value, str(value))
        if isinstance(value, datetime.datetime):
            return value.strftime('%Y-%m-%d %H:%M')
        return str(value)

    def to_markdown(self):
        """
        Returns the properties of the system as a Markdown table (label,
        value), the empty ones left out.

        >>> print(System('PC01', id=4, custom1='PROD').to_markdown())
        # PC01
        <BLANKLINE>
        | Property | Value |
        |---|---|
        | System ID | 4 |
        | System Name | PC01 |
        | Custom 1 | PROD |
        """
        lines = ['# ' + Policy.md_heading(self.name), '', '| Property | Value |', '|---|---|']
        for attribute in ATTRIBUTES:
            value = self.value(attribute)
            if value:
                lines.append('| {} | {} |'.format(label(attribute), Policy.md_escape(value)))
        return '\n'.join(lines)


def systems_to_markdown(systems, columns=DEFAULT_COLUMNS, title='Systems'):
    """
    Returns the systems as a Markdown table, sorted by name, with the
    default columns of the Systems page (or the ATTRIBUTES given).

    >>> print(systems_to_markdown([System('PC01', managed_state=1, tags=['Workstation'])],
    ...                           columns=('name', 'managed_state', 'tags')))
    # Systems
    <BLANKLINE>
    | System Name | Managed State | Tags |
    |---|---|---|
    | PC01 | Managed | Workstation |
    """
    unknown = [column for column in columns if column not in ATTRIBUTES]
    if unknown:
        raise ValueError('Unknown system properties: {}.'.format(', '.join(unknown)))
    lines = ['# ' + Policy.md_heading(title), '',
             '| ' + ' | '.join(label(column) for column in columns) + ' |',
             '|' + '---|' * len(columns)]
    for system in sorted(systems, key=lambda item: item.name.lower()):
        lines.append('| ' + ' | '.join(Policy.md_escape(system.value(column))
                                       for column in columns) + ' |')
    return '\n'.join(lines)


class Group():
    """
    A group of the System Tree: id (EPOBranchNode.AutoID, the groupId of
    system.findGroups), path from My Organization, parent id, type and
    notes.

    >>> group = Group(13, 'My Organization\\\\Servers\\\\Paris', parent_id=12)
    >>> group, group.name, group.parent_path, group.depth
    (<Group 13 My Organization\\Servers\\Paris>, 'Paris', 'My Organization\\\\Servers', 2)
    """

    def __init__(self, id, path, parent_id=None, type=GROUP_TYPE, notes=None):
        """
        :param: id: The group id.
        :param: path: The path from My Organization.
        :param: parent_id: The id of the parent group (None for My
                           Organization).
        :param: type: The group type: ROOT_TYPE (My Organization),
                      LOST_AND_FOUND_TYPE or GROUP_TYPE.
        :param: notes: The notes of the group.
        """
        self.id = id
        self.path = normalize_path(path)
        self.parent_id = parent_id
        self.type = type
        self.notes = notes

    @classmethod
    def from_json(cls, data):
        """
        Returns the group of a line of system.findGroups (id and path only)
        or of a row of the EPOBranchNode table.

        >>> Group.from_json({'groupId': 3, 'groupPath': 'My Organization\\\\Lost and Found'}).type
        5
        >>> Group.from_json({'EPOBranchNode.AutoID': 10, 'EPOBranchNode.NodeName': '(none)',
        ...     'EPOBranchNode.ParentID': 3, 'EPOBranchNode.Type': 3,
        ...     'EPOBranchNode.NodeTextPath2': '\\\\Lost&Found\\\\(none)\\\\'})
        <Group 10 My Organization\\Lost and Found\\(none)>
        """
        if 'groupId' in data:
            path = normalize_path(data['groupPath'])
            kind = (ROOT_TYPE if path == ROOT_GROUP else
                    LOST_AND_FOUND_TYPE if path == ROOT_GROUP + '\\' + LOST_AND_FOUND else
                    GROUP_TYPE)
            return cls(data['groupId'], path, type=kind)
        kind = data.get('EPOBranchNode.Type')
        return cls(data['EPOBranchNode.AutoID'], data.get('EPOBranchNode.NodeTextPath2') or '',
                   data.get('EPOBranchNode.ParentID') if kind != ROOT_TYPE else None,
                   kind, data.get('EPOBranchNode.Notes'))

    def __repr__(self):
        """
        Shows the id and the path.
        """
        return '<Group {} {}>'.format(self.id, self.path)

    def __eq__(self, other):
        """
        Two groups are equal when their ids and paths are.
        """
        return isinstance(other, Group) and (self.id, self.path) == (other.id, other.path)

    @property
    def name(self):
        """
        The group name (last part of the path).

        >>> Group(2, 'My Organization').name
        'My Organization'
        """
        return self.path.split('\\')[-1]

    @property
    def parent_path(self):
        """
        The path of the parent group (None for My Organization).

        >>> Group(2, 'My Organization').parent_path is None
        True
        """
        return self.path.rsplit('\\', 1)[0] if '\\' in self.path else None

    @property
    def depth(self):
        """
        The level of the group: 0 for My Organization, 1 for its subgroups...

        >>> Group(6, 'My Organization\\\\Workstations').depth
        1
        """
        return self.path.count('\\')

    @property
    def lost_and_found(self):
        """
        True for Lost and Found and its subgroups (see check_destination()).

        >>> Group(10, 'My Organization\\\\Lost and Found\\\\(none)').lost_and_found
        True
        """
        return is_lost_and_found(self.path)

    def md_row(self):
        """
        Returns the columns of the group table: the name indented by level,
        the id, the path and the notes.

        >>> Group(13, 'My Organization\\\\Servers\\\\Paris').md_row()
        ['&nbsp;&nbsp;&nbsp;&nbsp;Paris', '13', 'My Organization\\\\\\\\Servers\\\\\\\\Paris', '']
        """
        return ['&nbsp;' * 2 * self.depth + Policy.md_escape(self.name), str(self.id),
                Policy.md_escape(self.path), Policy.md_escape(self.notes or '')]


def groups_to_markdown(groups, title='System Tree'):
    """
    Returns the groups as a Markdown table in the order of the System Tree
    (each group under its parent, sorted by name).

    >>> print(groups_to_markdown([Group(6, 'My Organization\\\\Workstations'),
    ...                           Group(2, 'My Organization', type=ROOT_TYPE)]))
    # System Tree
    <BLANKLINE>
    | Group | ID | Path | Notes |
    |---|---|---|---|
    | My Organization | 2 | My Organization |  |
    | &nbsp;&nbsp;Workstations | 6 | My Organization\\\\Workstations |  |
    """
    lines = ['# ' + Policy.md_heading(title), '', '| Group | ID | Path | Notes |',
             '|---|---|---|---|']
    for group in sorted(groups, key=lambda item: [part.lower() for part in item.path.split('\\')]):
        lines.append('| ' + ' | '.join(group.md_row()) + ' |')
    return '\n'.join(lines)
