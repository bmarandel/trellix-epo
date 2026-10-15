# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the catalog of the system properties a tag criteria can
use, as the Tag Catalog of the ePO console shows them (Systems > Tag
Catalog > New Tag > Criteria, ePO 5.10 Update 7, read from
criteriaBuilderCard.do and loadDisplayType.do on the lab):

- PROPERTIES: the 120 properties (SQUID key, console label, console
  category, kind). Prefer the "Computer Properties" category for a tag
  criteria: the product properties (EPOProdPropsView_*) depend on the
  extensions installed on the server (this list is the one of the lab).
- KINDS: for each kind, the operators of the console and the value it takes.
- OPERATORS: the console label of each operator.
- ENUM_VALUES, LANGUAGES, MANAGEMENT_TYPES: the values of the drop-down lists.
"""

# Kinds of property, named after the console display types.
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

_BLANK = ('isBlank', 'not_isBlank')
_TEXT_OPS = ('eq', 'ne', 'contains', 'notContains', 'startsWith', 'endsWith', 'like') + _BLANK
_NUMBER_OPS = ('eq', 'ne', 'lt', 'le', 'gt', 'ge')

# Operators of each kind, in the order of the console list, and the maximum
# length of a text value (console input fields).
KINDS = {
    ENUM: {'operators': ('eq', 'ne') + _BLANK},
    TEXT: {'operators': _TEXT_OPS, 'max_length': 100},
    INTEGER: {'operators': _NUMBER_OPS, 'max_length': 10},
    LOOKUP: {'operators': _TEXT_OPS, 'max_length': 255},
    STRING_ENUM: {'operators': ('eq', 'ne') + _BLANK},
    MEGABYTES: {'operators': _NUMBER_OPS},
    BYTES: {'operators': _NUMBER_OPS},
    IPV4: {'operators': ('eq', 'ne', 'between', 'notBetween', 'in_subnet', 'not_in_subnet',
                         'match_any') + _BLANK},
    IPV6: {'operators': ('eq', 'ne', 'between', 'notBetween', 'in_ipv6_subnet',
                         'not_in_ipv6_subnet', 'match_any', 'not_match_any') + _BLANK},
    TIMESTAMP: {'operators': ('newerThan', 'newerThanFull', 'olderThan', 'newerThanAbsolute',
                              'olderThanAbsolute', 'between', 'beforeNow') + _BLANK},
    VERSION2: {'operators': ('version2_eq', 'version2_neq', 'version2_ge', 'version2_lt') + _BLANK},
    VERSION: {'operators': ('version_eq', 'version_neq', 'version_ge', 'version_lt') + _BLANK},
}

# Console label of each operator (the same key may have the same label in
# several kinds).
OPERATORS = {
    'eq': 'Equals', 'ne': 'Does not equal', 'isBlank': 'Value is blank',
    'not_isBlank': 'Value is not blank', 'contains': 'Contains', 'notContains': 'Does not contain',
    'startsWith': 'Starts with', 'endsWith': 'Ends with', 'like': 'Contains pattern',
    'lt': 'Less than', 'le': 'Less than or equals', 'gt': 'Greater than',
    'ge': 'Greater than or equals', 'between': 'Is between', 'notBetween': 'Is not between',
    'in_subnet': 'Matches subnet (CIDR format)',
    'not_in_subnet': 'Does not match subnet (CIDR format)',
    'in_ipv6_subnet': 'Matches subnet (CIDR format)',
    'not_in_ipv6_subnet': 'Does not match subnet (CIDR format)',
    'match_any': 'Matches one of the following',
    'not_match_any': 'Does not match any of the following',
    'newerThan': 'Is within the last', 'newerThanFull': 'Is within the last full',
    'olderThan': 'Is not within the last', 'newerThanAbsolute': 'Is later than',
    'olderThanAbsolute': 'Is earlier than', 'beforeNow': 'Is before now',
    'version2_eq': 'Equals', 'version2_neq': 'Does not equal',
    'version2_ge': 'Greater than or equals', 'version2_lt': 'Less than',
    'version_eq': 'Equals', 'version_neq': 'Does not equal',
    'version_ge': 'Greater than or equals', 'version_lt': 'Less than',
}

# The properties of the console criteria builder: (SQUID key, label,
# category, kind).
PROPERTIES = (
    # Computer Properties
    ('EPOComputerProperties.LastAgentHandler', 'Agent Handler', 'Computer Properties', ENUM),
    ('EPOComputerProperties.CPUSerialNumber', 'CPU Serial Number', 'Computer Properties', TEXT),
    ('EPOComputerProperties.CPUSpeed', 'CPU Speed (MHz)', 'Computer Properties', INTEGER),
    ('EPOComputerProperties.CPUType', 'CPU Type', 'Computer Properties', LOOKUP),
    ('EPOComputerProperties.UserProperty1', 'Custom 1', 'Computer Properties', TEXT),
    ('EPOComputerProperties.UserProperty2', 'Custom 2', 'Computer Properties', TEXT),
    ('EPOComputerProperties.UserProperty3', 'Custom 3', 'Computer Properties', TEXT),
    ('EPOComputerProperties.UserProperty4', 'Custom 4', 'Computer Properties', TEXT),
    ('EPOComputerProperties.UserProperty5', 'Custom 5', 'Computer Properties', TEXT),
    ('EPOComputerProperties.UserProperty6', 'Custom 6', 'Computer Properties', TEXT),
    ('EPOComputerProperties.UserProperty7', 'Custom 7', 'Computer Properties', TEXT),
    ('EPOComputerProperties.UserProperty8', 'Custom 8', 'Computer Properties', TEXT),
    ('EPOComputerProperties.DefaultLangID', 'Default Language', 'Computer Properties', STRING_ENUM),
    ('EPOComputerProperties.Description', 'Description', 'Computer Properties', TEXT),
    ('EPOComputerProperties.IPHostName', 'DNS Name', 'Computer Properties', TEXT),
    ('EPOComputerProperties.DomainName', 'Domain Name', 'Computer Properties', LOOKUP),
    ('EPOComputerProperties.EmailAddress', 'Email Address', 'Computer Properties', TEXT),
    ('EPOComputerProperties.Free_Space_of_Drive_C', 'Free C Drive Space',
     'Computer Properties', MEGABYTES),
    ('EPOComputerProperties.FreeDiskSpace', 'Free Disk Space', 'Computer Properties', MEGABYTES),
    ('EPOComputerProperties.FreeMemory', 'Free Memory', 'Computer Properties', BYTES),
    ('EPOComputerProperties.IPV4x', 'IP4 Address (deprecated)', 'Computer Properties', IPV4),
    ('EPOComputerProperties.IPV6', 'IP address', 'Computer Properties', IPV6),
    ('EPOComputerProperties.IPXAddress', 'IPX Address', 'Computer Properties', TEXT),
    ('EPOComputerProperties.OSBitMode', 'Is 64-bit OS', 'Computer Properties', ENUM),
    ('EPOComputerProperties.IsPortable', 'Is Laptop', 'Computer Properties', ENUM),
    ('EPOComputerProperties.LastUpdate', 'Last Communication', 'Computer Properties', TEXT),
    ('EPOComputerProperties.SystemBootTime', 'Last System Boot Time',
     'Computer Properties', TIMESTAMP),
    ('EPOComputerProperties.NetAddress', 'MAC Address', 'Computer Properties', TEXT),
    ('EPOComputerProperties.ManagementType', 'Management Type', 'Computer Properties', STRING_ENUM),
    ('EPOComputerProperties.NumOfCPU', 'Number Of CPUs', 'Computer Properties', INTEGER),
    ('EPOComputerProperties.EthernetMacAddressCount', 'Number of Ethernet MAC Address',
     'Computer Properties', INTEGER),
    ('EPOComputerProperties.NumOfHardDrives', 'Number of Hard Drives',
     'Computer Properties', INTEGER),
    ('EPOComputerProperties.OtherMacAddressCount', 'Number of Other MAC Address',
     'Computer Properties', INTEGER),
    ('EPOComputerProperties.WirelessMacAddressCount', 'Number of Wireless MAC Address',
     'Computer Properties', INTEGER),
    ('EPOComputerProperties.OSBuildNum', 'OS Build Number', 'Computer Properties', INTEGER),
    ('EPOComputerProperties.OSOEMID', 'OS OEM Identifier', 'Computer Properties', LOOKUP),
    ('EPOComputerProperties.OSPlatform', 'OS Platform', 'Computer Properties', LOOKUP),
    ('EPOComputerProperties.OSCsdVersion', 'OS Service Pack Version',
     'Computer Properties', LOOKUP),
    ('EPOComputerProperties.OSType', 'OS Type', 'Computer Properties', LOOKUP),
    ('EPOComputerProperties.OSVersion', 'OS Version', 'Computer Properties', LOOKUP),
    ('EPOComputerProperties.PlatformID', 'Platform ID', 'Computer Properties', TEXT),
    ('EPOComputerProperties.SystemRebootPending', 'Reboot Pending', 'Computer Properties', ENUM),
    ('EPOComputerProperties.SMBiosUUID', 'SMBios UUID', 'Computer Properties', TEXT),
    ('EPOComputerProperties.IPSubnet', 'Subnet Address', 'Computer Properties', IPV6),
    ('EPOComputerProperties.SubnetAddress', 'Subnet Address (deprecated)',
     'Computer Properties', TEXT),
    ('EPOComputerProperties.IPSubnetMask', 'Subnet Mask', 'Computer Properties', IPV6),
    ('EPOComputerProperties.SubnetMask', 'Subnet Mask (deprecated)', 'Computer Properties', TEXT),
    ('EPOComputerProperties.ComputerDescription', 'System Description',
     'Computer Properties', TEXT),
    ('EPOComputerProperties.SystemManufacturer', 'System Manufacturer',
     'Computer Properties', TEXT),
    ('EPOComputerProperties.SystemModel', 'System Model', 'Computer Properties', TEXT),
    ('EPOComputerProperties.ComputerName', 'System Name', 'Computer Properties', TEXT),
    ('EPOComputerProperties.SystemSerialNumber', 'System Serial Number',
     'Computer Properties', TEXT),
    ('EPOComputerProperties.TimeZone', 'Time Zone', 'Computer Properties', LOOKUP),
    ('EPOComputerProperties.Total_Space_of_Drive_C', 'Total C Drive Space',
     'Computer Properties', MEGABYTES),
    ('EPOComputerProperties.TotalDiskSpace', 'Total Disk Space', 'Computer Properties', MEGABYTES),
    ('EPOComputerProperties.TotalPhysicalMemory', 'Total Physical Memory',
     'Computer Properties', BYTES),
    ('EPOComputerProperties.UserName', 'User Name', 'Computer Properties', TEXT),
    ('EPOComputerProperties.Vdi', 'VDI', 'Computer Properties', ENUM),
    # Extended Computer Properties
    ('EPOExtendedComputerProperties.EthernetMacAddress_1', 'Ethernet MacAddress 1',
     'Extended Computer Properties', TEXT),
    # Trellix DXLBroker Properties
    ('EPOProdPropsView_DXLBROKER.hotfix', 'Hotfix/Update Version',
     'Trellix DXLBroker Properties', TEXT),
    ('EPOProdPropsView_DXLBROKER.language', 'Language',
     'Trellix DXLBroker Properties', STRING_ENUM),
    ('EPOProdPropsView_DXLBROKER.verProductVersion', 'Product Version (Fast)',
     'Trellix DXLBroker Properties', VERSION2),
    ('EPOProdPropsView_DXLBROKER.productversion', 'Product Version',
     'Trellix DXLBroker Properties', VERSION),
    # Trellix DXL Client Properties
    ('EPOProdPropsView_DXLCLIENT.hotfix', 'Hotfix/Update Version',
     'Trellix DXL Client Properties', TEXT),
    ('EPOProdPropsView_DXLCLIENT.language', 'Language',
     'Trellix DXL Client Properties', STRING_ENUM),
    ('EPOProdPropsView_DXLCLIENT.verProductVersion', 'Product Version (Fast)',
     'Trellix DXL Client Properties', VERSION2),
    ('EPOProdPropsView_DXLCLIENT.productversion', 'Product Version',
     'Trellix DXL Client Properties', VERSION),
    # Trellix DXL Java Client Properties
    ('EPOProdPropsView_DXLCLIENTJ.hotfix', 'Hotfix/Update Version',
     'Trellix DXL Java Client Properties', TEXT),
    ('EPOProdPropsView_DXLCLIENTJ.language', 'Language',
     'Trellix DXL Java Client Properties', STRING_ENUM),
    ('EPOProdPropsView_DXLCLIENTJ.verProductVersion', 'Product Version (Fast)',
     'Trellix DXL Java Client Properties', VERSION2),
    ('EPOProdPropsView_DXLCLIENTJ.productversion', 'Product Version',
     'Trellix DXL Java Client Properties', VERSION),
    # Trellix DXL Java Client Properties (second extension)
    ('EPOProdPropsView_DXLCLIENTJ1.hotfix', 'Hotfix/Update Version',
     'Trellix DXL Java Client Properties', TEXT),
    ('EPOProdPropsView_DXLCLIENTJ1.language', 'Language',
     'Trellix DXL Java Client Properties', STRING_ENUM),
    ('EPOProdPropsView_DXLCLIENTJ1.verProductVersion', 'Product Version (Fast)',
     'Trellix DXL Java Client Properties', VERSION2),
    ('EPOProdPropsView_DXLCLIENTJ1.productversion', 'Product Version',
     'Trellix DXL Java Client Properties', VERSION),
    # Endpoint Security Platform Properties
    ('EPOProdPropsView_ENDPOINTSECURITYPLATFORM.language', 'Language',
     'Endpoint Security Platform Properties', STRING_ENUM),
    ('EPOProdPropsView_ENDPOINTSECURITYPLATFORM.productversion', 'Product Version',
     'Endpoint Security Platform Properties', VERSION),
    ('EPOProdPropsView_ENDPOINTSECURITYPLATFORM.verProductVersion', 'Product Version (Fast)',
     'Endpoint Security Platform Properties', VERSION2),
    # Endpoint Security Storage Protection Properties
    ('EPOProdPropsView_ENDPOINTSTORAGEPROTECTION.hotfix', 'Hotfix/Update Version',
     'Endpoint Security Storage Protection Properties', TEXT),
    ('EPOProdPropsView_ENDPOINTSTORAGEPROTECTION.licensestatus', 'License Status',
     'Endpoint Security Storage Protection Properties', TEXT),
    ('EPOProdPropsView_ENDPOINTSTORAGEPROTECTION.productversion', 'Product Version',
     'Endpoint Security Storage Protection Properties', VERSION),
    ('EPOProdPropsView_ENDPOINTSTORAGEPROTECTION.verProductVersion', 'Product Version (Fast)',
     'Endpoint Security Storage Protection Properties', VERSION2),
    ('EPOProdPropsView_ENDPOINTSTORAGEPROTECTION.servicepack', 'Service Pack',
     'Endpoint Security Storage Protection Properties', TEXT),
    # Agent Properties
    ('EPOProdPropsView_EPOAGENT.hotfix', 'Hotfix/Update Version', 'Agent Properties', TEXT),
    ('EPOProdPropsView_EPOAGENT.language', 'Language', 'Agent Properties', STRING_ENUM),
    ('EPOProdPropsView_EPOAGENT.productversion', 'Product Version', 'Agent Properties', VERSION),
    ('EPOProdPropsView_EPOAGENT.verProductVersion', 'Product Version (Fast)',
     'Agent Properties', VERSION2),
    # Endpoint Security Firewall Properties
    ('EPOProdPropsView_FIREWALL.language', 'Language',
     'Endpoint Security Firewall Properties', STRING_ENUM),
    ('EPOProdPropsView_FIREWALL.productversion', 'Product Version',
     'Endpoint Security Firewall Properties', VERSION),
    ('EPOProdPropsView_FIREWALL.verProductVersion', 'Product Version (Fast)',
     'Endpoint Security Firewall Properties', VERSION2),
    # Trellix EDR Properties
    ('EPOProdPropsView_MVEDR.installedpath', 'Installed Path', 'Trellix EDR Properties', TEXT),
    ('EPOProdPropsView_MVEDR.language', 'Language', 'Trellix EDR Properties', STRING_ENUM),
    ('EPOProdPropsView_MVEDR.verProductVersion', 'Product Version (Fast)',
     'Trellix EDR Properties', VERSION2),
    ('EPOProdPropsView_MVEDR.productversion', 'Product Version', 'Trellix EDR Properties', VERSION),
    # Product Coverage Reports Properties
    ('EPOProdPropsView_PCR.verProductVersion', 'Product Version (Fast)',
     'Product Coverage Reports Properties', VERSION2),
    ('EPOProdPropsView_PCR.productversion', 'Product Version',
     'Product Coverage Reports Properties', VERSION),
    # SIR Properties
    ('EPOProdPropsView_SIR.hotfix', 'Hotfix/Update Version', 'SIR Properties', TEXT),
    ('EPOProdPropsView_SIR.language', 'Language', 'SIR Properties', STRING_ENUM),
    ('EPOProdPropsView_SIR.verProductVersion', 'Product Version (Fast)',
     'SIR Properties', VERSION2),
    ('EPOProdPropsView_SIR.productversion', 'Product Version', 'SIR Properties', VERSION),
    # Solidcore Properties
    ('EPOProdPropsView_SOLIDCORE.hotfix', 'Hotfix/Update Version', 'Solidcore Properties', TEXT),
    ('EPOProdPropsView_SOLIDCORE.installedpath', 'Installed Path', 'Solidcore Properties', TEXT),
    ('EPOProdPropsView_SOLIDCORE.language', 'Language', 'Solidcore Properties', STRING_ENUM),
    ('EPOProdPropsView_SOLIDCORE.verProductVersion', 'Product Version (Fast)',
     'Solidcore Properties', VERSION2),
    ('EPOProdPropsView_SOLIDCORE.productversion', 'Product Version',
     'Solidcore Properties', VERSION),
    # Endpoint Security Threat Prevention Properties
    ('EPOProdPropsView_THREATPREVENTION.language', 'Language',
     'Endpoint Security Threat Prevention Properties', STRING_ENUM),
    ('EPOProdPropsView_THREATPREVENTION.productversion', 'Product Version',
     'Endpoint Security Threat Prevention Properties', VERSION),
    ('EPOProdPropsView_THREATPREVENTION.verProductVersion', 'Product Version (Fast)',
     'Endpoint Security Threat Prevention Properties', VERSION2),
    # Trellix Threat Intelligence Exchange Properties
    ('EPOProdPropsView_TIE.verProductVersion', 'Product Version (Fast)',
     'Trellix Threat Intelligence Exchange Properties', VERSION2),
    ('EPOProdPropsView_TIE.productversion', 'Product Version',
     'Trellix Threat Intelligence Exchange Properties', VERSION),
    # Endpoint Security Adaptive Threat Protection Properties
    ('EPOProdPropsView_TIECLIENTMETA.language', 'Language',
     'Endpoint Security Adaptive Threat Protection Properties', STRING_ENUM),
    ('EPOProdPropsView_TIECLIENTMETA.productversion', 'Product Version',
     'Endpoint Security Adaptive Threat Protection Properties', VERSION),
    ('EPOProdPropsView_TIECLIENTMETA.verProductVersion', 'Product Version (Fast)',
     'Endpoint Security Adaptive Threat Protection Properties', VERSION2),
    # Endpoint Security Web Control Properties
    ('EPOProdPropsView_WEBCONTROL.language', 'Language',
     'Endpoint Security Web Control Properties', STRING_ENUM),
    ('EPOProdPropsView_WEBCONTROL.productversion', 'Product Version',
     'Endpoint Security Web Control Properties', VERSION),
    ('EPOProdPropsView_WEBCONTROL.verProductVersion', 'Product Version (Fast)',
     'Endpoint Security Web Control Properties', VERSION2),
    # Trellix EDR with Forensics Properties
    ('EPOProdPropsView_XCLIENT.installedpath', 'Installed Path',
     'Trellix EDR with Forensics Properties', TEXT),
    ('EPOProdPropsView_XCLIENT.language', 'Language',
     'Trellix EDR with Forensics Properties', STRING_ENUM),
    ('EPOProdPropsView_XCLIENT.verProductVersion', 'Product Version (Fast)',
     'Trellix EDR with Forensics Properties', VERSION2),
    ('EPOProdPropsView_XCLIENT.productversion', 'Product Version',
     'Trellix EDR with Forensics Properties', VERSION),
)

# Values of the ENUM properties (number -> console label). Agent Handler
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

# Language values (Default Language and the "Language" product properties):
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
