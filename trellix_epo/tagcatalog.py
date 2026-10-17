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

The Computer Properties, the kinds and the values of the drop-down lists are
the ones of the system properties (systemtree.PROPERTIES, the reference):
this module imports them.
"""

# Kinds of property, named after the console display types: defined with the
# system properties (systemtree), the reference of the Computer Properties.
from .systemtree import (ENUM, TEXT, INTEGER, LOOKUP, STRING_ENUM, MEGABYTES, BYTES,
                         IPV4, IPV6, TIMESTAMP, VERSION2, VERSION, ENUM_VALUES,
                         MANAGEMENT_TYPES, LANGUAGES, PROPERTIES as SYSTEM_PROPERTIES)  # noqa: F401

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
PROPERTIES = tuple(
    # Computer Properties: the system properties of the System Tree
    # (systemtree.PROPERTIES) the criteria builder offers, in its order.
    (key, label, 'Computer Properties', kind)
    for _, key, label, kind, criteria in SYSTEM_PROPERTIES if criteria) + (
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

# ENUM_VALUES (values of the ENUM properties), MANAGEMENT_TYPES and LANGUAGES
# (Default Language, also the "Language" product properties) are the ones of
# the system properties: imported from systemtree above.
