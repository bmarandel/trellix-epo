# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the settings of the ePO server used by the agents as
objects, without a server: AgentHandler (agentmgmt.listAgentHandlers) and
MacVendor (the Virtual MAC Vendors of ComputerMgmt.*MacVendor*), and their
Markdown tables.

>>> handler = AgentHandler.from_json({'autoId': 1, 'computerName': 'EPO01',
...     'dnsName': 'EPO01', 'lastKnownIp': '10.0.0.5', 'version': '5.10.0',
...     'enabled': True, 'masterHandler': True, 'versionMatch': 1,
...     'lastUpdate': '2026-10-18T14:32:10+02:00'})
>>> handler
<AgentHandler 1 EPO01 (master)>
>>> MacVendor('00059a', 'Cisco VPN')
<MacVendor 00059A Cisco VPN>

The operations on a server (epo.server) are in the eposerver module.
"""

import datetime
import re

from .policies import Policy


def _date(text):
    """
    Returns the datetime of a date of the Web API, or None.

    >>> _date('2026-10-18T14:32:10+02:00').isoformat()
    '2026-10-18T14:32:10+02:00'
    >>> _date(None) is None
    True
    """
    return datetime.datetime.fromisoformat(text) if text else None


class AgentHandler():
    """
    An Agent Handler of the server (a line of Configuration > Agent
    Handlers): the ePO server itself (master) or a remote Agent Handler.
    Its id is the one the agent deployment commands take (ahId,
    primaryAgentHandler) and the Agent Handler property of the systems
    (EPOComputerProperties.LastAgentHandler).
    """

    def __init__(self, id, name, dns_name='', ip_address='', version='', enabled=True,
                 master=False, version_match=None, published_dns_name=None,
                 published_netbios_name=None, published_ip=None, last_update=None):
        """
        :param: id: The id (autoId).
        :param: name: The computer name.
        :param: dns_name: The DNS name.
        :param: ip_address: The last known IP address.
        :param: version: The ePO version of the handler.
        :param: enabled: The handler takes agent connections.
        :param: master: The ePO server itself (masterHandler).
        :param: version_match: versionMatch of the Web API (1 on the lab:
                               same version as the server).
        :param: published_dns_name: The published DNS name (for agents
                                    outside the network), or None.
        :param: published_netbios_name: The published NetBIOS name, or None.
        :param: published_ip: The published IP address, or None.
        :param: last_update: The last communication (datetime).
        """
        self.id = id
        self.name = name
        self.dns_name = dns_name
        self.ip_address = ip_address
        self.version = version
        self.enabled = enabled
        self.master = master
        self.version_match = version_match
        self.published_dns_name = published_dns_name
        self.published_netbios_name = published_netbios_name
        self.published_ip = published_ip
        self.last_update = last_update

    @classmethod
    def from_json(cls, data):
        """
        Returns the Agent Handler of a line of agentmgmt.listAgentHandlers.

        >>> AgentHandler.from_json({'autoId': 2, 'computerName': 'AH-DMZ',
        ...     'enabled': False, 'masterHandler': False})
        <AgentHandler 2 AH-DMZ (disabled)>
        """
        return cls(data['autoId'], data.get('computerName') or data.get('dnsName') or '',
                   data.get('dnsName') or '', data.get('lastKnownIp') or '',
                   data.get('version') or '', bool(data.get('enabled')),
                   bool(data.get('masterHandler')), data.get('versionMatch'),
                   data.get('publishedDNSName'), data.get('publishedNetBiosName'),
                   data.get('publishedIP'), _date(data.get('lastUpdate')))

    def __repr__(self):
        """
        Shows the id, the name, and master or disabled.
        """
        states = [state for state, on in (('master', self.master),
                                          ('disabled', not self.enabled)) if on]
        return '<AgentHandler {} {}{}>'.format(
            self.id, self.name, ' ({})'.format(', '.join(states)) if states else '')

    def __eq__(self, other):
        """
        Two Agent Handlers are equal when their id and name are.
        """
        return isinstance(other, AgentHandler) and (self.id, self.name) == (other.id, other.name)

    def md_row(self):
        """
        Returns the columns of the Agent Handler table: id, name, DNS name,
        IP address, version, master, enabled, published DNS name and IP
        address, last communication.

        >>> AgentHandler(1, 'EPO01', 'epo01.example.com', '10.0.0.5', '5.10.0',
        ...              master=True).md_row()
        ['1', 'EPO01', 'epo01.example.com', '10.0.0.5', '5.10.0', 'Yes', 'Yes', '', '', '']
        """
        last = self.last_update.strftime('%Y-%m-%d %H:%M') if self.last_update else ''
        return [Policy.md_escape(value) for value in (
            self.id, self.name, self.dns_name, self.ip_address, self.version,
            'Yes' if self.master else 'No', 'Yes' if self.enabled else 'No',
            self.published_dns_name, self.published_ip, last)]


def agent_handlers_to_markdown(handlers, title='Agent Handlers'):
    """
    Returns the Agent Handlers as a Markdown table, by id.

    >>> print(agent_handlers_to_markdown([AgentHandler(1, 'EPO01', master=True)]))
    # Agent Handlers
    <BLANKLINE>
    | Id | Name | DNS Name | IP Address | Version | Master | Enabled | Published DNS Name | Published IP | Last Communication |
    |---|---|---|---|---|---|---|---|---|---|
    | 1 | EPO01 |  |  |  | Yes | Yes |  |  |  |
    """
    lines = ['# ' + Policy.md_heading(title), '',
             '| Id | Name | DNS Name | IP Address | Version | Master | Enabled | '
             'Published DNS Name | Published IP | Last Communication |',
             '|---|---|---|---|---|---|---|---|---|---|']
    for handler in sorted(handlers, key=lambda item: item.id):
        lines.append('| ' + ' | '.join(handler.md_row()) + ' |')
    return '\n'.join(lines)


def check_vendor_id(vendor_id):
    """
    Checks a virtual MAC vendor id: the first 3 bytes of the MAC addresses
    (the vendor part, OUI) as 6 hexadecimal digits; returns it in upper
    case, as the server lists them.

    Valid / invalid:

    >>> check_vendor_id('00059a')
    '00059A'
    >>> check_vendor_id('00:05:9A')
    Traceback (most recent call last):
    ...
    ValueError: A virtual MAC vendor id is 6 hexadecimal digits (the first 3 bytes of the MAC address, without separator): '00:05:9A'.
    """
    text = str(vendor_id).strip()
    if not re.fullmatch('[0-9A-Fa-f]{6}', text):
        raise ValueError('A virtual MAC vendor id is 6 hexadecimal digits (the first 3 bytes of '
                         'the MAC address, without separator): {!r}.'.format(vendor_id))
    return text.upper()


class MacVendor():
    """
    A Virtual MAC Vendor (Configuration > Server Settings > Virtual MAC
    Vendor): the systems whose MAC address starts with its id are virtual
    adapters (VPN, virtual machines...), not used to tell systems apart.
    """

    def __init__(self, vendor_id, note='', id=None):
        """
        :param: vendor_id: The vendor id: 6 hexadecimal digits.
        :param: note: The note (the vendor name).
        :param: id: The id of the server (autoID), None for a new vendor.
        :raise: ValueError: Not 6 hexadecimal digits.
        """
        self.vendor_id = check_vendor_id(vendor_id)
        self.note = note or ''
        self.id = id

    @classmethod
    def from_json(cls, data):
        """
        Returns the vendor of a line of ListAllVirtualMacVendorsCommand.

        >>> MacVendor.from_json({'note': 'NOT FOUND', 'autoID': 2, 'vendorID': '005345'})
        <MacVendor 005345 NOT FOUND>
        """
        return cls(data['vendorID'], data.get('note') or '', data.get('autoID'))

    def __repr__(self):
        """
        Shows the vendor id and the note.
        """
        return '<MacVendor {}>'.format(' '.join(item for item in (self.vendor_id, self.note)
                                                if item))

    def __eq__(self, other):
        """
        Two vendors are equal when their vendor id and note are.
        """
        return isinstance(other, MacVendor) and \
            (self.vendor_id, self.note) == (other.vendor_id, other.note)


def mac_vendors_to_markdown(vendors, title='Virtual MAC Vendors'):
    """
    Returns the virtual MAC vendors as a Markdown table, by vendor id.

    >>> print(mac_vendors_to_markdown([MacVendor('444553', 'Microsoft')]))
    # Virtual MAC Vendors
    <BLANKLINE>
    | Vendor ID | Note |
    |---|---|
    | 444553 | Microsoft |
    """
    lines = ['# ' + Policy.md_heading(title), '', '| Vendor ID | Note |', '|---|---|']
    for vendor in sorted(vendors, key=lambda item: item.vendor_id):
        lines.append('| {} | {} |'.format(vendor.vendor_id, Policy.md_escape(vendor.note)))
    return '\n'.join(lines)
