# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESSPPolicyICAP (Endpoint Security Storage
Protection: ICAP Policies).

Storage learnt from a test policy changed in the ePO 5.10 console: the IP
addresses of the connection list are ICAPGeneral.szICAPClient_<n> (from 0)
with the count dwICAPClientCount.
"""

from .common import ESSPPolicy
from ...validators import check_int, is_sp_ipv4


class ESSPPolicyICAP(ESSPPolicy):
    """
    The ESSPPolicyICAP class can be used to edit the Endpoint Security
    Storage Protection policy: ICAP Policies (console tabs Connections and
    Server, Scan Items, Performance, Actions, Reports).
    """
    PREFIX = 'ICAP'
    TYPE = 'VSES1000_Icap_Policies'
    MD_CATEGORY = 'ICAP Policies'
    # The console offers no "Delete" action for ICAP.
    PRIMARY_ACTIONS = [ESSPPolicy.CLEAN, ESSPPolicy.CONTINUE]
    SECONDARY_ACTIONS = [ESSPPolicy.CONTINUE]

    # ------------------------------ Connections and Server ------------------------------
    def get_overwrite_connection_list(self):
        """
        Get state of Overwrite client's connection list ('1' or '0').
        """
        return self._get('General', 'bOverwriteLocalConnectionList')

    def set_overwrite_connection_list(self, mode):
        """
        Set state of Overwrite client's connection list ('1' or '0').
        """
        return self._set('General', 'bOverwriteLocalConnectionList', mode)

    overwrite_connection_list = property(get_overwrite_connection_list,
                                         set_overwrite_connection_list)

    def get_filter_connections(self):
        """
        Get state of Accept connections and scan requests from these IP
        addresses only ('1' or '0').
        """
        return self._get('General', 'bFilterConnections')

    def set_filter_connections(self, mode):
        """
        Set state of Accept connections and scan requests from these IP
        addresses only ('1' or '0').
        """
        return self._set('General', 'bFilterConnections', mode)

    filter_connections = property(get_filter_connections, set_filter_connections)

    def get_connection_list(self):
        """
        Get the connection list: IP addresses of the ICAP clients.
        """
        return self.get_indexed_list('ICAPGeneral', 'dwICAPClientCount', 'szICAPClient_{}') or []

    def set_connection_list(self, addresses):
        """
        Set the connection list: IP addresses of the ICAP clients (see
        is_sp_ipv4; the console flags an invalid address and refuses a
        duplicate).
        """
        addresses = [str(address) for address in addresses]
        for index, address in enumerate(addresses):
            if not is_sp_ipv4(address):
                raise ValueError('Invalid ICAP client address: {!r}'.format(address))
            if address in addresses[:index]:
                raise ValueError('Duplicate ICAP client address: {!r}'.format(address))
        return self.set_indexed_list('ICAPGeneral', 'dwICAPClientCount', 'szICAPClient_{}',
                                     addresses)

    connection_list = property(get_connection_list, set_connection_list)

    def get_overwrite_server_config(self):
        """
        Get state of Overwrite ICAP server configuration on each client ('1' or '0').
        """
        return self._get('General', 'bOverwriteServerConfig')

    def set_overwrite_server_config(self, mode):
        """
        Set state of Overwrite ICAP server configuration on each client ('1' or '0').
        """
        return self._set('General', 'bOverwriteServerConfig', mode)

    overwrite_server_config = property(get_overwrite_server_config, set_overwrite_server_config)

    def get_bind_address(self):
        """
        Get the ICAP server Bind address.
        """
        return self._get('General', 'szBindAddress')

    def set_bind_address(self, address):
        """
        Set the ICAP server Bind address (an IPv4 address, the first number
        up to 223, see is_sp_ipv4; 0.0.0.0 = all the interfaces).
        """
        if not is_sp_ipv4(address) or len(str(address)) > 15:
            raise ValueError('Invalid bind address: {!r}'.format(address))
        return self._set('General', 'szBindAddress', str(address))

    bind_address = property(get_bind_address, set_bind_address)

    def get_port(self):
        """
        Get the ICAP server Port number.
        """
        value = self._get('General', 'dwPort')
        return int(value) if value is not None else None

    def set_port(self, port):
        """
        Set the ICAP server Port number (1-65535).
        """
        return self._set('General', 'dwPort', check_int('Port', port, 1, 65535))

    port = property(get_port, set_port)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        overwrite = self.get_overwrite_connection_list()
        connection = self._md_tab(
            'Specify the ICAP server configuration and the list of IP addresses to accept '
            'connections from', [
                ('Connection list', [
                    ["Overwrite client's connection list (This scan server accepts ICAP "
                     "requests from the IP addresses in this list)", self.md_check(overwrite)],
                    ['Accept connections and scan requests from these IP addresses only',
                     self.md_check(self.get_filter_connections())]])])
        if overwrite == '1':
            connection += '\n' + self.md_table(['IP Address'], [
                [address] for address in self.get_connection_list()], numbered=True)
        overwrite_server = self.get_overwrite_server_config()
        rows = [['Overwrite ICAP server configuration on each client',
                 self.md_check(overwrite_server)]]
        if overwrite_server == '1':
            rows += [['Bind address', self.get_bind_address()], ['Port number', self.get_port()]]
        connection += '\n### ICAP Server Configuration\n\n' + self.md_settings(rows)
        return [('Connections and Server', connection),
                ('Scan Items', self._md_scan_items()),
                ('Performance', self._md_performance()),
                ('Actions', self._md_actions_tab()),
                ('Reports', self._md_reports())]
