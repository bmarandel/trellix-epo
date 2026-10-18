# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOServer, the server settings operations of EPOClient
(epo.server): the Agent Handlers, the Virtual MAC Vendors, the registered
servers, and the custom agent install package (agentmgmt.* and
ComputerMgmt.* commands).

    epo.server.agent_handlers()                         # [AgentHandler...]
    epo.server.add_mac_vendor('00059A', 'Cisco VPN')    # MacVendor
    epo.server.custom_install_package('Windows')        # path of the ZIP on the server

The operations on systems and groups that use these settings are on
epo.systems and epo.groups: agent wake-up, deployment and transfer, the
agent deployment URL of a group (see the eposystemtree module).

Server behaviours handled here (checked on ePO 5.10 Update 7):
- the agent package of the commands (deployPath, agentPackage) is its path
  in the repository ("Current/EPOAGENT3000/Install/0409", the deploymentPath
  of repository.findPackages), not a System Tree path: the methods take
  the platform (Windows, Linux, Mac) or a Package and read the path in the
  repository (epo.repository.agent_package());
- ahId, fallBackAhId and primaryAgentHandler take the id (autoId) of
  agentmgmt.listAgentHandlers: the methods take the name or the id;
- ComputerMgmt.GetVirtualMacVendorCommand answers [] for an unknown or
  invalid vendor id; Add, edit and delete answer a message ("Virtual MAC
  Vendor IDs '0C1A0D' added.", "... updated.", "... deleted."), also written
  in the Audit Log: the methods read the vendor back;
- createCustomInstallPackageCmd answers "Your custom agent package is
  located here: <path on the server>" (the path is returned); the Web API
  can't delete the package.
"""

from .epo import EPOError
from .squid import Query
from .server import AgentHandler, MacVendor, check_vendor_id


def _package_path(answer):
    """
    Returns the path of the ZIP file in the answer of
    createCustomInstallPackageCmd ("Your custom agent package is located
    here: <path>"), or the answer when it has no path.

    >>> _package_path('Your custom agent package is located here: C:\\\\DB\\\\customAgentPackage.zip')
    'C:\\\\DB\\\\customAgentPackage.zip'
    """
    text = str(answer).strip()
    marker = 'located here:'
    return text[text.index(marker) + len(marker):].strip() if marker in text else text


class EPOServer():
    """
    The server settings operations of an EPOClient (epo.server).
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPOServer of {!r}>'.format(self.epo)

    # --------------------------- Agent Handlers ---------------------------
    def agent_handlers(self):
        """
        Returns the Agent Handlers of the server (agentmgmt.listAgentHandlers,
        Configuration > Agent Handlers), the ePO server itself included.

        Example: [handler.name for handler in epo.server.agent_handlers()].
        """
        return [AgentHandler.from_json(item)
                for item in self.epo.call('agentmgmt.listAgentHandlers')]

    def agent_handler(self, handler):
        """
        Returns an Agent Handler, or None.

        Example: epo.server.agent_handler('W2022EPO510'), epo.server.agent_handler(1).

        :param: handler: The id, the computer or DNS name (case
                         insensitive), or the AgentHandler.
        """
        if isinstance(handler, AgentHandler):
            handler = handler.id
        handlers = self.agent_handlers()
        if isinstance(handler, int):
            return next((item for item in handlers if item.id == handler), None)
        name = str(handler).lower()
        return next((item for item in handlers
                     if name in (item.name.lower(), item.dns_name.lower())), None)

    def agent_handler_id(self, handler):
        """
        Returns the id of an Agent Handler for the commands (ahId,
        primaryAgentHandler), or None for None.

        Example: epo.server.agent_handler_id('W2022EPO510') gives 1.

        :raise: ValueError: Unknown Agent Handler.
        """
        if handler is None:
            return None
        found = self.agent_handler(handler)
        if found is None:
            raise ValueError('Unknown Agent Handler: {}.'.format(
                handler.name if isinstance(handler, AgentHandler) else handler))
        return found.id

    # ------------------------- Registered servers -------------------------
    def registered_servers(self):
        """
        Returns the names of the registered servers (OrionRegisteredServers,
        Configuration > Registered Servers): the local ePO server, other ePO
        servers, TIE, OpenSearch... system.transfer takes the name of an ePO
        server of this list.

        Example: epo.server.registered_servers().
        """
        rows = self.epo.query(Query('OrionRegisteredServers').select('Name'))
        return [row['OrionRegisteredServers.Name'] for row in rows]

    # ------------------------ Virtual MAC Vendors -------------------------
    def mac_vendors(self):
        """
        Returns the Virtual MAC Vendors (ListAllVirtualMacVendorsCommand,
        Configuration > Server Settings > Virtual MAC Vendor).

        Example: epo.server.mac_vendors().
        """
        return [MacVendor.from_json(item)
                for item in self.epo.call('ComputerMgmt.ListAllVirtualMacVendorsCommand')]

    def mac_vendor(self, vendor_id):
        """
        Returns a Virtual MAC Vendor, or None.

        Example: epo.server.mac_vendor('444553').

        :param: vendor_id: The vendor id (6 hexadecimal digits) or MacVendor.
        :raise: ValueError: Not 6 hexadecimal digits.
        """
        if isinstance(vendor_id, MacVendor):
            vendor_id = vendor_id.vendor_id
        found = self.epo.call('ComputerMgmt.GetVirtualMacVendorCommand',
                              vendorId=check_vendor_id(vendor_id))
        return MacVendor.from_json(found[0]) if found else None

    def _require_vendor(self, vendor_id):
        """
        Returns a Virtual MAC Vendor, or raises ValueError when it doesn't
        exist.
        """
        found = self.mac_vendor(vendor_id)
        if found is None:
            raise ValueError('Unknown virtual MAC vendor: {}.'.format(
                vendor_id.vendor_id if isinstance(vendor_id, MacVendor) else vendor_id))
        return found

    def add_mac_vendor(self, vendor_id, note=''):
        """
        Adds a Virtual MAC Vendor (AddVirtualMacVendorCommand).

        Example: epo.server.add_mac_vendor('00059A', 'Cisco VPN').

        :param: vendor_id: The vendor id (6 hexadecimal digits) or a
                           MacVendor (its note then).
        :return: The vendor, read back.
        :raise: ValueError: Invalid id, or a vendor with this id already.
        :raise: EPOError: The vendor is not there after the command.
        """
        if isinstance(vendor_id, MacVendor):
            vendor_id, note = vendor_id.vendor_id, note or vendor_id.note
        vendor_id = check_vendor_id(vendor_id)
        if self.mac_vendor(vendor_id) is not None:
            raise ValueError('A virtual MAC vendor {} exists already.'.format(vendor_id))
        self.epo.call('ComputerMgmt.AddVirtualMacVendorCommand', vendorId=vendor_id,
                      vendorNote=note)
        return self._read_back('ComputerMgmt.AddVirtualMacVendorCommand', vendor_id)

    def edit_mac_vendor(self, vendor_id, new_vendor_id=None, note=None):
        """
        Changes the id or the note of a Virtual MAC Vendor (editMacVendor;
        the command takes both: the value left to None is kept).

        Example: epo.server.edit_mac_vendor('00059A', note='Cisco AnyConnect').

        :return: The vendor, read back.
        :raise: ValueError: Unknown vendor, invalid new id, nothing to change.
        :raise: EPOError: The vendor is not as changed after the command.
        """
        if new_vendor_id is None and note is None:
            raise ValueError('Give the new vendor id or the note.')
        vendor = self._require_vendor(vendor_id)
        new_id = vendor.vendor_id if new_vendor_id is None else check_vendor_id(new_vendor_id)
        self.epo.call('ComputerMgmt.editMacVendor', vendorId=vendor.vendor_id,
                      newVendorId=new_id, newVendorNote=vendor.note if note is None else note)
        changed = self._read_back('ComputerMgmt.editMacVendor', new_id)
        if note is not None and changed.note != note:
            raise EPOError('ComputerMgmt.editMacVendor', 'The note of {} is {!r}, not {!r}.'.format(
                new_id, changed.note, note))
        return changed

    def remove_mac_vendor(self, vendor_id):
        """
        Removes a Virtual MAC Vendor (deleteMacVendor).

        Example: epo.server.remove_mac_vendor('00059A').

        :return: True once removed.
        :raise: ValueError: Unknown vendor.
        :raise: EPOError: The vendor is still there after the command.
        """
        vendor = self._require_vendor(vendor_id)
        self.epo.call('ComputerMgmt.deleteMacVendor', vendorId=vendor.vendor_id)
        if self.mac_vendor(vendor.vendor_id) is not None:
            raise EPOError('ComputerMgmt.deleteMacVendor', '{} is still there.'.format(
                vendor.vendor_id))
        return True

    def _read_back(self, command, vendor_id):
        """
        Returns a vendor after a command, or raises EPOError when it is not
        there.
        """
        found = self.mac_vendor(vendor_id)
        if found is None:
            raise EPOError(command, 'The virtual MAC vendor {} is not there after the '
                           'command.'.format(vendor_id))
        return found

    # ----------------------- Custom install package -----------------------
    def custom_install_package(self, package='Windows', agent_handler=None,
                               fallback_agent_handler=None):
        """
        Creates an agent install package on the server
        (createCustomInstallPackageCmd, New Systems > "Create and download
        agent installation package" of the console, without the embedded
        credentials). The package is not tied to a group: the systems
        installed with it are sorted as new systems (System Tree sorting,
        else Lost and Found); give the IT administrators the deployment URL
        of a group instead (epo.groups.deployment_url()) to have them land
        in the group.

        Example: epo.server.custom_install_package('Windows', 'W2022EPO510').

        :param: package: Windows, Linux or Mac (the agent package of the
                         Current branch), a repository path or a Package.
        :param: agent_handler: The primary Agent Handler (name or id),
                               None for all the Agent Handlers.
        :param: fallback_agent_handler: The fallback Agent Handler.
        :return: The path of the ZIP file on the ePO server (short names:
                 "C:\\PROGRA~2\\Trellix\\EPOLIC~1\\DB\\CustomAgentPackages\\
                 customAgentPackage.zip" on the lab; the next package
                 replaces it): copy it from the server.
        :raise: ValueError: Unknown package or Agent Handler.
        """
        found = self.epo.repository.agent_package(package)
        answer = self.epo.call('ComputerMgmt.createCustomInstallPackageCmd',
                               deployPath=found.deployment_path,
                               ahId=self.agent_handler_id(agent_handler),
                               fallBackAhId=self.agent_handler_id(fallback_agent_handler))
        return _package_path(answer)
