"""
Agent operations and server settings (trellix_epo.server, trellix_epo.eposerver,
the agent methods of epo.systems and epo.groups, epo.repository.agent_package),
without a server.

Answers of the ePO 5.10 Update 7 lab (2026-10-18): agentmgmt.listAgentHandlers,
the Virtual MAC Vendors (test vendor 0C1A0D, deleted), the agent Install
packages of repository.findPackages, createAgentDeploymentUrlCmd (token
replaced) and createCustomInstallPackageCmd.
"""

import doctest
import json
import urllib.parse

import pytest

from trellix_epo import server as module
from trellix_epo import eposerver as operations
from trellix_epo import (EPOClient, AgentHandler, MacVendor, Package,
                         agent_handlers_to_markdown, mac_vendors_to_markdown)

HANDLERS = [{'lastKnownIp': '192.168.100.20', 'publishedDNSName': None, 'autoId': 1,
             'publishedNetBiosName': None, 'dnsName': 'W2022EPO510', 'version': '5.10.0',
             'enabled': True, 'masterHandler': True, 'publishedIP': None, 'versionMatch': 1,
             'computerName': 'W2022EPO510', 'lastUpdate': '2026-10-18T14:32:10+02:00',
             'key': None}]
VENDOR = {'note': 'Claude - Test', 'autoID': 6, 'vendorID': '0C1A0D'}
PACKAGES = [{'productID': 'EPOAGENT3000', 'productName': 'Trellix Agent for OT',
             'packageType': 'Install', 'packageBranch': 'Current',
             'productDetectionProductVersion': '5.8.7', 'buildNumber': '752',
             'hotFixVersion': '752', 'packageLangID': '0409',
             'deploymentPath': 'Current/EPOAGENT3000/Install/0409',
             'checkinDate': '2026-10-01T10:00:00+02:00'},
            {'productID': 'EPOAGENT3700LYNX', 'productName': 'Trellix Agent for LINUX',
             'packageType': 'Install', 'packageBranch': 'Current',
             'productDetectionProductVersion': '5.8.7', 'buildNumber': '752',
             'hotFixVersion': '752', 'packageLangID': '0409',
             'deploymentPath': 'Current/EPOAGENT3700LYNX/Install/0409',
             'checkinDate': '2026-10-01T10:00:00+02:00'},
            {'productID': 'ENDP_GS_1070', 'productName': 'Endpoint Security Platform',
             'packageType': 'Install', 'packageBranch': 'Current',
             'productDetectionProductVersion': '26.8.0', 'buildNumber': '22584',
             'packageLangID': '0000', 'checkinDate': '2026-10-17T10:30:05+02:00'}]
GROUPS = [{'EPOBranchNode.AutoID': 2, 'EPOBranchNode.NodeName': 'My Organization',
           'EPOBranchNode.ParentID': 1, 'EPOBranchNode.Type': 2, 'EPOBranchNode.Notes': '',
           'EPOBranchNode.NodeTextPath2': '\\My Organization\\'},
          {'EPOBranchNode.AutoID': 3, 'EPOBranchNode.NodeName': 'Lost and Found',
           'EPOBranchNode.ParentID': 2, 'EPOBranchNode.Type': 5, 'EPOBranchNode.Notes': '',
           'EPOBranchNode.NodeTextPath2': '\\My Organization\\Lost and Found\\'},
          {'EPOBranchNode.AutoID': 6, 'EPOBranchNode.NodeName': 'Workstations',
           'EPOBranchNode.ParentID': 2, 'EPOBranchNode.Type': 3, 'EPOBranchNode.Notes': '',
           'EPOBranchNode.NodeTextPath2': '\\My Organization\\Workstations\\'}]
URL = 'https://W2022EPO510:8443/ComputerMgmt/agentPackage.get?token=0123456789abcdef'
SERVERS = [{'OrionRegisteredServers.Name': 'W2022EPO510 (local Trellix ePO server)'},
           {'OrionRegisteredServers.Name': 'EPO-PARIS'}]


def ok(value):
    """
    Returns the answer of the server for a value (JSON encoded).
    """
    return 'OK:\r\n' + json.dumps(value) + '\r\n'


class FakeServer(EPOClient):
    """
    EPOClient whose server is a list of answers; the requests are kept in
    self.requests as (command, form fields).
    """

    def __init__(self, *answers):
        """
        :param: answers: The raw answers of the server, in order.
        """
        super(FakeServer, self).__init__('https://epo.example.com:8443', 'admin', 'secret')
        self.answers = list(answers)
        self.requests = []

    def _send(self, request):
        """
        Records the request and returns the next answer.
        """
        command = urllib.parse.urlsplit(request.full_url).path.split('/remote/')[1]
        self.requests.append((command, dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))))
        return self.answers.pop(0)


def test_docstring_examples():
    assert doctest.testmod(module).attempted >= 10 and doctest.testmod(module).failed == 0
    assert doctest.testmod(operations).failed == 0


def test_agent_handlers():
    epo = FakeServer(ok(HANDLERS), ok(HANDLERS), ok(HANDLERS))
    handlers = epo.server.agent_handlers()
    assert handlers == [AgentHandler(1, 'W2022EPO510')] and handlers[0].master
    assert handlers[0].last_update.tzinfo is not None
    assert epo.server.agent_handler_id('w2022epo510') == 1
    with pytest.raises(ValueError, match='Unknown Agent Handler: AH-DMZ'):
        epo.server.agent_handler_id('AH-DMZ')
    assert epo.server.agent_handler_id(None) is None
    assert '| 1 | W2022EPO510 | W2022EPO510 | 192.168.100.20 | 5.10.0 | Yes | Yes |' in \
        agent_handlers_to_markdown(handlers)


def test_mac_vendors():
    assert MacVendor('0c1a0d').vendor_id == '0C1A0D'
    for bad in ('0C1A0', '0C:1A:0D', 'ZZZZZZ', ''):
        with pytest.raises(ValueError, match='6 hexadecimal digits'):
            MacVendor(bad)
    # Add: not there, the command, read back.
    epo = FakeServer(ok([]), ok("Virtual MAC Vendor IDs '0C1A0D' added."), ok([VENDOR]))
    assert epo.server.add_mac_vendor('0c1a0d', 'Claude - Test') == MacVendor('0C1A0D',
                                                                              'Claude - Test')
    assert epo.requests[1] == ('ComputerMgmt.AddVirtualMacVendorCommand',
                               {'vendorId': '0C1A0D', 'vendorNote': 'Claude - Test'})
    epo = FakeServer(ok([VENDOR]))
    with pytest.raises(ValueError, match='exists already'):
        epo.server.add_mac_vendor('0C1A0D')
    # Edit: the command takes the id and the note, the one not given is kept.
    moved = dict(VENDOR, vendorID='0C1A0E')
    epo = FakeServer(ok([VENDOR]), ok("Virtual MAC Vendor ID '0C1A0D' updated."), ok([moved]))
    assert epo.server.edit_mac_vendor('0C1A0D', new_vendor_id='0C1A0E').vendor_id == '0C1A0E'
    assert epo.requests[1] == ('ComputerMgmt.editMacVendor', {
        'vendorId': '0C1A0D', 'newVendorId': '0C1A0E', 'newVendorNote': 'Claude - Test'})
    with pytest.raises(ValueError, match='Give the new vendor id or the note'):
        epo.server.edit_mac_vendor('0C1A0D')
    epo = FakeServer(ok([moved]), ok("Virtual MAC Vendor ID '0C1A0E' deleted."), ok([]))
    assert epo.server.remove_mac_vendor('0C1A0E') is True
    epo = FakeServer(ok([]))
    with pytest.raises(ValueError, match='Unknown virtual MAC vendor: 0C1A0E'):
        epo.server.remove_mac_vendor('0C1A0E')
    assert '| 0C1A0D | Claude - Test |' in mac_vendors_to_markdown([MacVendor.from_json(VENDOR)])


def test_agent_package():
    package = Package.from_json(PACKAGES[0])
    assert package.deployment_path == 'Current/EPOAGENT3000/Install/0409'
    assert (package.version, package.hotfix, package.agent_platform) == ('5.8.7', '752', 'Windows')
    epo = FakeServer(ok(PACKAGES), ok(PACKAGES), ok(PACKAGES))
    assert epo.repository.agent_package('linux').product_id == 'EPOAGENT3700LYNX'
    assert epo.repository.agent_package('Current\\EPOAGENT3000\\Install\\0409') == package
    with pytest.raises(ValueError, match='No Trellix Agent package for Mac'):
        epo.repository.agent_package('Mac')
    with pytest.raises(ValueError, match='must be one of Windows, Linux, Mac'):
        epo.repository.agent_package('Solaris')
    with pytest.raises(ValueError, match='Not an Install package of the Trellix Agent'):
        epo.repository.agent_package(Package.from_json(PACKAGES[2]))


def test_deployment_url():
    epo = FakeServer(ok(GROUPS), ok(PACKAGES), ok(HANDLERS), ok(URL))
    assert epo.groups.deployment_url('Workstations', 'Claude - URL Test',
                                     agent_handler='W2022EPO510') == URL
    assert epo.requests[-1] == ('ComputerMgmt.createAgentDeploymentUrlCmd', {
        'deployPath': 'Current/EPOAGENT3000/Install/0409', 'groupId': '6',
        'urlName': 'Claude - URL Test', 'agentVersionNumber': '5.8.7', 'agentHotFix': '752',
        'edit': 'true', 'ahId': '1'})
    epo = FakeServer(ok(GROUPS))
    with pytest.raises(ValueError, match='Lost and Found'):
        epo.groups.deployment_url('Lost and Found', 'x')
    epo = FakeServer(ok(GROUPS))
    with pytest.raises(ValueError, match='50 characters at most'):
        epo.groups.deployment_url('Workstations', 'x' * 51)


def test_custom_install_package():
    answer = ('Your custom agent package is located here: '
              'C:\\PROGRA~2\\Trellix\\EPOLIC~1\\DB\\CustomAgentPackages\\customAgentPackage.zip')
    epo = FakeServer(ok(PACKAGES), ok(answer))
    assert epo.server.custom_install_package() == \
        'C:\\PROGRA~2\\Trellix\\EPOLIC~1\\DB\\CustomAgentPackages\\customAgentPackage.zip'
    assert epo.requests[-1] == ('ComputerMgmt.createCustomInstallPackageCmd',
                                {'deployPath': 'Current/EPOAGENT3000/Install/0409'})


def test_wakeup():
    # Answer of the lab (the agent of the ePO server, 2026-10-18).
    epo = FakeServer(ok(GROUPS), ok('completed: 1\nfailed: 0\nexpired: 0'))
    assert epo.groups.wakeup('Workstations', subgroups=True, random_minutes=10) == {
        'completed': 1, 'failed': 0, 'expired': 0}
    assert epo.requests[-1] == ('system.wakeupAgent', {
        'groupId': '6', 'includeSubgroups': 'true', 'fullProps': 'false',
        'forceFullPolicyUpdate': 'false', 'superAgent': 'false', 'useAllHandlers': 'false',
        'randomMinutes': '10', 'retryIntervalSeconds': '60', 'attempts': '0',
        'abortAfterMinutes': '20'})
    epo = FakeServer(ok('done'))
    epo.systems.wakeup(14, force_full_policy_update=True)
    assert epo.requests[-1][1]['ids'] == '14'
    with pytest.raises(ValueError, match='abort_after must be a whole number'):
        epo.systems.wakeup(14, abort_after=1.5)


def test_deploy_agent():
    epo = FakeServer(ok(PACKAGES), ok('done'))
    epo.systems.deploy_agent(['PC01', '10.0.0.12'], 'admin', 'pass', domain='CORP')
    command, fields = epo.requests[-1]
    assert command == 'system.deployAgent' and fields['names'] == 'PC01,10.0.0.12'
    assert fields['agentPackage'] == 'Current/EPOAGENT3000/Install/0409'
    assert fields['inputSource'] == '1' and fields['skipIfInstalled'] == 'true'
    with pytest.raises(ValueError, match='user name of the systems is required'):
        FakeServer().systems.deploy_agent('PC01', '')
    epo = FakeServer(ok(PACKAGES))
    with pytest.raises(ValueError, match='not both'):
        epo.systems.deploy_agent(['PC01', 14], 'admin')
    epo = FakeServer(ok(PACKAGES), ok(HANDLERS))
    with pytest.raises(ValueError, match='Give an Agent Handler or use_all_agent_handlers'):
        epo.systems.deploy_agent('PC01', 'admin', agent_handler=1, use_all_agent_handlers=True)


def test_transfer():
    epo = FakeServer(ok(SERVERS), ok('done'))
    epo.systems.transfer(14, 'epo-paris')
    assert epo.requests[-1] == ('system.transfer', {'ids': '14', 'epoServer': 'EPO-PARIS'})
    epo = FakeServer(ok(SERVERS))
    with pytest.raises(ValueError, match='Unknown registered server: EPO-NOPE'):
        epo.systems.transfer(14, 'EPO-NOPE')
