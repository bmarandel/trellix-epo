"""
ENS Firewall: values accepted by the console (Firewall 26.8, checked on the
lab).

The rules come from the console pages (EditFWOpts.jsp, fw/rules/ip.js,
firecore/validation.js, fw/rules/transport.jspf, location.jspf,
ExecutableEditInc.jsp); the address, port, path, registry and domain checks
were run through the console code (jsc and the lab pages) with the same
results as below. The signer checks are those of the server
(/ENDP_FW_META/ExecutableValidateSignerName.do, the same rules as the
Threat Prevention one).

fw_options_limits.xml: "My Default" and "Claude - ENS FW Options Test", a
copy saved in the console with one Defined Network of each address type and
a Trusted Executable with a file description only and "Allow any signature".
"""

import copy
from pathlib import Path

import pytest

from mcafee_epo_policies import ESFWPolicies, ESFWPolicyOptions
from mcafee_epo_policies.es.fw.rules import (FWAddress, FWNetwork, FWExecutable,
                                             FWLocation, FWRule, FWGroup)
from mcafee_epo_policies.validators import (is_fw_host, is_fw_port, is_fw_defined_network,
                                            is_x500_name)

FIXTURE = Path(__file__).parent / 'fixtures' / 'fw_options_limits.xml'


def load(name):
    policies = ESFWPolicies()
    policies.load_from_file(str(FIXTURE))
    return ESFWPolicyOptions(copy.deepcopy(policies.get_policy('FW_StatusMode', name)))


# Results of validHost (network dialog of a rule) on the lab page.
HOSTS = [('10.0.0.1', True), ('010.0.0.1', False), ('10.0.0.256', False), ('0.0.0.0', False),
         ('::', False), ('::1', True), ('FD00::1', True), ('fd00:::1', False),
         ('::ffff:10.0.0.1', True), ('10.0.0.0/8', True), ('10.0.0.0/33', False),
         ('10.0.0.0/0', False), ('fd00::/64', True), ('fd00::/129', False),
         ('10.0.0.1-10.0.0.9', True), ('10.0.0.9-10.0.0.10', True), ('10.0.0.9-10.0.0.1', False),
         ('fd00::1-fd00::9', True), ('fd00::9-fd00::1', False), ('10.0.0.1-fd00::1', False),
         ('server.example.com', True), ('*.example.com', False), ('server', False),
         ('Server.Example.COM', True), ('a_b.com', False), ('fe80::1%eth0', False),
         ('1.2.3.4.5', False), ('10.0.0.1/8', True), (' 10.0.0.1', False), ('abc.def', True),
         ('dead:beef::', False), ('host-1.corp.local', True), ('10.0.0.0/08', True)]
# Results of TRANSPORT.validatePort on the lab page.
PORTS = [('80', True), ('0', False), ('65535', True), ('65536', False), ('1000-2000', True),
         ('2000-1000', False), ('80-80', False), (' 80 ', True), ('80 - 90', True),
         ('80-90x', False), ('-1', False), ('http', False), ('1-65535', True), ('007', True),
         ('80-', False), ('-80', False)]
# Results of DEFINED_NETWORKS.definedNetworksValidator on the lab page.
DEFINED = [('SingleIP', '10.0.0.1', True), ('SingleIP', ' 10.0.0.1 ', True),
           ('SingleIP', 'fe80::1%eth0', False), ('SingleIP', '10.0.0.0/8', False),
           ('Subnet', '10.0.0.0/8', True), ('Subnet', '10.0.0.0 /8', False),
           ('Subnet', 'fd00::/64', True), ('Subnet', '10.0.0.1/8/9', True),
           ('Range', '10.0.0.1-10.0.0.9', True), ('Range', '10.0.0.9-10.0.0.1', False),
           ('Range', '10.0.0.1', True), ('Range', '10.0.0.0/8', True),
           ('Range', '10.0.0.1-10.0.0.9, 10.1.0.1-10.1.0.9', False),
           ('Range', 'fd00::1-fd00::9', True), ('FQDN', 'server.example.com', True),
           ('FQDN', 'server', False), ('FQDN', '*.example.com', False),
           ('FQDN', 'server.example.c', False), ('FQDN', 'a' * 64 + '.com', False)]
# Results of the server signer check (Firewall and Threat Prevention).
SIGNERS = [('CN=Intel Corporation, STREET=2200 Mission College Blvd, POSTALCODE=95054, C=US', True),
           ('POBOX=1', True), ('DESCRIPTION=x', True), ('NAME=x', False), ('SN=x', False),
           ('CN=a,,O=b', False), ('Microsoft Corporation', False)]


def test_console_cases():
    for value, valid in HOSTS:
        assert is_fw_host(value) == valid, value
    for value, valid in PORTS:
        assert is_fw_port(value) == valid, value
    for kind, value, valid in DEFINED:
        assert is_fw_defined_network(kind, value) == valid, (kind, value)
    for value, valid in SIGNERS:
        assert is_x500_name(value) == valid, value


def test_options_console_rebuild():
    """
    The Defined Networks and the Trusted Executable entered in the console,
    applied with the library to "My Default", give the settings the console
    saved.
    """
    policy, console = load('My Default'), load('Claude - ENS FW Options Test')
    policy.defined_networks = [
        {'type': 'SingleIP', 'address': '10.0.0.1', 'trusted': '1'},
        {'type': 'Subnet', 'address': '10.10.0.0/16', 'trusted': '0'},
        {'type': 'LocalSubnet', 'address': '', 'trusted': '1'},
        {'type': 'Range', 'address': '10.20.0.1-10.20.0.50', 'trusted': '0'},
        {'type': 'FQDN', 'address': 'server.example.com', 'trusted': '1'},
        {'type': 'AnyIPv4', 'address': '', 'trusted': '0'},
        {'type': 'AnyIPv6', 'address': '', 'trusted': '1'},
        {'type': 'AnyLocalIP', 'address': '', 'trusted': '0'}]
    policy.trusted_executables = [{'name': 'Claude Any Signer',
                                   'description': 'Claude description only',
                                   'signature': ESFWPolicyOptions.ANY_SIGNATURE}]
    assert policy.defined_networks == console.defined_networks
    assert policy.trusted_executables == console.trusted_executables


def test_options_checks():
    policy = load('My Default')
    for setter, minimum, maximum in [('set_tcp_timeout', 1, 240),
                                     ('set_udp_icmp_timeout', 1, 300)]:
        getattr(policy, setter)(str(maximum))
        for value in (minimum - 1, maximum + 1, 'ten'):
            with pytest.raises(ValueError):
                getattr(policy, setter)(value)
    policy.blocked_domains = ['*', '*.example.com', 'ads?.example.org']
    for domains in [['example'], ['a b.com'], ['x.example.com', 'x.example.com'], ['-.com']]:
        with pytest.raises(ValueError):
            policy.blocked_domains = domains
    for network in [{'type': 'SingleIP', 'address': '10.0.0.0/8', 'trusted': '1'},
                    {'type': 'AnyIPv4', 'address': '10.0.0.1', 'trusted': '1'},
                    {'type': 'FQDN', 'address': 'server', 'trusted': '1'},
                    {'type': 'SingleIP', 'address': '10.0.0.1', 'trusted': 'yes'}]:
        with pytest.raises(ValueError):
            policy.defined_networks = [network]
    for executable in [{'name': 'x'}, {'name': '', 'path': 'a.exe'},
                       {'name': 'x', 'path': 'C:\\a\\\\b.exe'}, {'name': 'x', 'hash': 'abc'},
                       {'name': 'x', 'signature': 'Contoso'},
                       {'name': 'x', 'path': 'a.exe', 'note': 'n' * 3001}]:
        with pytest.raises(ValueError):
            policy.trusted_executables = [executable]


def test_rule_network_storage():
    # Network saved in the console: "Fully qualified domain name"
    # Claude.Example.COM and "Any local IP address" (stored sorted).
    network = FWNetwork('Claude Test Network', ['Claude.Example.COM', FWAddress.ANY_LOCAL_IP])
    values = network.to_values(FWNetwork.REMOTE)
    assert sorted([values['+RemoteAddress#0'], values['+RemoteAddress#1']]) == \
        ['[local]', 'claude.example.com']
    assert FWAddress.from_epo('[local]') == FWAddress.ANY_LOCAL_IP


def test_rule_checks():
    FWRule('x', transport_protocol=FWRule.TCP, local_ports=['80', '1000-2000'],
           remote_networks=[FWNetwork('n', ['10.0.0.0/8', 'host-1.corp.local',
                                            FWAddress.ANY_LOCAL_IP])]).check()
    bad = [dict(transport_protocol=FWRule.TCP, local_ports=['2000-1000']),
           dict(transport_protocol=FWRule.UDP, remote_ports=['http']),
           dict(remote_networks=[FWNetwork('n', ['*.example.com'])]),
           dict(remote_networks=[FWNetwork('n', ['10.0.0.9-10.0.0.1'])]),
           dict(network_protocols=[FWRule.IPV4, '2054']),
           dict(network_protocols=['70000'])]
    for kwargs in bad:
        with pytest.raises(ValueError):
            FWRule('x', **kwargs).check()
    FWRule('x', network_protocols=['2054']).check()
    rule = FWRule('x')
    rule.set_schedule(['Monday'], '18:00', '08:00')
    with pytest.raises(ValueError):
        rule.check()
    with pytest.raises(ValueError):
        FWGroup('g', timed_minutes=61).check()
    FWGroup('g', timed_minutes=60).check()


def test_executable_and_location_checks():
    FWExecutable('x', description='Contoso tool').check()      # a description is enough
    FWExecutable('x', path='/usr/bin/curl', signer=FWExecutable.ANY_SIGNATURE).check()
    FWExecutable('x', path='**\\app.exe', signer='CN=Contoso, POSTALCODE=1, C=US').check()
    for kwargs in [dict(path='C:\\a\\\\b.exe'), dict(path='a|b.exe'), dict(md5='z' * 32),
                   dict(signer='Contoso'), dict()]:
        with pytest.raises(ValueError):
            FWExecutable('x', **kwargs).check()
    FWLocation('Office', dns_suffixes=['*.corp.example.com'], dns_servers=['10.0.0.53'],
               domains_reachable=['dc.corp.example.com'],
               registry_key='HKEY_LOCAL_MACHINE\\SOFTWARE\\Contoso\\Office=1').check()
    for kwargs in [dict(dns_suffixes=['corp']), dict(dns_servers=['10.0.0.0/8']),
                   dict(domains_reachable=['*.example.com']),
                   dict(registry_key='HKLM\\SOFTWARE\\Contoso\\Office=1'),
                   dict(registry_key='HKEY_USERS\\Value')]:
        with pytest.raises(ValueError):
            FWLocation('Office', **kwargs).check()


def test_unchanged_trellix_values():
    """
    Some Trellix-defined rules hold values the console dialogs refuse (the
    network address ::, the path *\\Windows\\system32\\spoolsv.exe, both in view
    only rules of the console fixture): the objects read from the policy are
    not checked again by update_rule (check(unchanged)), new ones are.
    """
    from mcafee_epo_policies import ESFWPolicyRules
    policy = ESFWPolicyRules()
    policy.load_from_file(str(Path(__file__).parent / 'fixtures' / 'fw_console.xml'))
    policy.load_policy()
    rule = policy.get_rule('Allow inbound traffic from special IP addresses')
    with pytest.raises(ValueError):
        rule.check()
    stored = [obj for obj, _ in rule.all_aggregates()]
    rule.check(stored)
    rule.remote_networks.append(FWNetwork('Bad', ['::']))
    with pytest.raises(ValueError):
        rule.check(stored)
