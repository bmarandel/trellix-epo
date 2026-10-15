"""
ENS Firewall Options, against fw_options.xml: a copy of "My Default" from the
lab ePO 5.10 with two DNS Blocking domains, one Defined Network and one
Trusted Executable added in the console. The setting names are the console
form field names (checked with the browser developer tools).
"""

from pathlib import Path

import pytest

from trellix_epo import ESFWPolicyOptions

FIXTURE = Path(__file__).parent / 'fixtures' / 'fw_options.xml'


@pytest.fixture
def fw_options():
    policy = ESFWPolicyOptions()
    policy.load_from_file(str(FIXTURE))
    return policy


def test_read(fw_options):
    assert fw_options.get_name() == 'Claude - FW Options Test'
    assert fw_options.firewall == '1'
    assert fw_options.get_option('MergeRules') == '1'
    assert fw_options.gti_incoming_threshold == '-100'
    assert fw_options.tcp_timeout == 30
    assert fw_options.udp_icmp_timeout == 30
    assert fw_options.blocked_domains == ['blocked.example.com', '*.claudetest.example']
    assert fw_options.defined_networks == [
        {'type': 'SingleIP', 'address': '192.168.100.20', 'trusted': '1'}]
    assert fw_options.trusted_executables == [
        {'name': 'Claude test tool', 'path': 'C:\\Tools\\claudetest.exe', 'description': '',
         'hash': '', 'signature': '', 'note': 'Claude test note'}]


def test_write(fw_options):
    assert fw_options.set_option('LogAllAllowed', '1')
    assert fw_options.get_option('LogAllAllowed') == '1'
    assert not fw_options.set_option('Unknown', '1')
    fw_options.gti_outgoing_threshold = '50'
    assert fw_options.gti_outgoing_threshold == '50'
    with pytest.raises(ValueError):
        fw_options.gti_outgoing_threshold = '40'
    with pytest.raises(ValueError):
        fw_options.tcp_timeout = 241
    fw_options.blocked_domains = ['a.example']
    assert fw_options.blocked_domains == ['a.example']
    fw_options.defined_networks = [{'type': 'Subnet', 'address': '10.0.0.0/8', 'trusted': '0'},
                                   {'type': 'AnyLocalIP', 'address': '', 'trusted': '1'}]
    assert len(fw_options.defined_networks) == 2
    assert fw_options.get_option('_AddressType') == '2'
    fw_options.trusted_executables = []
    assert fw_options.trusted_executables == []
    assert fw_options.get_option('_TrustedExeName') == '0'


def test_markdown(fw_options):
    text = fw_options.to_markdown()
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. Firewall', '## 2. Protection Options (Windows only)',
                        '## 3. Tuning Options',
                        '## 4. Trellix GTI Network Reputation (Windows only)',
                        '## 5. Stateful Firewall', '## 6. Firewall Status Control',
                        '## 7. DNS Blocking', '## 8. Defined Networks',
                        '## 9. Trusted Executables (Windows only)', '## 10. Document control']
    assert '| Enable Firewall | Yes |' in text
    assert '| Retain existing user-added rules and Adaptive mode rules when this policy is ' \
        'enforced | Yes |' in text
    assert '| Incoming network-reputation threshold | Do not block |' in text
    assert '| If Trellix GTI ratings server is not reachable | Block traffic |' in text
    # Sub-options hidden by the console when their parent is unchecked.
    assert 'Enable Observe mode' not in text
    assert 'Retain user-disabled Firewall status' not in text
    assert '| 2 | \\*.claudetest.example |' in text
    assert '| 1 | Single IP address | 192.168.100.20 | Trusted |' in text
    assert '| 1 | Claude test tool | C:\\\\Tools\\\\claudetest.exe |  |  |  | Claude test note |' \
        in text
