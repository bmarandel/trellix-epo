"""
ENS Web Control: values accepted by the console (Web Control 26.8.0.15512,
checked on the lab).

The rules come from the console pages (newGeneralPolicy.js/.jsp for the
Options, deviationCommon.js and deviationList.js for the Block and Allow
List, enforcementMessagingPolicy.jsp) and from the server classes
(ManageGeneral, ManageBlockAndAllowList, EnforcementDeviationPolicy); the
IP list, DNS name, URL and site pattern checks were run on the lab pages
with the same results as below.

wc_limits.xml: "Claude - WC Options Test", "Claude - WC Block Allow Test"
and "Claude - WC Messaging Test", copies written by the library at the
limits, imported and opened valid in the console (a 400 characters site
included; a site imported with a tab came back with a space, see
test_library_sites).
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import ESWCPolicies
from mcafee_epo_policies.es.wc import (ESWCPolicyOptions, ESWCPolicyBlockAllowList,
                                       ESWCPolicyMessaging, WCSite)
from mcafee_epo_policies.validators import (is_wc_ip_list, is_wc_gateway_ip_list,
                                            is_wc_domain_name, is_wc_reporter_url,
                                            is_wc_site_pattern)

FIXTURE = Path(__file__).parent / 'fixtures' / 'wc_limits.xml'


def load(cls, name):
    policies = ESWCPolicies()
    policies.load_from_file(str(FIXTURE))
    return cls(policies.get_policy(cls.TYPE, name))


# Cases run on the lab page, results as returned by the console functions
# (1 valid, 0 refused).
IP_LISTS = ['10.0.0.1', '10.0.0.1, 10.0.0.2', '172.16.0.0/16', '192.168.56-68.1-5', '10.0.0.5-5',
            '10.0.0.5-4', '10.0.0.1-10.0.0.9', 'fd00::1', '2001-2003:db8::1', 'fd00::/64',
            '10.0.0.0/33, bad', '10.0.0.0/8, bad', 'bad, 10.0.0.0/8', '', ' , ', '10.0.0.256',
            '010.0.0.1', '10.0.0', '10.0.0.0/0', '10.1-2-3.0.1', ' 10.0.0.1 ', 'fe80::1%eth0',
            '::ffff:10.0.0.1', 'server.example.com', '10.0.0.1;10.0.0.2', '0x1-0x2.0.0.1',
            '1-0x2.0.0.1', 'a-f::1', '1.2.3.4/32', '::/0', '::/128', '10.0.0.1,',
            '1.1.1.1,' * 1999 + '1.1.1.1', '1.1.1.1,' * 2000]
IP_LISTS_LAB = '1111000111010110100010100000100110'      # validateAgumentIPList
GATEWAYS = ['10.0.0.254', '10.0.0.254, fd00::1', '10.0.0.0/8', '10.0.0.1-5', '', 'server',
            '010.0.0.1', '::ffff:10.0.0.1', '10.0.0.256', ' 10.0.0.1 , 10.0.0.2', 'fe80::1%eth0',
            '1.1.1.1,' * 1998 + '1.1.1.1', '1.1.1.1,' * 1999 + '1.1.1.1']
GATEWAYS_LAB = '1100101101011'                           # validateGatewayIPList
DOMAINS = ['intranet', 'intranet.example.com', 'www.1example.com', 'a', 'a-', 'a-b', 'a.b',
           'ex_ample.com', 'example.com.', '-a.com', 'a1.b2.c3', 'A.COM', 'xn--bcher-kva.example',
           '1a', ' a.com', 'a..b']
DOMAINS_LAB = '1101011000111000'                         # validateDomainName
URLS = ['http://reporter.example.com:9121/', 'http://reporter.example.com/?a=1',
        'http://reporter.example.com/a;b/', 'reporter.example.com', 'https://10.0.0.1/',
        'ftp://10.0.0.1/x', 'ftps://h.example/', 'gopher://h.example/', 'http:/h.example/',
        'http://h.example:0/', 'http://h.example:65535/', 'http://h.example:65536/',
        'http://h.example:/', 'http://user:pw@h.example/', 'http://h_x.example/',
        'http://[fd00::1]/', 'http://h.example/a b', 'http://h.example/a#x', '', 'http://',
        'HTTP://H.EXAMPLE/', 'http://h.example/a%20b', 'http://h.example/a,b',
        'http://h.example/a=b']
URLS_LAB = '110111100010001011001000'                    # isValidWebReporterURLConfig
SITES = ['example.com', 'ab', 'abc', 'a b', '*.example.com', 'a<b', 'a>b', 'a\\b', 'a,b',
         'a\tb', 'http://example.com/path?x=1', '  ab  ', ' abc', 'www.example.com/path',
         'xn--bcher-kva.ch', 'b\u00fccher.ch', 'a;b', 'a"b', 'a|b', 'a%b', '::1', '10.0.0.1', 'a/b',
         '..']
SITES_LAB = '101000001110011111111110'                   # validatePattern
# The library goes on after a CIDR item, refuses the comma (the server
# splits the Add entry on it), the tab (lost by the policy export) and the
# surrounding blanks (trimmed by WCSite).
LIBRARY = {'10.0.0.0/8, bad': False, 'a,b': False, 'a\tb': False}


def cases(values, lab):
    assert len(values) == len(lab)
    return [(value, LIBRARY.get(value, flag == '1')) for value, flag in zip(values, lab)]


@pytest.mark.parametrize('text,valid', cases(IP_LISTS, IP_LISTS_LAB), ids=lambda value: repr(value)[:30])
def test_ip_list_rule(text, valid):
    assert is_wc_ip_list(text) is valid


@pytest.mark.parametrize('text,valid', cases(GATEWAYS, GATEWAYS_LAB), ids=lambda value: repr(value)[:30])
def test_gateway_rule(text, valid):
    assert is_wc_gateway_ip_list(text) is valid


@pytest.mark.parametrize('name,valid', cases(DOMAINS, DOMAINS_LAB))
def test_domain_rule(name, valid):
    assert is_wc_domain_name(name) is valid


@pytest.mark.parametrize('url,valid', cases(URLS, URLS_LAB))
def test_reporter_url_rule(url, valid):
    assert is_wc_reporter_url(url) is valid


@pytest.mark.parametrize('pattern,valid', cases(SITES, SITES_LAB))
def test_site_pattern_rule(pattern, valid):
    assert is_wc_site_pattern(pattern) is valid


def test_library_options():
    policy = load(ESWCPolicyOptions, 'Claude - WC Options Test')
    assert policy.get_gateway_ips() == ['10.0.0.254', 'fd00::1', '010.0.0.1']
    assert policy.get_landmark_dns() == 'intranet.example-corp.com'
    assert policy.get_excluded_ips()[:2] == ['192.168.56-68.1-5', '172.16.0.0/16']
    assert len(policy.get_web_reporter()['url']) == 50
    assert policy.check() == []


def test_options_limits():
    policy = load(ESWCPolicyOptions, 'Claude - WC Options Test')
    for addresses in [['10.0.0.0/8'], ['server'], ['10.0.0.1, 10.0.0.2'], ['']]:
        with pytest.raises(ValueError):
            policy.set_gateway_ips(addresses)
    for addresses in [['10.0.0.1-10.0.0.9'], ['10.0.0.0/8', 'bad'], ['1.1.1.1'] * 2000 + ['::1']]:
        with pytest.raises(ValueError):
            policy.set_excluded_ips(addresses)
    policy.set_excluded_ips(['1.1.1.1'] * 2000)     # 15999 characters
    assert policy.get_gateway_ips() == ['10.0.0.254', 'fd00::1', '010.0.0.1']
    for name in ['www.1example.com', 'a' * 256, 'a_b.com']:
        with pytest.raises(ValueError):
            policy.set_landmark_dns(name)
    policy.set_landmark_dns('')
    for url in ['http://reporter.example.com/' + 'a' * 23, 'gopher://h.example/']:
        with pytest.raises(ValueError):
            policy.set_web_reporter('0', url=url)
    with pytest.raises(ValueError):
        policy.set_web_reporter('0', user='U' * 51)
    assert len(policy.get_web_reporter()['url']) == 50


def test_library_sites():
    policy = load(ESWCPolicyBlockAllowList, 'Claude - WC Block Allow Test')
    sites = {site.pattern: site for site in policy.get_sites()}
    assert len(sites) == 7
    assert 's' * 245 in sites and 'l' * 400 in sites
    assert sites['trimmed.example'].note == 'note'
    assert sites['abc'].note == 'n' * 50
    # Imported with 'tab\there.example.com': the export wrote the tab raw in
    # the XML attribute, read back as a space (refused since then).
    with pytest.raises(ValueError):
        sites.pop('tab here.example.com').check()
    policy.set_sites(list(sites.values()))


def test_site_limits():
    policy = load(ESWCPolicyBlockAllowList, 'Claude - WC Block Allow Test')
    policy.set_sites([site for site in policy.get_sites() if '\t' not in site.pattern and
                      ' ' not in site.pattern])
    count = len(policy.get_sites())
    with pytest.raises(ValueError):
        policy.set_sites(policy.get_sites() + [WCSite('ABC')])
    for site in [WCSite('a,b,c'), WCSite('ab'), WCSite(' ab '), WCSite('a b c'),
                 WCSite('abc', '2'), WCSite('xyz', '0', 'n' * 51)]:
        with pytest.raises(ValueError):
            policy.add_site(site)
    policy.add_site(WCSite('ABC', '0'))        # replaces abc (case ignored)
    sites = policy.get_sites()
    assert len(sites) == count and sites[-1] == WCSite('ABC', '0')
    assert WCSite('  example.com ', '1', ' Blocked ').pattern == 'example.com'


def test_messages():
    policy = load(ESWCPolicyMessaging, 'Claude - WC Messaging Test')
    assert policy.get_message('szBlock') == 'B' * 100
    assert policy.get_message('szBlockDetail').startswith('<b>Line 1</b>\nxx')
    assert len(policy.get_message('szBlockDetail')) == 999
    assert len(policy.get_message('szLogoUrl')) == 254
    for message, text in [('szBlock', 'B' * 101), ('szBlock', ' '), ('szWarnZeroDay', ''),
                          ('szBlockDetail', 'x' * 1001), ('szLogoUrl', 'l' * 255)]:
        with pytest.raises(ValueError):
            policy.set_message(message, text)
    policy.set_message('szBlockDetail', '')
    policy.set_message('szLogoUrl', '')
    policy.set_message('szBlockDetail', 'a' * 500 + '\r\n' + 'b' * 499)
    assert len(policy.get_message('szBlockDetail')) == 1000
