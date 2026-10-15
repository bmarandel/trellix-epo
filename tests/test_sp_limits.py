"""
ENS Storage Protection: values accepted by the console (lab Storage
Protection 2.4.0.694; local zip 2.4.0.692, the checks compared function by
function on the lab pages).

The rules come from the ICAP and NetApp pages (EditIcapPolicy.jsp,
EditNetappPolicy.jsp, ExclusionsTemplate.jsp, Common.js, VSECommon.js): the
number fields only let digits be typed (maximum scan time 10-9999 in 4
digits, scan threads 1-800 in 3, log size 1-999 in 3, port 1-65535), the
ICAP addresses digits and dots, the NetApp filers letters, digits and dots.
The address, file type and exclusion checks were run on the lab pages with
the same results as below.

sp_limits.xml: "Claude - ENSSP ICAP Test" and "Claude - ENSSP NetApp Test",
copies written by the library at the limits, imported and opened valid in
the console.
"""

from pathlib import Path

import pytest

from trellix_epo.es.sp import (ESSPPolicies, ESSPPolicyICAP, ESSPPolicyNetApp,
                                       SPExclusion)
from trellix_epo.validators import (is_sp_ipv4, is_sp_filer, is_sp_file_type,
                                            is_sp_exclusion_pattern, is_sp_exclusion_file_type)

FIXTURE = Path(__file__).parent / 'fixtures' / 'sp_limits.xml'


def load(cls, name):
    policies = ESSPPolicies()
    policies.load_from_file(str(FIXTURE))
    return cls(policies.get_policy(cls.TYPE, name))


def cases(values, lab):
    assert len(values) == len(lab)
    return [(value, flag == '1') for value, flag in zip(values, lab)]


# IsValidBindAddressFormat / IsValidIPAddressFormat2 of the ICAP page (the
# cases with a letter or a space, which cannot be typed, are left out).
ICAP_IPS = cases(['0.0.0.0', '223.255.255.255', '224.0.0.1', '10.0.0', '10.0.0.1.1',
                  '010.000.0.1', '256.0.0.1', '10..0.1', '0.1.2.3', '1.0.0.0', '1.2.3.04'],
                 '11000100111')
# IsValidIPAddressFormat2 of the NetApp page (first number 1-223).
FILERS = cases(['0.0.0.0', '223.255.255.255', '224.0.0.1', '10.0.0', '10.0.0.1.1',
                '010.000.0.1', '256.0.0.1', '10..0.1'], '01000100')
# validateFileTypes (each space-separated item).
FILE_TYPES = cases(['doc', 'docx', 'do?', '*', ':::', 'a:b', 'a/b', 'a"b', 'a|b', 'a<b', 'a\\b',
                    '::'], '101110000000')
# IsValidExclusionPattern + IsValidAmcoreExclusionPattern.
PATTERNS = cases(['C:\\Data\\', '/vol/data', 'a|b', 'a<b', '\\', '\\\\', '\\?', '\\?\\', '\\\\?',
                  '\\\\\\x', '\\\\?\\x', '\\?\\\\x', '\\\\server\\share\\', '*.log', 'C:\\a?b*',
                  '\\x', '\\?x'], '10000000000011111')
# IsValidExclusionFileType.
EXCLUSION_TYPES = cases(['tmp', ':::', 'a:b', 'a/b', 'a"b', 'abcdefghij', 'a\\b', '*', 'a b'],
                        '110001011')


@pytest.mark.parametrize('address,valid', ICAP_IPS)
def test_icap_address_rule(address, valid):
    assert is_sp_ipv4(address) is valid


@pytest.mark.parametrize('filer,valid', FILERS + [('filer01', True), ('filer-01', False),
                                                  ('filer01.example', False)])
def test_filer_rule(filer, valid):
    assert is_sp_filer(filer) is valid


@pytest.mark.parametrize('file_type,valid', FILE_TYPES)
def test_file_type_rule(file_type, valid):
    assert is_sp_file_type(file_type) is valid


@pytest.mark.parametrize('pattern,valid', PATTERNS)
def test_exclusion_pattern_rule(pattern, valid):
    assert is_sp_exclusion_pattern(pattern) is valid


@pytest.mark.parametrize('file_type,valid', EXCLUSION_TYPES)
def test_exclusion_file_type_rule(file_type, valid):
    assert is_sp_exclusion_file_type(file_type) is valid


def test_icap_limits():
    policy = load(ESSPPolicyICAP, 'Claude - ENSSP ICAP Test')
    assert policy.get_bind_address() == '223.255.255.255'
    assert policy.get_port() == 65535
    assert policy.get_connection_list() == ['1.2.3.4', '0.0.0.1', '010.000.0.1']
    assert (policy.get_max_scan_time(), policy.get_scan_threads()) == (9999, 800)
    assert policy.get_reporting()['max_size_mb'] == '999'
    for setter, value in [(policy.set_bind_address, '224.0.0.1'), (policy.set_port, 0),
                          (policy.set_port, 65536), (policy.set_max_scan_time, 9),
                          (policy.set_max_scan_time, 10000), (policy.set_scan_threads, 0),
                          (policy.set_scan_threads, 801), (policy.set_connection_list, ['::1']),
                          (policy.set_connection_list, ['1.2.3.4', '1.2.3.4'])]:
        with pytest.raises(ValueError):
            setter(value)
    for size in [0, 1000]:
        with pytest.raises(ValueError):
            policy.set_reporting(log_to_file='1', max_size_mb=size)
    assert policy.get_reporting()['max_size_mb'] == '999'
    with pytest.raises(ValueError):
        policy.set_file_types_to_scan(policy.SPECIFIED_ONLY, ['doc', 'docx'])
    policy.set_file_types_to_scan(policy.SPECIFIED_ONLY, ['doc', 'xl?'], no_extension=True)
    policy.set_bind_address('0.0.0.0')


def test_netapp_limits():
    policy = load(ESSPPolicyNetApp, 'Claude - ENSSP NetApp Test')
    assert policy.get_filer_list() == ['filer01', '10.0.0.5']
    exclusions = policy.get_exclusions()
    assert [len(exclusion.value) for exclusion in exclusions] == [100, 15, 5, 10, 3, 4, 1]
    policy.set_exclusions(exclusions)
    for filers in [['filer.corp'], ['0.0.0.0'], ['filer01', 'filer01']]:
        with pytest.raises(ValueError):
            policy.set_filer_list(filers)
    for exclusion in [SPExclusion.pattern('C:\\Data', True), SPExclusion.pattern('x' * 101),
                      SPExclusion.pattern(''), SPExclusion.pattern('/vol'),
                      SPExclusion.file_type('abcdefghijk'), SPExclusion.file_type('a:b'),
                      SPExclusion.file_age(0), SPExclusion.file_age(10000),
                      SPExclusion(SPExclusion.MODIFIED, '1a')]:
        with pytest.raises(ValueError):
            policy.add_exclusion(exclusion)
    assert policy.add_exclusion(SPExclusion.pattern('D:\\Scratch\\', True))
