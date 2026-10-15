"""
Tests of the Trellix Agent cipher suites (extension 5.8.7, read only):
settings AHService/CipherSuiteListTA587 (TLS 1.2) and
TLS13CipherSuiteListOpenssl (TLS 1.3), not shown by the console, read by the
agent 5.8.7.

ma_general_587.xml: export of the lab policies after the upgrade of the
extension EPOAGENTMETA from 5.8.6.314 to 5.8.7.232 (2026-10-15): the upgrade
added both lists with their default values and kept the legacy
CipherSuiteList5Openssl / CipherSuiteList5RSA.
ma_general_586.xml: policies of the extension 5.8.6 (no 5.8.7 list).
"""

import copy
from pathlib import Path

import pytest

from trellix_epo import TAPolicies, TAPolicyGeneral

FIXTURES = Path(__file__).parent / 'fixtures'


def load(file_name='ma_general_587.xml', name='My Default'):
    """Returns a copy of a General policy of a fixture as TAPolicyGeneral."""
    policies = TAPolicies()
    policies.load_from_file(str(FIXTURES / file_name))
    return TAPolicyGeneral(copy.deepcopy(policies.get_policy('General', name)))


def test_defaults_read_from_587_export():
    for name in ['My Default', 'Demo (Systray)']:
        policy = load(name=name)
        assert policy.cipher_suites == TAPolicyGeneral.DEFAULT_CIPHER_SUITES
        assert policy.tls13_cipher_suites == TAPolicyGeneral.DEFAULT_TLS13_CIPHER_SUITES
        legacy = policy.get_legacy_cipher_suites()
        assert legacy['CipherSuiteList5Openssl'][-1] == 'AES128-SHA'
        assert legacy['CipherSuiteList5RSA'][2] == 'EDH-RSA-AES256-SHA256'


def test_missing_before_587():
    policy = load('ma_general_586.xml')
    assert policy.cipher_suites is None and policy.tls13_cipher_suites is None
    assert 'Agent-to-server TLS' not in policy.to_markdown()


def test_read_only():
    policy = load()
    with pytest.raises(AttributeError):
        policy.cipher_suites = ['ECDHE-ECDSA-AES256-GCM-SHA384']
    with pytest.raises(AttributeError):
        policy.tls13_cipher_suites = ['TLS_AES_256_GCM_SHA384']


def test_markdown():
    policy = load()
    text = policy.to_markdown()
    assert '### Agent-to-server TLS (not shown by the console)' in text
    # md_table escapes the underscores.
    assert '| TLS 1.3 cipher suites | TLS\\_AES\\_256\\_GCM\\_SHA384, ' \
           'TLS\\_CHACHA20\\_POLY1305\\_SHA256, TLS\\_AES\\_128\\_GCM\\_SHA256 (default) |' in text
    # A list changed on the server side is shown without "(default)".
    policy.set_setting_value('AHService', 'CipherSuiteListTA587', 'ECDHE-ECDSA-AES256-GCM-SHA384')
    assert policy.cipher_suites == ['ECDHE-ECDSA-AES256-GCM-SHA384']
    assert '| TLS 1.2 cipher suites | ECDHE-ECDSA-AES256-GCM-SHA384 |' in policy.to_markdown()
