"""
Tests for SCCCPolicyRules (Solidcore Change Control Rules), using real ePO
exports of policies built with this library, imported into ePO and exported
back (sc_cc_rules_win.xml, sc_cc_rules_unix.xml). The Windows policy was
created from a copy of a policy edited in the ePO console (Read-Protect
exclusion of C:\\Claude\\secret.txt, Write-Protect of C:\\Claude\\wp.cfg and of
HKEY_LOCAL_MACHINE\\SOFTWARE\\Claude).
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import SCCCPolicyRules

FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.fixture
def win_policy():
    return SCCCPolicyRules(et.parse(str(FIXTURES / 'sc_cc_rules_win.xml')).getroot())


@pytest.fixture
def unix_policy():
    return SCCCPolicyRules(et.parse(str(FIXTURES / 'sc_cc_rules_unix.xml')).getroot())


def test_metadata(win_policy, unix_policy):
    assert win_policy.get_type() == 'CC Rules (Windows)'
    assert unix_policy.get_type() == 'CC Rules (Unix)'
    assert win_policy.get_product() == 'SCOR_CC'
    assert win_policy.get_rule_group_names() == []


def test_read_protect(win_policy):
    assert win_policy.get_read_protect_list() == [
        {'pattern': 'C:\\Claude\\secret.txt', 'action': 'Exclude'},
        {'pattern': 'C:\\E2E\\Secrets\\', 'action': 'Include'},
        {'pattern': 'C:\\E2E\\Secrets\\public.txt', 'action': 'Exclude'}]
    assert not win_policy.add_read_protect('C:\\E2E\\Secrets\\')
    assert win_policy.add_read_protect('D:\\Keys\\')
    assert win_policy.get_rule('rp-file', {'pattern': 'D:\\Keys\\'}) == {
        'action': 'Include', 'pattern': 'D:\\Keys\\', 'type': 'rp-file'}
    assert win_policy.remove_read_protect('D:\\Keys\\')
    assert not win_policy.remove_read_protect('D:\\Keys\\')


def test_write_protect(win_policy, unix_policy):
    assert {'pattern': 'C:\\E2E\\app.cfg', 'action': 'Include'} in win_policy.get_write_protect_file_list()
    assert win_policy.get_write_protect_registry_list()[0] == {
        'pattern': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Claude', 'action': 'Include'}
    assert win_policy.add_write_protect_registry('HKEY_CURRENT_USER\\Software\\X', include=False)
    assert win_policy.get_rule('wp-reg', {'pattern': 'HKEY_CURRENT_USER\\Software\\X'})['action'] == 'Exclude'
    assert win_policy.remove_write_protect_file('C:\\E2E\\app.cfg')

    assert unix_policy.get_write_protect_file_list() == [{'pattern': '/etc/e2e/', 'action': 'Include'}]
    assert unix_policy.get_read_protect_list() == [{'pattern': '/etc/e2e/secret', 'action': 'Include'}]


def test_updaters_and_users(win_policy, unix_policy):
    assert win_policy.get_updaters()[0]['binary'] == 'C:\\E2E\\deploy.exe'
    assert win_policy.get_trusted_users()[0]['user'] == 'LAB\\deployer'
    assert unix_policy.get_updaters()[0]['tag'] == 'E2EDeploy'
    assert unix_policy.remove_updater('E2EDeploy') == 1
    assert unix_policy.get_updaters() == []
