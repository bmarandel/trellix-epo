"""
Tests for SCFIMPolicyRules (Solidcore Integrity Monitor Rules), using real ePO
exports of policies built with this library, imported into ePO and exported
back (sc_fim_rules_win.xml, sc_fim_rules_unix.xml). The Windows policy was
created from a copy of a policy edited in the ePO console (C:\\Claude\\fim.ini
with Content Change Tracking, directory C:\\Claude\\Dir\\ with recursion,
*.cfg included and *.tmp excluded).
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import SCFIMPolicyRules

FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.fixture
def win_policy():
    return SCFIMPolicyRules(et.parse(str(FIXTURES / 'sc_fim_rules_win.xml')).getroot())


@pytest.fixture
def unix_policy():
    return SCFIMPolicyRules(et.parse(str(FIXTURES / 'sc_fim_rules_unix.xml')).getroot())


def test_metadata(win_policy, unix_policy):
    assert win_policy.get_type() == 'Mon Rules (Windows)'
    assert unix_policy.get_type() == 'Mon Rules (Unix)'
    assert win_policy.get_product() == 'SCOR_FIM'


def test_file_list(win_policy):
    files = {f['pattern']: f for f in win_policy.get_file_list()}
    assert files['C:\\Claude\\fim.ini'] == {
        'pattern': 'C:\\Claude\\fim.ini', 'action': 'Include', 'change_tracking': True,
        'encoding': 'AutoDetect', 'is_directory': False, 'recurse': False,
        'include_patterns': [], 'exclude_patterns': []}
    assert files['C:\\E2E\\Logs\\']['action'] == 'Exclude'
    assert not files['C:\\E2E\\Logs\\']['change_tracking']
    assert files['C:\\E2E\\watched.ini']['encoding'] == 'UTF8'
    assert files['C:\\Claude\\Dir\\']['is_directory']
    assert files['C:\\Claude\\Dir\\']['recurse']
    assert files['C:\\Claude\\Dir\\']['include_patterns'] == ['*.cfg']
    assert files['C:\\Claude\\Dir\\']['exclude_patterns'] == ['*.tmp']
    assert files['C:\\E2E\\Conf\\']['include_patterns'] == ['*.xml', '*.ini']


def test_add_file_like_the_console(win_policy):
    console = win_policy.get_rule('file-diff-dir', {'pattern': 'C:\\Claude\\Dir\\'})
    win_policy.add_directory_change_tracking('C:\\New\\', include_patterns=['*.cfg'],
                                             exclude_patterns=['*.tmp'])
    assert win_policy.get_rule('file-diff-dir', {'pattern': 'C:\\New\\'}) == dict(
        console, pattern='C:\\New\\')
    console = win_policy.get_rule('mon-file', {'pattern': 'C:\\Claude\\fim.ini'})
    win_policy.add_file('C:\\New\\a.ini', change_tracking=True)
    assert win_policy.get_rule('mon-file', {'pattern': 'C:\\New\\a.ini'}) == dict(
        console, pattern='C:\\New\\a.ini')
    with pytest.raises(ValueError):
        win_policy.add_file('C:\\New\\b.ini', change_tracking=True, encoding='UTF-32')
    assert not win_policy.add_file('C:\\New\\a.ini')
    assert win_policy.remove_file('C:\\New\\')
    assert win_policy.remove_file('C:\\New\\a.ini')


def test_pattern_tabs(win_policy, unix_policy):
    assert win_policy.get_registry_list() == [
        {'pattern': 'HKEY_LOCAL_MACHINE\\SOFTWARE\\E2E', 'action': 'Include'}]
    assert win_policy.get_extension_list() == [{'pattern': 'log', 'action': 'Exclude'}]
    assert win_policy.get_program_list() == [{'pattern': 'C:\\E2E\\noisy.exe', 'action': 'Exclude'}]
    assert win_policy.get_user_list() == [{'pattern': 'LAB\\svc_backup', 'action': 'Exclude'}]
    assert win_policy.add_user('LAB\\admin', include=True)
    assert win_policy.get_rule('mon-user', {'pattern': 'LAB\\admin'})['action'] == 'Include'
    assert win_policy.remove_extension('log')
    assert unix_policy.get_extension_list() == [{'pattern': 'swp', 'action': 'Exclude'}]
    assert unix_policy.get_program_list() == [{'pattern': '/usr/sbin/logrotate', 'action': 'Exclude'}]


def test_filters(win_policy, unix_policy):
    filters = win_policy.get_filters()
    assert filters[0]['conditions'] == [
        {'condition': 'Event', 'match': 'equals', 'pattern': 'FILE_MODIFIED'},
        {'condition': 'Process', 'match': 'ends', 'pattern': '\\backup.exe'}]
    rule_uuid = unix_policy.add_filter([{'condition': 'User', 'match': 'equals', 'pattern': 'root'}])
    assert len(unix_policy.get_filters()) == 2
    assert unix_policy.remove_filter(rule_uuid)
    assert unix_policy.get_filters()[0]['conditions'][0]['pattern'] == '/var/tmp/'
