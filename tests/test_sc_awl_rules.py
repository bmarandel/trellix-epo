"""
Tests for SCAWLPolicyRules (Solidcore Application Control Rules), using real ePO
exports:
  - sc_awl_rules_win.xml: "Claude - AWL Rules (Windows)", referencing the shared
    Rule Group "Internet Explorer (32 bit)", with one entry added in the ePO
    console in most tabs (updater by name with a Parent condition, updater by
    SHA-1, installer, trusted user, executable files banned by name and by
    SHA-1, two Policy Discovery filters, an Inventory filter and an Execution
    Control rule);
  - sc_awl_rules_unix.xml: the "Demo (Test)" Unix policy (4 shared Rule Groups,
    no rule of its own).
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import SCAWLPolicyRules, SCException as exc

FIXTURES = Path(__file__).parent / 'fixtures'
SHA1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


@pytest.fixture
def win_policy():
    return SCAWLPolicyRules(et.parse(str(FIXTURES / 'sc_awl_rules_win.xml')).getroot())


@pytest.fixture
def unix_policy():
    return SCAWLPolicyRules(et.parse(str(FIXTURES / 'sc_awl_rules_unix.xml')).getroot())


def test_rule_groups(win_policy, unix_policy):
    assert win_policy.get_rule_group_names() == ['Internet Explorer (32 bit)']
    assert sorted(unix_policy.get_rule_group_names()) == [
        'AGENT and ENS Linux', 'EDR and MAR', 'Global Rules', 'KCC']
    assert unix_policy.get_rules() == []
    # The rules of the shared Rule Groups are only returned on request.
    assert len(unix_policy.get_rules(all_groups=True)) > 0
    assert unix_policy.remove_rule_group('KCC')
    assert not unix_policy.remove_rule_group('KCC')
    assert 'KCC' not in unix_policy.get_rule_group_names()
    assert len(unix_policy.root.findall('EPOPolicySettings')) == 4
    assert len(unix_policy.root.findall('EPOPolicyObject/PolicySettings')) == 4


def test_updaters(win_policy):
    updaters = win_policy.get_updaters()
    assert updaters[0] == {'binary': 'C:\\Claude\\updater.exe', 'caseSensitive': 'false',
                           'inherit': 'false', 'log': 'false', 'parent': 'claudeparent.exe',
                           'tag': 'ClaudeUpdater', 'type': 'updater-binary'}
    assert updaters[1]['cksum'] == SHA1 and updaters[1]['showas'] == 'updater'

    win_policy.add_updater('C:\\Other\\up.exe', 'Other', parent='claudeparent.exe',
                           disable_inheritance=True, suppress_events=True)
    reference = dict(updaters[0], binary='C:\\Other\\up.exe', tag='Other')
    assert win_policy.get_rule('updater-binary', {'tag': 'Other'}) == reference
    win_policy.add_updater_by_checksum(SHA1.upper(), 'OtherSha1')
    assert win_policy.get_rule('installer', {'tag': 'OtherSha1'}) == dict(
        updaters[1], tag='OtherSha1')
    win_policy.add_updater_by_checksum(SHA256, 'OtherSha256')
    assert win_policy.get_rule('installer', {'tag': 'OtherSha256'})['cksum256'] == SHA256
    with pytest.raises(ValueError):
        win_policy.add_updater_by_checksum('not a checksum', 'Bad')
    with pytest.raises(ValueError):
        win_policy.add_updater('a.exe', 'Bad', parent='p.exe', library='l.dll')
    assert win_policy.remove_updater('OtherSha1') == 1
    assert len(win_policy.get_updaters()) == 4


def test_certificates(win_policy):
    assert win_policy.get_certificates() == []
    pem = '-----BEGIN CERTIFICATE-----\n' + 'A' * 3000 + '\n-----END CERTIFICATE-----'
    win_policy.add_certificate(pem, 'ClaudeCert', updater=True)
    rule = win_policy.get_rule('cert')
    assert len(rule['pem_1']) == 2048 and rule['pem_length'] == str(len(pem))
    assert win_policy.get_certificates() == [
        {'id': '1', 'pem': pem, 'label': 'ClaudeCert', 'updater': 'Yes'}]
    assert win_policy.remove_certificate(1)


def test_installers(win_policy):
    assert win_policy.get_installers() == [
        {'cksum': '803291bcc5aa45a0221b4016f62d63a26d3ee4af', 'ruletype': 'checksum',
         'tag': 'ClaudeInstaller', 'type': 'installer', 'vendor': 'McAfee',
         'version': 'McAfee Total Protection\\'}]
    win_policy.add_installer(SHA1, 'Setup', name='Setup', version='1.0', vendor='Acme')
    assert win_policy.get_rule('installer', {'tag': 'Setup'})['version'] == 'Setup\\1.0'
    assert win_policy.remove_installer('Setup') == 1
    # An updater by checksum is not an installer.
    assert win_policy.remove_installer('ClaudeSha1') == 0


def test_directories_and_users(win_policy):
    assert win_policy.get_trusted_directories() == []
    win_policy.add_trusted_directory('C:\\Tools', updater=True)
    assert win_policy.get_trusted_directories() == [
        {'action': 'Include', 'path': 'C:\\Tools', 'type': 'trusted', 'updater': 'true'}]
    assert win_policy.remove_trusted_directory('C:\\Tools')

    users = win_policy.get_trusted_users()
    assert users[0]['user'] == 'LAB\\claudeuser'
    win_policy.add_trusted_user('LAB\\other', 'Other', 'Other User')
    assert sorted(win_policy.get_rule('updater-user', {'user': 'LAB\\other'})) == sorted(users[0])
    assert win_policy.remove_trusted_user('LAB\\other')


def test_executable_files(win_policy):
    assert win_policy.get_executable_files() == [
        {'name': 'ClaudeBan', 'action': 'Ban', 'type': 'name', 'value': 'claudeban.exe'},
        {'name': 'ClaudeBanSha', 'action': 'Ban', 'type': 'sha1',
         'value': '1111111111111111111111111111111111111111'}]
    win_policy.add_executable_file('AllowSha', SHA256)
    win_policy.add_executable_file('AllowName', 'tool.exe')
    assert win_policy.get_rule('auth-cksum', {'tag': 'AllowSha'}) == {
        'action': 'Allow', 'cksum256': SHA256, 'tag': 'AllowSha', 'type': 'auth-cksum'}
    assert win_policy.get_rule('attr', {'tag': 'AllowName'}) == {
        'always_auth': 'true', 'file': 'tool.exe', 'tag': 'AllowName', 'type': 'attr'}
    assert win_policy.remove_executable_file('ClaudeBan') == 1
    assert len(win_policy.get_executable_files()) == 3


def test_exclusions(win_policy):
    # Executable file rules ('attr' with always_unauth) are not exclusions.
    assert win_policy.get_exclusion_list() == []
    win_policy.add_exclusion(exc.CASP, 'app.exe')
    assert win_policy.get_exclusion_list() == [{'exclusion': exc.CASP, 'name': 'app.exe'}]


def test_filters(win_policy):
    filters = win_policy.get_filters()
    assert filters[0]['conditions'] == [
        {'condition': 'File', 'match': 'equals', 'pattern': 'C:\\claude\\ob.exe'}]
    assert not filters[0]['apply_to_events']
    assert filters[1]['apply_to_events']
    assert filters[1]['conditions'][1]['pattern'] == 'C:\\Temp\\claude.txt'

    rule_uuid = win_policy.add_filter([('Event', 'equals', 'WRITE_DENIED'),
                                       ('User', 'contains', 'svc')], apply_to_events=True)
    observation = win_policy.get_rule('ob-exclusion', {'rule-uuid': rule_uuid})
    event = win_policy.get_rule('mon-advanced', {'rule-uuid': rule_uuid})
    assert dict(observation, type='mon-advanced') == event
    assert observation['condition-type_1'] == 'User'
    assert win_policy.remove_filter(rule_uuid)
    assert len(win_policy.get_filters()) == 2

    assert win_policy.get_inventory_filters()[0]['conditions'][0]['pattern'] == 'C:\\claude\\inv.dll'
    rule_uuid = win_policy.add_inventory_filter([{'condition': 'vendor-name',
                                                  'match': 'equals', 'pattern': 'Acme'}])
    assert len(win_policy.get_inventory_filters()) == 2
    assert win_policy.remove_inventory_filter(rule_uuid)


def test_execution_control(win_policy):
    assert win_policy.get_execution_control_rules() == [
        {'process_name': 'claudeexec.exe', 'action': 'monitor',
         'conditions': [{'condition': 'path', 'match': 'equals',
                         'pattern': 'C:\\Claude\\claudeexec.exe'},
                        {'condition': 'parent_process_name', 'match': 'equals',
                         'pattern': 'cmd.exe'}],
         'description': 'Claude exec rule'}]
    win_policy.add_execution_control_rule('powershell.exe', 'block',
                                          [('command_line', 'matches', '.*-enc.*')],
                                          'Block encoded PowerShell')
    win_policy.add_execution_control_rule('cmd.exe', 'block_interactive')
    rules = win_policy.get_execution_control_rules()
    assert rules[1]['conditions'] == [
        {'condition': 'command_line', 'match': 'matches', 'pattern': '.*-enc.*'}]
    assert rules[2] == {'process_name': 'cmd.exe', 'action': 'block_interactive',
                        'conditions': [], 'description': None}
    with pytest.raises(ValueError):
        win_policy.add_execution_control_rule('x.exe', 'deny')
    assert win_policy.remove_execution_control_rules('cmd.exe') == 1
