"""
Trellix Agent General policy: values accepted by the console (extension
EPOAGENTMETA 5.8.6.314, checked on the lab).

The number bounds and text lengths come from the console pages (orion
numberbox minimum/maximum, maxlength) and were tested on the lab page
(min - 1 and max + 1 refused, min and max accepted); the path, relay
address and port rules are those of the page scripts, run on the lab with
the same cases as below.

ma_general_586.xml: "My Default" and "Claude - MA General Test", a copy saved
in the console with three relay servers (DNS Name, IPv4, IPv6), a forced
reboot after 120 seconds and the IP reporting mode IPv4.
"""

import copy
from pathlib import Path

import pytest

from mcafee_epo_policies import McAfeeAgentPolicies, McAfeeAgentPolicyGeneral
from mcafee_epo_policies.ma.general import check_repository_path, check_relay_server
from mcafee_epo_policies.validators import check_int, check_length

FIXTURE = Path(__file__).parent / 'fixtures' / 'ma_general_586.xml'


def load(name='My Default'):
    policies = McAfeeAgentPolicies()
    policies.load_from_file(str(FIXTURE))
    return McAfeeAgentPolicyGeneral(copy.deepcopy(policies.get_policy('General', name)))


def test_check_helpers():
    assert check_int('x', '42', 1, 60) == 42 and check_int('x', -1, -1, 5) == -1
    for value in [True, '4.5', '', None, 61]:
        with pytest.raises(ValueError):
            check_int('x', value, 1, 60)
    assert check_length('x', 'abc', 3) == 'abc'
    for value, required in [('abcd', False), (' ', True), (12, False)]:
        with pytest.raises(ValueError):
            check_length('x', value, 3, required)


# setter, minimum, maximum (console field bounds)
BOUNDS = [('set_policy_enforcement_interval', 5, 10080), ('set_auto_reboot_after', 1, 10000),
          ('set_asci', 5, 2880), ('set_asci_do_when', 1, 360),
          ('set_sa_cache_sync_interval', 0, 300), ('set_sa_cache_disk_quota', 1, 250),
          ('set_sa_cache_purge_interval', 1, 90), ('set_relay_server_port', 1, 65535),
          ('set_events_upload_interval', 1, 60), ('set_events_max_per_upload', 1, 1000),
          ('set_log_limit', 2, 100), ('set_log_roll_over', 1, 10),
          ('set_log_remote_limit', 1, 5000), ('set_p2p_disk_quota', 100, 5000),
          ('set_p2p_purge_interval', 1, 90)]


@pytest.mark.parametrize('setter,minimum,maximum', BOUNDS)
def test_number_bounds(setter, minimum, maximum):
    policy = load()
    for value in (minimum, maximum, str(maximum)):
        getattr(policy, setter)(value)
    for value in (minimum - 1, maximum + 1, 'ten', 1.5):
        with pytest.raises(ValueError):
            getattr(policy, setter)(value)


def test_text_lengths():
    policy = load()
    for setter in ('set_upd_log_file', 'set_upd_run_exe'):
        getattr(policy, setter)('x' * 254)
        with pytest.raises(ValueError):
            getattr(policy, setter)('x' * 255)
    policy.set_sa_repo_path_windows('C:\\' + 'a' * 48 + '\\' + 'b' * 48)     # 100 characters
    with pytest.raises(ValueError):
        policy.set_sa_repo_path_windows('C:\\' + 'a' * 48 + '\\' + 'b' * 49)


# Results of validateVirtualDirectory / validateVirtualDirectoryNonWin on the lab page.
WINDOWS_PATHS = [('C:\\Repo\\Agent', True), ('<SYSTEM_DRIVE>\\Repo\\Agent', True),
                 ('C:\\Repo', False), ('C:\\\\Repo\\a', False), ('C:\\Re;po\\a', False),
                 ('D:\\a b\\c', True), ('<FOO>\\a\\b', False), ('C:\\a\\<SYSTEM_DRIVE>', False),
                 ('DEFAULT', True), ('C:\\a\\b\\', True), ('c:\\x\\y', True), ('1:\\x\\y', False),
                 ('C:\\a\\ \\b', False)]
UNIX_PATHS = [('/opt/repo/agent', True), ('/opt/my-repo/x', False), ('/opt', False),
              ('/opt//x', False), ('/a/b.c', False), ('/a/b_c', True), ('opt/a/b', False)]


def test_repository_paths():
    for paths, windows in [(WINDOWS_PATHS, True), (UNIX_PATHS, False)]:
        for path, valid in paths:
            if valid:
                check_repository_path('x', path, windows=windows)
            else:
                with pytest.raises(ValueError):
                    check_repository_path('x', path, windows=windows)
    policy = load()
    policy.set_p2p_repo_path('')                               # not checked when empty
    with pytest.raises(ValueError):
        policy.set_p2p_repo_path_unix('/opt')


# Results of _validIPAddress / _validPort on the lab page.
RELAYS = [('DNS Name', 'relay01.example.com', True), ('DNS Name', 'relay01', True),
          ('DNS Name', 'a b', True), ('DNS Name', 'a:b', False), ('DNS Name', 'é.com', True),
          ('IPv4', '10.0.0.256', False), ('IPv4', '010.0.0.1', True), ('IPv4', ' 10.0.0.1 ', True),
          ('IPv4', '10.0.0', False), ('IPv6', 'fd00::30', True), ('IPv6', '[fd00::30]', True),
          ('IPv6', 'fd00:::30', False), ('IPv6', '::ffff:10.0.0.1', True),
          ('IPv6', 'fe80::1%eth0', False), ('IPv4 ', '10.0.0.1', False)]


def test_relay_servers():
    for address_type, address, valid in RELAYS:
        if valid:
            check_relay_server(address_type, address, 80)
        else:
            with pytest.raises(ValueError):
                check_relay_server(address_type, address, 80)
    assert check_relay_server('IPv4', '10.0.0.1', '08081') == '8081'
    for port in ('0', '65536', '-1', '80a', ' 80', ''):
        with pytest.raises(ValueError):
            check_relay_server('IPv4', '10.0.0.1', port)
    with pytest.raises(ValueError):
        check_relay_server('DNS Name', 'r' * 255, 80)
    with pytest.raises(ValueError):
        load().set_relay_server_list([{'relayip': '10.0.0.1', 'relayport': '80'}])


def test_console_rebuild():
    """
    The changes made in the console, applied with the library to "My
    Default", give the settings the console saved.
    """
    policy, console = load(), load('Claude - MA General Test')
    policy.set_relay_client('1')
    policy.set_relay_disable_discovery('1')
    policy.set_relay_server_list([
        {'relayselect': 'DNS Name', 'relayip': 'relay01.example.com', 'relayport': '8081'},
        {'relayselect': 'IPv4', 'relayip': '10.0.0.30', 'relayport': 8085},
        {'relayselect': 'IPv6', 'relayip': '[fd00::30]', 'relayport': '08086'}])
    policy.set_auto_reboot_after(120)
    policy.set_ip_reporting_mode('1')
    assert policy.get_relay_server_list() == console.get_relay_server_list()
    for section, setting in [('RelayService', 'RelayServerCount'),
                             ('RelayService', 'IsRelayDiscoveryDisabled'),
                             ('AgentListenServer', 'IsRelayClientEnabled'),
                             ('General', 'RebootTimeOut'), ('UpdaterService', 'RebootTimeout'),
                             ('General', 'IPVersionPreference')]:
        assert policy.get_setting_value(section, setting) == \
            console.get_setting_value(section, setting), (section, setting)
    assert console.ip_reporting_mode == '1'
    with pytest.raises(ValueError):
        policy.set_ip_reporting_mode('3')
    policy.set_auto_reboot_after(-1)
    assert policy.get_setting_value('UpdaterService', 'RebootTimeout') == '-1'
