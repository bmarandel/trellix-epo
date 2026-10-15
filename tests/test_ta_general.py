"""
Tests for TAPolicyGeneral, using a real ePO export (ma_general.xml)
provided by the user.

Note: unlike the ENS Threat Prevention/Firewall classes, TAPolicyGeneral
requires its policy element at construction time (no optional/None default), so
the fixture parses the file and passes the root directly, instead of the
Class().load_from_file(path) two-step pattern used elsewhere in this suite.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import TAPolicyGeneral

FIXTURE = Path(__file__).parent / 'fixtures' / 'ma_general.xml'


@pytest.fixture
def general_policy():
    root = et.parse(str(FIXTURE)).getroot()
    return TAPolicyGeneral(root)


def test_epo_metadata(general_policy):
    assert general_policy.get_epo_server() == 'W2022EPO510'
    assert general_policy.get_epo_version() == '5.10.0.0'
    assert general_policy.get_name() == 'My Default'


def test_simple_passthrough_properties(general_policy):
    assert general_policy.mcafee_system_tray_icon == '1'
    assert general_policy.super_agent == '0'
    assert general_policy.log_limit == 2
    assert general_policy.events_priority_level == '3'


def test_validated_range_property(general_policy):
    assert general_policy.policy_enforcement_interval == 60
    with pytest.raises(ValueError):
        general_policy.policy_enforcement_interval = 1  # below the 5-minute minimum


def test_old_new_setting_fallback(general_policy):
    # asci reads PropertyService/PropertyCollectionTimeout when present, falling
    # back to Network/CheckNetworkMessageInterval otherwise (older agent versions).
    assert general_policy.asci == 60
    general_policy.asci = 15
    assert general_policy.asci == 15


def test_relay_server_list_and_upd_branch_selection(general_policy):
    assert general_policy.relay_server_list == []

    branches = general_policy.upd_branch_selection
    assert len(branches) == 17
    assert {'BranchType': 'Current', 'OneClickEnabled': '1', 'SoftwareID': 'ENDPCNT_1000'} in branches


def test_cert_authentication_is_read_only(general_policy):
    assert general_policy.test_cert_authentication == '0'
    with pytest.raises(AttributeError):
        general_policy.test_cert_authentication = '1'


def test_cert_authentication_loads_ca_files_relative_to_module(general_policy, monkeypatch, tmp_path):
    # Regression test: set_test_cert_authentication used to open '__root__.ca'/
    # '__signer__.ca' as bare relative paths, which only worked if the caller's
    # cwd happened to be trellix_epo/ta/. Running from an unrelated cwd
    # must not raise FileNotFoundError anymore.
    monkeypatch.chdir(tmp_path)
    assert general_policy.set_test_cert_authentication('1') in (True, False)


def test_getters_read_the_console_section_first():
    # The console shows the section named after its fields when the
    # "service" section differs (checked on the ePO 5.10 lab).
    root = et.parse(str(FIXTURE)).getroot()
    policy = TAPolicyGeneral(root)
    # AgentListenServer.IsRelayClientEnabled 0, RelayService.EnableClient 1.
    assert policy.get_relay_client() == '0'
    assert policy.get_policy_enforcement_interval() == 60
    systray = TAPolicyGeneral(
        et.parse(str(FIXTURE.with_name('ma_general_systray.xml'))).getroot())
    # AgentListenServer.bEnableLazyCaching 1, HttpServerService.IsLazyCachingEnabled 0.
    assert systray.get_sa_lazy_caching() == '1'
    assert systray.get_sa_repo_path_windows() == 'DEFAULT'
    assert systray.get_asci() == 5


def test_set_lazy_caching_writes_both_sections(general_policy):
    general_policy.set_sa_lazy_caching('0')
    assert general_policy.get_setting_value('AgentListenServer', 'bEnableLazyCaching') == '0'
    assert general_policy.get_setting_value('HttpServerService', 'IsLazyCachingEnabled') == '0'
    assert general_policy.get_sa_lazy_caching() == '0'
