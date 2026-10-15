"""
Tests for SCAWLPolicyOptions (Solidcore Application Control Options), using real
ePO exports:
  - sc_awl_options_win.xml: "Trellix Default" duplicated in the ePO console as
    "Claude - AWL Options (Windows)", then edited in every tab (Self-Approval
    enabled, Optional justification, 120s timeout, Helpdesk information,
    EXECUTION_DENIED message, Script as Updater off, Bypass Package Control on,
    8 days / 4 hours inventory intervals, TIE with Enterprise Trust Level,
    Known Trusted / Most Likely Malicious, ATD level and size);
  - sc_awl_options_unix.xml: the "My Default" Unix policy.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import SCAWLPolicyOptions, SCReputation as rep, State

FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.fixture
def win_policy():
    return SCAWLPolicyOptions(et.parse(str(FIXTURES / 'sc_awl_options_win.xml')).getroot())


@pytest.fixture
def unix_policy():
    return SCAWLPolicyOptions(et.parse(str(FIXTURES / 'sc_awl_options_unix.xml')).getroot())


def test_metadata(win_policy, unix_policy):
    assert win_policy.get_type() == 'AWL Options (Windows)'
    assert unix_policy.get_type() == 'AWL Options (Unix)'
    assert win_policy.get_product() == 'SCOR_AWL'


def test_self_approval_tab(win_policy):
    assert win_policy.self_approval == State.ENABLED
    assert win_policy.self_approval_text == 'Claude banner'
    assert win_policy.self_approval_timeout == '120'
    assert win_policy.justification_optional == '1'
    assert win_policy.self_approval_at_boot == '0'
    win_policy.self_approval_timeout = 90
    assert win_policy.self_approval_timeout == '90'
    with pytest.raises(ValueError):
        win_policy.self_approval_timeout = 240


def test_end_user_notifications_tab(win_policy):
    assert win_policy.user_message == 'false'
    assert win_policy.helpdesk_mail_to == 'sec@claude.test'
    assert win_policy.helpdesk_mail_subject == 'Claude subject'
    assert win_policy.helpdesk_website == 'www.claude.test'
    assert win_policy.helpdesk_epo_address == '10.0.0.1:8443'
    assert len(win_policy.get_message_events()) == 10
    assert win_policy.get_message('EXECUTION_DENIED') == 'Claude test {file_name}'
    assert win_policy.get_message_show_in_dialog('EXECUTION_DENIED') == 'false'
    assert win_policy.get_message_show_in_dialog('WRITE_DENIED') == 'true'

    win_policy.helpdesk_mail_to = 'a@example.com;d@example.org'
    win_policy.helpdesk_epo_address = 'epo.lab:8443'
    win_policy.set_message('WRITE_DENIED', 'No write to {file_name}')
    assert all(r['mailto'] == 'a@example.com;d@example.org' for r in win_policy.get_rules('event-cust-msg'))
    assert win_policy.helpdesk_epo_address == 'epo.lab:8443'
    assert win_policy.get_rule('event-cust-msg', {'event_name': 'READ_DENIED'})['epo_url'] == (
        'https://epo.lab:8443/SOLIDCORE_META/showEvents.do?seqNo={seqno}'
        '&hostName={hostname}&detectedUTC={detectedUtc}')
    assert win_policy.get_message('WRITE_DENIED') == 'No write to {file_name}'


def test_features_tab(win_policy):
    assert win_policy.enforce_feature_control == 'false'
    assert win_policy.execution_control == State.ENABLED
    assert win_policy.script_as_updater == State.DISABLED
    assert win_policy.bypass_package_control == State.ENABLED
    win_policy.enforce_feature_control = 'true'
    win_policy.memory_protection_nx = State.DISABLED
    assert win_policy.enforce_feature_control == 'true'
    assert win_policy.get_rule('features', {'name': 'mp-nx'}) == {
        'enforce': 'true', 'name': 'mp-nx', 'status': '0', 'type': 'features'}
    # TIE/GTI/Self-Approval are always enforced, untouched by the Features tab.
    assert win_policy.get_rule('features', {'name': 'self-approval'})['enforce'] == 'true'
    # Not in the Features tab: the console leaves mp-vasr unenforced (checked
    # on the ePO 5.10 lab); the hidden activex rule is kept (the console drops
    # it at any save of the policy, whatever the change).
    assert win_policy.get_rule('features', {'name': 'mp-vasr'})['enforce'] == 'false'


def test_inventory_tab(win_policy):
    assert win_policy.hide_windows_os_files == 'true'
    assert win_policy.pull_inventory_interval == '8'
    assert win_policy.inventory_updates_interval == '4'
    assert len(win_policy.get_rules('advanced-inv-exclusion')) == 2
    win_policy.hide_windows_os_files = 'false'
    assert win_policy.get_rules('advanced-inv-exclusion') == []
    win_policy.hide_windows_os_files = 'true'
    assert len(win_policy.get_rules('advanced-inv-exclusion')) == 2
    win_policy.pull_inventory_interval = 7
    assert win_policy.get_config('PullInvTimeout') == '604800'


def test_reputation_tab(win_policy, unix_policy):
    assert win_policy.tie_reputation == State.ENABLED
    assert win_policy.tie_enterprise_trust_level == '1'
    assert win_policy.gti_reputation == State.DISABLED
    assert win_policy.allow_reputation_level == rep.KNOWN_TRUSTED
    assert win_policy.ban_reputation_level == rep.MOST_LIKELY_MALICIOUS
    assert win_policy.atd_submission == '0'
    assert win_policy.atd_reputation_level == rep.MIGHT_BE_MALICIOUS
    assert win_policy.atd_file_size_limit == '6'

    assert unix_policy.gti_reputation == State.DISABLED
    assert unix_policy.allow_by_reputation == '1'
    assert unix_policy.allow_reputation_level == rep.MOST_LIKELY_TRUSTED
    unix_policy.ban_reputation_level = rep.KNOWN_MALICIOUS
    assert unix_policy.ban_reputation_level == '1'
    # The Unix policy has no self-approval or message settings.
    assert unix_policy.self_approval is None
    assert unix_policy.get_message_events() == []


def test_hidden_settings_are_not_public(win_policy):
    prefix = '_SCAWLPolicyOptions__'
    assert getattr(win_policy, prefix + 'get_critical_process_list')().startswith('wordpad.exe,')
    assert not hasattr(win_policy, 'critical_process_list')
