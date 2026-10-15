"""
Tests for TAPolicyTroubleshooting, using two real ePO exports
provided by the user: ma_troubleshooting.xml (language selection off,
default UI language) and ma_troubleshooting_english.xml (language selection
on, English (United States) - LCID 0409), which together confirm the
AgentLanguage/bEnableAgentLangSelection behavior.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import TAPolicyTroubleshooting, Language

FIXTURE_DEFAULT = Path(__file__).parent / 'fixtures' / 'ma_troubleshooting.xml'
FIXTURE_ENGLISH = Path(__file__).parent / 'fixtures' / 'ma_troubleshooting_english.xml'


def _load(fixture_path):
    root = et.parse(str(fixture_path)).getroot()
    return TAPolicyTroubleshooting(root)


@pytest.fixture
def default_policy():
    return _load(FIXTURE_DEFAULT)


@pytest.fixture
def english_policy():
    return _load(FIXTURE_ENGLISH)


def test_epo_metadata(default_policy):
    assert default_policy.get_epo_server() == 'W2022EPO510'
    assert default_policy.get_epo_version() == '5.10.0.0'
    assert default_policy.get_name() == 'My Default'


def test_language_selection_disabled_by_default(default_policy):
    assert default_policy.enable_agent_language_selection == '0'
    assert default_policy.agent_language == Language.UI_DEFAULT


def test_language_selection_enabled_english(english_policy):
    assert english_policy.enable_agent_language_selection == '1'
    assert english_policy.agent_language == Language.ENGLISH


def test_agent_language_set_writes_both_sections(default_policy):
    default_policy.enable_agent_language_selection = '1'
    default_policy.agent_language = Language.FRENCH

    assert default_policy.enable_agent_language_selection == '1'
    assert default_policy.agent_language == Language.FRENCH
    # Both the General and LanguageOptions sections must stay in sync.
    assert default_policy.get_setting_value('General', 'AgentLanguage') == Language.FRENCH
    assert default_policy.get_setting_value('LanguageOptions', 'AgentLanguage') == Language.FRENCH


def test_health_check_round_trip(default_policy):
    assert default_policy.health_check == '1'
    default_policy.health_check = '0'
    assert default_policy.health_check == '0'


def test_server_id_is_not_exposed(default_policy):
    assert not hasattr(default_policy, 'server_id')
    assert not hasattr(default_policy, 'get_server_id')
    assert not hasattr(default_policy, 'set_server_id')
