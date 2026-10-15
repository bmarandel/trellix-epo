"""
Tests for SCGENPolicyConfiguration (Solidcore General > Configuration (Client)),
using a real ePO export (sc_gen_config.xml): a copy of a lab policy imported
as "Claude - Config Import Test", then edited in the ePO console (CLI enabled
with 4 attempts, Events throttling disabled, Inventory threshold 21000, log
files 7, inventory merge timeout 1900, MPCompat 0). The CLI password hashes
and salt have been replaced by dummy values.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import SCGENPolicyConfiguration, SCPolicies, State

FIXTURE = Path(__file__).parent / 'fixtures' / 'sc_gen_config.xml'


@pytest.fixture
def config_policy():
    root = et.parse(str(FIXTURE)).getroot()
    return SCGENPolicyConfiguration(root)


def test_epo_metadata(config_policy):
    assert config_policy.get_epo_server() == 'W2022EPO510'
    assert config_policy.get_name() == 'Claude - Config Import Test'
    assert config_policy.get_type() == 'Lockdown Rules'
    assert config_policy.get_product() == 'SCOR_GEN'


def test_wrong_type_is_rejected(config_policy):
    config_policy.root.find('EPOPolicyObject').set('typeid', 'AWL Rules (Windows)')
    with pytest.raises(ValueError):
        SCGENPolicyConfiguration(config_policy.root)


def test_rule_group(config_policy):
    groups = config_policy.get_rule_groups()
    assert len(groups) == 1
    assert groups[0]['group_name'] == 'My Rules'
    assert groups[0]['shared'] is False
    assert config_policy.get_rule_group_names() == []


def test_cli_tab(config_policy):
    assert config_policy.cli_access == State.ENABLED
    assert config_policy.cli_failed_attempts == '4'
    assert config_policy.cli_attempts_within_minutes == '30'
    assert config_policy.cli_lockdown_minutes == '30'
    password = config_policy.get_cli_password_hash()
    assert password['password'] == '0123456789abcdef0123456789abcdef01234567'
    assert password['salt'] == '00000000-0000-0000-0000-000000000000'

    config_policy.cli_access = State.DISABLED
    config_policy.cli_lockdown_minutes = '60'
    assert config_policy.cli_access == State.DISABLED
    assert config_policy.cli_lockdown_minutes == '60'
    assert len(config_policy.get_rules('local-cli-lock')) == 1


def test_throttling_tab(config_policy):
    assert config_policy.throttling == State.ENABLED
    assert config_policy.throttling_events == State.DISABLED
    assert config_policy.events_threshold == '2000'
    assert config_policy.events_cache_size == '7000'
    assert config_policy.throttling_inventory == State.ENABLED
    assert config_policy.inventory_threshold == '21000'
    assert config_policy.throttling_policy_discovery == State.ENABLED
    assert config_policy.policy_discovery_threshold == '100'
    assert config_policy.policy_discovery_cache_size == '700'

    config_policy.throttling_events = State.ENABLED
    config_policy.events_threshold = '3000'
    assert config_policy.throttling_events == State.ENABLED
    assert config_policy.events_threshold == '3000'
    rule = config_policy.get_rule('features', {'name': 'throttle-evt'})
    assert rule == {'enforce': 'true', 'name': 'throttle-evt', 'status': '1', 'type': 'features'}


def test_other_tabs(config_policy):
    assert config_policy.file_diff_max_size == '1000'
    assert config_policy.file_diff_attr_only_types.startswith('zip,7z,rar')
    assert config_policy.file_diff_max_files == '100'
    assert config_policy.paths_writable_only_by_updaters == 'NA'
    assert config_policy.log_file_size == '5000'
    assert config_policy.log_file_num == '7'
    assert config_policy.inventory_merge_timeout == '1900'
    assert config_policy.inventory_merge_by_size_period == '150'
    assert config_policy.vtp_trust_check == '1'
    assert config_policy.allow_failed_cert_trust_with_vtp == '0'
    assert config_policy.catalog_cert_extraction_disabled == '0'
    assert config_policy.embedded_cert_extraction_disabled == '0'
    assert config_policy.mp_compat == '0'
    assert config_policy.disable_device_guard_compat == '0'
    assert config_policy.inventory_backup == '0'
    assert config_policy.tid_optimization == '1'
    assert config_policy.skip_validate_file_length == '1'
    assert config_policy.trusted_local_group == '1'


def test_missing_config_is_created(config_policy):
    assert config_policy.remove_rules('config', {'name': 'logFileSize'}) == 1
    assert config_policy.log_file_size is None
    config_policy.log_file_size = '8000'
    assert config_policy.log_file_size == '8000'
    sections = [s.get('name') for s in config_policy.root.iter('Section')]
    # A new rule gets the next free number, and scor_info stays the last section.
    assert 'General_Rule_43' in sections
    assert sections[-1] == 'scor_info'


def test_hidden_settings_are_not_public(config_policy):
    prefix = '_SCGENPolicyConfiguration__'
    assert getattr(config_policy, prefix + 'get_inv_diff_config')() == '1'
    assert getattr(config_policy, prefix + 'get_inv_diff_config2')() == '2'
    assert not hasattr(config_policy, 'inv_diff_config')


def test_new_policy_from_export():
    xml_data = FIXTURE.read_bytes()
    policies = SCPolicies(xml_data)
    new = policies.new_policy('Lockdown Rules', 'Copy', template='Claude - Config Import Test')
    policy = SCGENPolicyConfiguration(new)
    assert policy.get_name() == 'Copy'
    settings_name = new.find('EPOPolicySettings').get('name')
    assert settings_name.startswith('Copy::Settings (')
    assert new.find('EPOPolicyObject/PolicySettings').text == settings_name
    assert policy.log_file_num == '7'
