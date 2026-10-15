"""
Tests for TAPolicyTelemetry, using a real ePO export
(ma_telemetry.xml) provided by the user.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import TAPolicyTelemetry

FIXTURE = Path(__file__).parent / 'fixtures' / 'ma_telemetry.xml'


@pytest.fixture
def telemetry_policy():
    root = et.parse(str(FIXTURE)).getroot()
    return TAPolicyTelemetry(root)


def test_epo_metadata(telemetry_policy):
    assert telemetry_policy.get_epo_server() == 'W2022EPO510'
    assert telemetry_policy.get_epo_version() == '5.10.0.0'
    assert telemetry_policy.get_name() == 'My Default'


def test_product_improvement_program_round_trip(telemetry_policy):
    # Note: raw values are the strings 'true'/'false', not '1'/'0'.
    assert telemetry_policy.product_improvement_program == 'true'
    telemetry_policy.product_improvement_program = 'false'
    assert telemetry_policy.product_improvement_program == 'false'


def test_hidden_settings_are_not_public(telemetry_policy):
    name_mangled_prefix = '_TAPolicyTelemetry__'
    assert getattr(telemetry_policy, name_mangled_prefix + 'get_branch')() == 'Current'
    assert getattr(telemetry_policy, name_mangled_prefix + 'get_max_telemetry_size')() == '10'
    assert getattr(telemetry_policy, name_mangled_prefix + 'get_server_level_install_flag')() == 'true'
    assert getattr(telemetry_policy, name_mangled_prefix + 'get_timer')() == '86400000'

    for public_name in ('branch', 'max_telemetry_size', 'server_level_install_flag', 'timer'):
        assert not hasattr(telemetry_policy, public_name)
