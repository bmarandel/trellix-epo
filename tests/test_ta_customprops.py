"""
Tests for TAPolicyCustomProps, using a real ePO export
(ma_custom_props.xml) provided by the user.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import TAPolicyCustomProps

FIXTURE = Path(__file__).parent / 'fixtures' / 'ma_custom_props.xml'


@pytest.fixture
def customprops_policy():
    root = et.parse(str(FIXTURE)).getroot()
    return TAPolicyCustomProps(root)


def test_epo_metadata(customprops_policy):
    assert customprops_policy.get_epo_server() == 'W2022EPO510'
    assert customprops_policy.get_epo_version() == '5.10.0.0'
    assert customprops_policy.get_name() == 'My Default'


def test_custom_properties_read(customprops_policy):
    properties = customprops_policy.custom_properties
    assert len(properties) == 8
    assert all(row == {'AllowClientEditing': '1', 'Visibility': '1'} for row in properties)


def test_custom_properties_round_trip(customprops_policy):
    properties = customprops_policy.custom_properties
    properties[0] = {'AllowClientEditing': '0', 'Visibility': '1'}
    properties[7] = {'AllowClientEditing': '1', 'Visibility': '0'}

    assert customprops_policy.set_custom_properties(properties)

    reloaded = customprops_policy.custom_properties
    assert reloaded[0] == {'AllowClientEditing': '0', 'Visibility': '1'}
    assert reloaded[7] == {'AllowClientEditing': '1', 'Visibility': '0'}
    assert len(reloaded) == 8


def test_overwrite_blanks_round_trip(customprops_policy):
    assert customprops_policy.overwrite_blanks == '1'
    customprops_policy.overwrite_blanks = '0'
    assert customprops_policy.overwrite_blanks == '0'
