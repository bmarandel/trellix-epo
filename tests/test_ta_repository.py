"""
Tests for TAPolicyRepository, using a real ePO export
(ma_repository.xml) provided by the user.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import TAPolicyRepository, RepositoryList

FIXTURE = Path(__file__).parent / 'fixtures' / 'ma_repository.xml'


@pytest.fixture
def repository_policy():
    root = et.parse(str(FIXTURE)).getroot()
    return TAPolicyRepository(root)


def test_epo_metadata(repository_policy):
    assert repository_policy.get_epo_server() == 'W2022EPO510'
    assert repository_policy.get_epo_version() == '5.10.0.0'
    assert repository_policy.get_name() == 'My Default'


def test_site_list(repository_policy):
    site_list = repository_policy.get_site_list()
    assert site_list == [['ePO_W2022EPO510', 'Enabled'], ['Trellix HTTPS', 'Enabled']]


def test_repository_list_workflow(repository_policy):
    repo_list = RepositoryList(repository_policy.get_site_list())

    assert repo_list.contain('ePO_W2022EPO510')
    assert repo_list.state('ePO_W2022EPO510') == 'Enabled'

    repo_list.disable('Trellix HTTPS')
    assert repo_list.state('Trellix HTTPS') == 'Disabled'

    repo_list.move_top('Trellix HTTPS')
    assert repo_list.index('Trellix HTTPS') == 0

    assert repository_policy.set_site_list(repo_list.get_repo_list())
    assert repository_policy.get_site_list() == [
        ['Trellix HTTPS', 'Disabled'], ['ePO_W2022EPO510', 'Enabled'],
    ]
