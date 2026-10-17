"""
Policy Catalog and policy assignments (trellix_epo.policycatalog,
trellix_epo.epopolicies), without a server.

Fixtures of the ePO 5.10 Update 7 lab: policy_find.json is policy.find (170
policies), policy_assignments.json the EPOBrokenInherintanceView table (the
groups and the system W10ENTB01 that don't inherit a category),
policy_applied.json the EPOAssignedPolicy rows of W10ENTB01;
system_branches.json is the EPOBranchNode table (see test_system_tree). The
answers of the modifying commands are the ones of the lab tests ("Claude -
Template" policies on a test group and a dummy system).
"""

import doctest
import json
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import policycatalog as module
from trellix_epo import epopolicies as operations
from trellix_epo import (EPOClient, PolicyRef, Assignment, policies_to_markdown,
                         assignments_to_markdown, applied_to_markdown)
from trellix_epo.epo import EPOError
from trellix_epo.policycatalog import CATEGORIES, type_id_of

FIXTURES = Path(__file__).parent / 'fixtures'
POLICIES = (FIXTURES / 'policy_find.json').read_text(encoding='utf-8')
ASSIGNMENTS = (FIXTURES / 'policy_assignments.json').read_text(encoding='utf-8')
APPLIED = (FIXTURES / 'policy_applied.json').read_text(encoding='utf-8')
BRANCHES = (FIXTURES / 'system_branches.json').read_text(encoding='utf-8')
VIEW = 'EPOBrokenInherintanceView.'


def ok(text):
    """
    Returns the answer of the server for a JSON text.
    """
    return 'OK:\r\n' + text


def view_row(path, policy_id, feature_id, node_type=3):
    """
    Returns a row of EPOBrokenInherintanceView.
    """
    return {VIEW + 'nodetype2': node_type, VIEW + 'nodetextpath': path,
            VIEW + 'policyobjectid': policy_id, VIEW + 'editflags': 0,
            VIEW + 'ForceInheritance': 0, VIEW + 'PolicyDesc': '', VIEW + 'FeatureTextID': feature_id}


class FakeServer(EPOClient):
    """
    EPOClient whose server is a list of answers; the requests are kept in
    self.requests as (command, form fields or multipart body).
    """

    def __init__(self, *answers):
        """
        :param: answers: The raw answers of the server, in order.
        """
        super(FakeServer, self).__init__('https://epo.example.com:8443', 'admin', 'secret')
        self.answers = list(answers)
        self.requests = []

    def _send(self, request):
        """
        Records the request and returns the next answer.
        """
        command = urllib.parse.urlsplit(request.full_url).path.split('/remote/')[1]
        if request.get_header('Content-type').startswith('multipart/'):
            fields = request.data
        else:
            fields = dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))
        self.requests.append((command, fields))
        return self.answers.pop(0)


def policies():
    """
    Returns the policies of the fixture by id.
    """
    return {item['objectId']: PolicyRef.from_json(item) for item in json.loads(POLICIES)}


def test_docstring_examples():
    result = doctest.testmod(module)
    assert result.attempted >= 18 and result.failed == 0
    result = doctest.testmod(operations)
    assert result.attempted >= 2 and result.failed == 0


def test_every_category_of_the_library_is_found_in_policy_find():
    # (featureId, typeName) of policy.find give the typeid of every category
    # the library knows (Firewall: featureId ENDP_FW_META_FW, productId
    # ENDP_FW_META; Solidcore: SCOR_*, productId SOLIDCORE_META).
    found = {(policy.feature_id, policy.type_id) for policy in policies().values()}
    assert set(CATEGORIES) <= found | {None}
    assert type_id_of('ENDP_FW_META_FW', 'Rules') == 'FireCore_FW_Rules'


def test_find_and_filters():
    epo = FakeServer(*[ok(POLICIES)] * 3)
    found = epo.policies.find()
    assert len(found) == 170
    policy = [item for item in found if item.id == 201][0]
    assert (policy.name, policy.product_id, policy.type_number, policy.category,
            policy.product_name, policy.type_id) == (
                'Demo (Ransomware)', 'ENDP_AM_1000', 25, 'On-Access Scan',
                'Endpoint Security Threat Prevention', 'EAM_General_Policies')
    ep = epo.policies.find(product_id='ENDP_AM_1000', category='Exploit Prevention')
    assert len(ep) == 7 and all(item.multi_slot for item in ep)
    scor = epo.policies.find(product_id='SCOR_AWL', category='AWL Rules (Windows)')
    assert len(scor) == 14 and {item.product_id for item in scor} == {'SOLIDCORE_META'}


def test_get_and_require():
    epo = FakeServer(ok(POLICIES), ok(POLICIES), ok(POLICIES), ok(POLICIES))
    with pytest.raises(EPOError, match='Several policies are named My Default'):
        epo.policies.get('My Default')
    assert epo.policies.get('My Default', 'On-Access Scan', 'ENDP_AM_1000').id == 59
    assert epo.policies.require(201).name == 'Demo (Ransomware)'
    with pytest.raises(ValueError, match='Unknown policy: Nope'):
        epo.policies.require('Nope')
    assert epo.requests[0] == ('policy.find', {'searchText': 'My Default'})


def test_read_only_and_slots():
    defaults = [policy for policy in policies().values() if policy.name == 'Trellix Default']
    assert defaults and all(policy.read_only for policy in defaults)
    oas = policies()[201]
    assert oas.slot == ('ENDP_AM_1000', 'on-access scan') and not oas.multi_slot


def test_assignments():
    epo = FakeServer(ok(ASSIGNMENTS), ok(POLICIES))
    found = epo.policies.assignments()
    assert len(found) == 24
    system = [item for item in found if item.system]
    assert [(item.system, item.path) for item in system] == [
        ('W10ENTB01', 'My Organization\\Workstations')]
    assert {item.path for item in found} == {
        'My Organization\\Workstations', 'My Organization\\ePO Server',
        'My Organization\\Linux Servers', 'My Organization\\OT Systems'}
    assert all(item.policy is not None for item in found)
    epo = FakeServer(ok(ASSIGNMENTS), ok(POLICIES), ok(BRANCHES), ok(ASSIGNMENTS), ok(POLICIES))
    group = epo.policies.assignments(group='Workstations')
    assert group and all(item.system is None for item in group)
    assert [item.system for item in epo.policies.assignments(system='w10entb01')] == ['W10ENTB01']


def test_applied():
    epo = FakeServer(ok(APPLIED), ok(POLICIES))
    applied = epo.policies.applied('W10ENTB01')
    assert len(applied) == 28
    command, fields = epo.requests[0]
    assert command == 'core.executeQuery' and fields['where'] == \
        '(eq EPOAssignedPolicy.NodeName "W10ENTB01")'
    oas = [item for item in applied if item.policy_id == 201][0]
    assert oas.policy.name == 'Demo (Ransomware)' and oas.origin == 'tree' and oas.up_to_date
    assert any(item.read_only for item in applied)
    epo = FakeServer(ok(APPLIED), ok(POLICIES), ok(APPLIED), ok(POLICIES))
    epo.policies.applied(['PC01', 'PC02'])
    assert epo.requests[0][1]['where'] == ('(or (eq EPOAssignedPolicy.NodeName "PC01") '
                                           '(eq EPOAssignedPolicy.NodeName "PC02"))')
    epo.policies.applied()
    assert 'where' not in epo.requests[2][1]


def test_assign_to_a_group():
    after = json.dumps(json.loads(ASSIGNMENTS) + [view_row('\\Test Group\\', 355, 'ENDP_GS_1000')])
    epo = FakeServer(ok(POLICIES), ok(BRANCHES), ok('true'), ok(after), ok(POLICIES), ok(BRANCHES))
    found = epo.policies.assign(355, group='Test Group')
    assert epo.requests[2] == ('policy.assignToGroup', {'groupId': '12',
                                                        'productId': 'ENDP_GS_1000',
                                                        'objectId': '355'})
    assert [item.policy_id for item in found] == [355]
    # The server answered true but the policy is not there.
    epo = FakeServer(ok(BRANCHES), ok('true'), ok(ASSIGNMENTS), ok(POLICIES), ok(BRANCHES))
    with pytest.raises(EPOError, match='is not assigned to My Organization\\\\Test Group'):
        epo.policies.assign(policies()[355], group='Test Group')


def test_assign_multi_slot_adds():
    # Exploit Prevention: a second assignment adds a policy (lab, P3).
    after = json.dumps(json.loads(ASSIGNMENTS) + [
        view_row('\\Test Group\\', 356, 'ENDP_AM_1000'),
        view_row('\\Test Group\\', 63, 'ENDP_AM_1000')])
    epo = FakeServer(ok(BRANCHES), ok('true'), ok(after), ok(POLICIES), ok(BRANCHES))
    found = epo.policies.assign(policies()[63], group='Test Group')
    assert sorted(item.policy_id for item in found) == [63, 356]


def test_assign_to_systems():
    answer = ok(json.dumps([{'name': 'Claude-TEST05', 'id': '20',
                             'message': 'Assign policy succeeded', 'status': 0}]))
    epo = FakeServer(answer)
    assert epo.policies.assign(policies()[354], systems=20) == ['Claude-TEST05']
    assert epo.requests[0] == ('policy.assignToSystem', {
        'ids': '20', 'productId': 'EPOAGENTMETA', 'typeId': '4', 'objectId': '354'})
    epo = FakeServer(ok(json.dumps([{'name': '', 'id': '20', 'status': -1,
                                     'message': 'Unable to take action on the computer'}])))
    with pytest.raises(EPOError, match='Unable to take action'):
        epo.policies.assign(policies()[354], systems=20)
    with pytest.raises(ValueError, match='Give a group or systems'):
        epo.policies.assign(policies()[354])
    with pytest.raises(ValueError, match='Give a group or systems'):
        epo.policies.assign(policies()[354], group=12, systems=20)


def test_reset_a_group():
    before = json.dumps(json.loads(ASSIGNMENTS) + [view_row('\\Test Group\\', 356, 'ENDP_AM_1000'),
                                                   view_row('\\Test Group\\', 63, 'ENDP_AM_1000')])
    epo = FakeServer(ok(POLICIES), ok(before), ok(POLICIES), ok(BRANCHES), ok('true'))
    assert epo.policies.reset('Exploit Prevention', 'ENDP_AM_1000', group='Test Group') == [
        'My Organization\\Test Group']
    command, fields = epo.requests[-1]
    assert command == 'policy.assignToGroup' and fields['resetInheritance'] == 'true'
    assert fields['groupId'] == '12' and fields['productId'] == 'ENDP_AM_1000'
    # Nothing to reset: the server would answer "Invalid product ID".
    epo = FakeServer(ok(POLICIES), ok(ASSIGNMENTS), ok(POLICIES), ok(BRANCHES))
    with pytest.raises(ValueError, match='Test Group inherits Endpoint Security Threat '
                                         'Prevention / Exploit Prevention already'):
        epo.policies.reset('Exploit Prevention', 'ENDP_AM_1000', group='Test Group')
    epo = FakeServer(ok(POLICIES))
    with pytest.raises(ValueError, match='Several products have the category Options'):
        epo.policies.reset('Options', group='Test Group')


def test_reset_systems():
    # W10ENTB01 has its own SIR Set Registry policy (134) on the lab.
    answer = ok(json.dumps([{'name': '', 'id': '4', 'message': 'Reset inheritance succeeded',
                             'status': 0}]))
    systems = ok((FIXTURES / 'systems.json').read_text(encoding='utf-8'))
    set_registry, agent = policies()[134], policies()[354]
    epo = FakeServer(ok(ASSIGNMENTS), ok(POLICIES), systems, answer)
    assert epo.policies.reset(set_registry, systems='W10ENTB01') == ['W10ENTB01']
    assert epo.requests[-1] == ('policy.assignToSystem', {
        'ids': '4', 'productId': 'SIR_____1000', 'typeId': '56', 'objectId': '134',
        'resetInheritance': 'true'})
    # A policy id tells the category too.
    epo = FakeServer(ok(POLICIES), ok(ASSIGNMENTS), ok(POLICIES), systems, answer)
    assert epo.policies.reset(134, systems='W10ENTB01') == ['W10ENTB01']
    # The system inherits the Trellix Agent General category.
    epo = FakeServer(ok(ASSIGNMENTS), ok(POLICIES), systems)
    with pytest.raises(ValueError, match='W10ENTB01 inherits Trellix Agent / General already'):
        epo.policies.reset(agent, systems='W10ENTB01')


def test_markdown():
    refs = policies()
    text = policies_to_markdown(refs.values())
    assert text.count('\n') == 3 + 170
    assert '| Endpoint Security Threat Prevention | On-Access Scan | Demo (Ransomware) | 201 |  |' in text
    assignments = [Assignment.from_json(row, refs) for row in json.loads(ASSIGNMENTS)]
    table = assignments_to_markdown(assignments)
    assert table.splitlines()[2] == '| Group | System | Product | Category | Policy | Locked |'
    assert '| My Organization\\\\Workstations | W10ENTB01 |' in table
    applied = FakeServer(ok(APPLIED), ok(POLICIES)).policies.applied('W10ENTB01')
    assert '| W10ENTB01 | Endpoint Security Threat Prevention | On-Access Scan | Demo (Ransomware) ' \
           '| tree | Yes |' in applied_to_markdown(applied)


def test_export_and_import_shortcuts():
    epo = FakeServer('OK:\r\n<EPOPolicySchema/>', 'OK:\r\nNumber of imported policies: 1')
    assert type(epo.export_policies('NOPE')).__name__ == 'Policies'
    assert epo.import_policies(b'<x/>').startswith('Number of imported policies')
    assert epo.requests[0] == ('policy.export', {'productId': 'NOPE'})
