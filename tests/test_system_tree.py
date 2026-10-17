"""
System Tree (trellix_epo.systemtree, trellix_epo.eposystemtree), without a
server.

Fixtures of the ePO 5.10 Update 7 lab (OS OEM ids masked, test groups
renamed): systems.json is system.find with an empty text (5 systems, the 56
fields), systems_flat.json system.find.multiple, system_groups.json
system.findGroups and system_branches.json the EPOBranchNode table, with
the groups "Test Group" (12), "Test Sub" (13) and the empty "Test Empty" (14)
created by an import file. The answers of the modifying commands are the
ones of the lab tests (dummy systems "Claude-TEST01..03").
"""

import doctest
import json
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import systemtree as module
from trellix_epo import eposystemtree as operations
from trellix_epo import EPOClient, System, Group, systems_to_markdown, groups_to_markdown
from trellix_epo.epo import EPOError
from trellix_epo.systemtree import FIELDS, check_destination, criteria_property, import_file, label

FIXTURES = Path(__file__).parent / 'fixtures'
SYSTEMS = (FIXTURES / 'systems.json').read_text(encoding='utf-8')
FLAT = (FIXTURES / 'systems_flat.json').read_text(encoding='utf-8')
GROUPS = (FIXTURES / 'system_groups.json').read_text(encoding='utf-8')
BRANCHES = (FIXTURES / 'system_branches.json').read_text(encoding='utf-8')
WORKSTATIONS = json.dumps([row for row in json.loads(SYSTEMS)
                           if row['EPOBranchNode.AutoID'] == 6])


def ok(text):
    """
    Returns the answer of the server for a JSON text.
    """
    return 'OK:\r\n' + text


def statuses(message, *names, status=0):
    """
    Returns the {name, id, message, status} list of setUserProperties,
    resort and delete.
    """
    return ok(json.dumps([{'name': name, 'id': str(13 + index) if status == 0 else '-1',
                           'message': message, 'status': status}
                          for index, name in enumerate(names)]))


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


def test_docstring_examples():
    result = doctest.testmod(module)
    assert result.attempted >= 40 and result.failed == 0
    result = doctest.testmod(operations)
    assert result.attempted >= 6 and result.failed == 0


def test_find_reads_the_56_fields():
    epo = FakeServer(ok(SYSTEMS))
    systems = epo.systems.find()
    # searchText is sent empty (parse_qsl of FakeServer leaves it out).
    assert epo.requests[0] == ('system.find', {})
    assert len(systems) == 5
    assert list(FIELDS.values()) == list(json.loads(SYSTEMS)[0])
    server = systems[0]
    assert (server.name, server.id, server.group_id) == ('W2022EPO510', 3, 4)
    assert server.tags == ['DXLBROKER', 'Server']
    assert server.managed and server.is_64bit and server.is_laptop
    assert server.is_domain_controller is None
    assert server.last_communication.isoformat() == '2026-10-17T13:58:53+02:00'
    assert server.ip_address == '192.168.100.20' and server.dns_name == 'W2022EPO510'
    assert 'Trellix Agent' in server.products
    assert ('Agent', '2024-09-17 11:47:43') in server.installed
    workstation = systems[1]
    assert workstation.is_domain_controller is False
    # Never set: empty texts (None for a system added by importSystem).
    assert workstation.custom_fields == {'custom1': '', 'custom2': '', 'custom3': '',
                                         'custom4': ''}
    linux = [system for system in systems if system.name == 'ubuntud01'][0]
    assert linux.os_type == 'Linux' and linux.is_laptop is False


def test_all_pages_with_find_multiple():
    rows = json.loads(FLAT)
    # The JSON is given as a text (double encoded) by the server.
    epo = FakeServer(ok(json.dumps(json.dumps(rows[:3]))), ok(json.dumps(json.dumps(rows[3:]))),
                     ok(json.dumps('[]')))
    systems = list(epo.systems.all(batch_size=3))
    assert [system.id for system in systems] == [3, 4, 5, 7, 12]
    assert [request[1] for request in epo.requests] == [
        {'lastNodeId': '0', 'batchSize': '3'}, {'lastNodeId': '5', 'batchSize': '3'},
        {'lastNodeId': '12', 'batchSize': '3'}]
    assert systems[0].last_communication.isoformat() == '2026-10-17T12:03:54.060000+00:00'
    assert systems[0].group_id is None and systems[0].mac_address == '000C298190CD'


def test_get():
    epo = FakeServer(ok(SYSTEMS), ok(SYSTEMS), ok('[]'))
    assert epo.systems.get('w10entb01').id == 4
    assert epo.requests[0][1] == {'searchText': 'w10entb01', 'searchNameOnly': 'true'}
    assert epo.systems.get(12).name == 'rhel96srv'
    assert epo.systems.get('NOPE') is None
    twice = json.dumps([dict(json.loads(SYSTEMS)[1], **{'EPOComputerProperties.ParentID': i})
                        for i in (4, 20)])
    with pytest.raises(EPOError, match=r'Several systems are named W10ENTB01 \(ids 4, 20\)'):
        FakeServer(ok(twice)).systems.get('W10ENTB01')


def test_groups_list_and_get():
    epo = FakeServer(ok(BRANCHES), ok(GROUPS))
    groups = epo.groups.list()
    assert epo.requests[0][0] == 'core.executeQuery'
    # Same groups as system.findGroups, Lost and Found under its console name.
    expected = [Group.from_json(item) for item in epo.call('system.findGroups')]
    assert [(group.id, group.path) for group in groups] == sorted(
        [(group.id, group.path) for group in expected],
        key=lambda item: [part.lower() for part in item[1].split('\\')])
    root, sub = groups[0], [group for group in groups if group.id == 13][0]
    assert (root.path, root.parent_id, root.type) == ('My Organization', None, 4)
    assert (sub.path, sub.parent_id, sub.depth) == ('My Organization\\Test Group\\Test Sub', 12, 2)
    lost = [group for group in groups if group.id == 10][0]
    assert lost.lost_and_found and lost.path == 'My Organization\\Lost and Found\\(none)'
    epo = FakeServer(*[ok(BRANCHES)] * 3)
    assert epo.groups.get('workstations').id == 6
    assert epo.groups.get(12).name == 'Test Group'
    assert epo.groups.get('Nope') is None


def test_children_and_systems():
    # children() reads the groups twice (the group, then its subgroups).
    epo = FakeServer(*[ok(BRANCHES)] * 8, ok(WORKSTATIONS))
    assert [group.id for group in epo.groups.children('Test Group')] == [14, 13]
    assert [group.id for group in epo.groups.children('My Organization')] == [4, 9, 3, 11, 12, 6]
    assert len(epo.groups.children('My Organization', recursive=True)) == 9
    with pytest.raises(ValueError, match='Unknown System Tree group: Nope'):
        epo.groups.children('Nope')
    systems = epo.groups.systems('Workstations', subgroups=True)
    assert epo.requests[-1] == ('epogroup.findSystems', {'groupId': '6', 'searchSubgroups': 'true'})
    assert [system.name for system in systems] == ['W10ENTB01', 'W2022CORE']


def test_add():
    added = json.dumps([dict(json.loads(SYSTEMS)[1], **{
        'EPOComputerProperties.ParentID': 13, 'EPOComputerProperties.ComputerName': 'PC01',
        'EPOBranchNode.AutoID': 6})])
    epo = FakeServer(ok(BRANCHES), ok('[]'), ok('true'), ok(BRANCHES), ok(added))
    systems = epo.systems.add('PC01', 'Workstations')
    assert [system.id for system in systems] == [13]
    assert epo.requests[2] == ('system.importSystem', {'names': 'PC01', 'branchNodeID': '6'})


def test_add_refusals():
    # Lost and Found is filled by the server.
    epo = FakeServer(ok(BRANCHES))
    with pytest.raises(ValueError, match='Nothing is added to or moved into Lost and Found'):
        epo.systems.add('PC01', 3)
    # A name already in the System Tree would be ignored by the server.
    epo = FakeServer(ok(BRANCHES), ok(SYSTEMS))
    with pytest.raises(ValueError, match='Already in the System Tree.*W10ENTB01'):
        epo.systems.add('W10ENTB01', 'Workstations')
    # Unknown group: NullPointerException on the server.
    epo = FakeServer(ok(BRANCHES))
    with pytest.raises(ValueError, match='Unknown System Tree group: 999'):
        epo.systems.add('PC01', 999)
    with pytest.raises(ValueError, match='backslash'):
        epo.systems.add('A\\B', 'Workstations')
    # The import answered true but the system is not in the group.
    epo = FakeServer(ok(BRANCHES), ok('[]'), ok('true'), ok(BRANCHES), ok('[]'))
    with pytest.raises(EPOError, match=r'Not in My Organization\\Workstations after the import: pc01'):
        epo.systems.add('PC01', 'Workstations')


def test_move():
    epo = FakeServer(ok(BRANCHES), ok(SYSTEMS), ok('true'))
    assert epo.systems.move('W10ENTB01', 'Test Group') is True
    # autoSort is 0 or 1: the server refuses false and true.
    assert epo.requests[2] == ('system.move', {'ids': '4', 'parentGroupId': '12',
                                               'autoSort': '0'})
    # The server answers true for an unknown system: looked up first.
    epo = FakeServer(ok(BRANCHES), ok('[]'))
    with pytest.raises(ValueError, match='Unknown system: NOPE'):
        epo.systems.move('NOPE', 'Test Group')
    epo = FakeServer(ok(BRANCHES))
    with pytest.raises(ValueError, match='Lost and Found'):
        epo.systems.move(4, 'Lost and Found\\(none)')


def test_set_properties():
    epo = FakeServer(statuses('Computer updated successfully', 'Claude-TEST01'))
    assert epo.systems.set_properties(13, description='Claude desc', custom1='CF1',
                                      custom4='CF4') == ['Claude-TEST01']
    assert epo.requests[0] == ('system.setUserProperties', {
        'ids': '13', 'description': 'Claude desc', 'customField1': 'CF1', 'customField4': 'CF4'})
    with pytest.raises(ValueError, match='Give the description or a custom field'):
        epo.systems.set_properties(13)
    with pytest.raises(ValueError, match="can't clear a field.*custom2"):
        epo.systems.set_properties(13, custom2=' ')
    epo = FakeServer(statuses('Unable to take action on the computer because it may not exist',
                              'Claude-NOPE', status=-1))
    with pytest.raises(EPOError, match='Claude-NOPE: Unable to take action'):
        epo.systems.set_properties(99, custom1='x')


def test_names_of_the_answers_given_by_id():
    # With ids, setUserProperties and resort answer an empty name (lab).
    answer = ok(json.dumps([{'name': '', 'id': '4', 'message': 'Computer sorted successfully',
                             'status': 0}]))
    epo = FakeServer(ok(SYSTEMS), answer, answer)
    assert epo.systems.resort('W10ENTB01') == ['W10ENTB01']
    assert epo.systems.resort(4) == ['4']


def test_resort_and_delete():
    epo = FakeServer(statuses('Computer sorted successfully', 'Claude-TEST01'),
                     statuses('Computer deleted successfully', 'Claude-TEST01', 'Claude-TEST02'))
    assert epo.systems.resort(13) == ['Claude-TEST01']
    assert epo.systems.delete([13, 14]) == ['Claude-TEST01', 'Claude-TEST02']
    assert epo.requests[1] == ('system.delete', {'ids': '13,14', 'uninstall': 'false',
                                                 'uninstallSoftware': 'false'})
    with pytest.raises(ValueError, match='At least one system'):
        epo.systems.delete([])


def test_create_group():
    created = json.loads(BRANCHES) + [{
        'EPOBranchNode.AutoID': 15, 'EPOBranchNode.NodeName': 'Paris',
        'EPOBranchNode.ParentID': 20, 'EPOBranchNode.Type': 3, 'EPOBranchNode.Notes': None,
        'EPOBranchNode.NodeTextPath2': '\\Test Group\\Servers\\Paris\\'}]
    epo = FakeServer(ok(BRANCHES), ok('true'), ok(json.dumps(created)))
    group = epo.groups.create('Test Group\\Servers\\Paris')
    assert group.id == 15 and group.path == 'My Organization\\Test Group\\Servers\\Paris'
    command, body = epo.requests[1]
    # The file is imported under the deepest existing group (Test Group).
    assert command == 'system.importSystem'
    assert b'name="branchNodeID"\r\n\r\n12\r\n' in body
    assert b'filename="groups.txt"' in body and b'\r\n\r\nServers\\Paris\\\r\n\r\n' in body
    # An existing group is returned without a request.
    epo = FakeServer(ok(BRANCHES))
    assert epo.groups.create('Test Group').id == 12 and len(epo.requests) == 1
    with pytest.raises(ValueError, match='Lost and Found'):
        epo.groups.create('Lost and Found\\Mine')
    epo = FakeServer(ok(BRANCHES), ok('true'), ok(BRANCHES))
    with pytest.raises(EPOError, match='was not created'):
        epo.groups.create('Servers')


def test_import_file_and_destination():
    assert import_file(['Servers\\SRV01', ['Servers', 'Paris', '']]) == \
        'Servers\\SRV01\r\nServers\\Paris\\\r\n'
    check_destination('My Organization\\Lost Systems')
    with pytest.raises(ValueError):
        check_destination('lost and found')


def test_markdown():
    epo = FakeServer(ok(SYSTEMS), ok(BRANCHES))
    systems = epo.systems.find()
    text = systems_to_markdown(systems)
    assert text.splitlines()[2] == ('| System Name | Managed State | Tags | IP address | '
                                    'User Name | Last Communication | Agent Version |')
    assert '| W10ENTB01 | Managed | Escalated, Workstation | 192.168.100.234 | Demo | ' \
           '2026-10-14 16:35 | 5.8.6.185 |' in text
    details = systems[1].to_markdown()
    assert '| DNS Name | W10ENTB01.localdomain |' in details
    assert '| Is 64-bit OS | Yes |' in details and '| isDomainController | No |' in details
    assert '| Default Language | English (United States) |' in details
    tree = groups_to_markdown(epo.groups.list())
    assert tree.splitlines()[4] == '| My Organization | 2 | My Organization |  |'
    assert '| &nbsp;&nbsp;&nbsp;&nbsp;Test Sub | 13 |' in tree
    with pytest.raises(ValueError, match='Unknown system properties: nope'):
        systems_to_markdown(systems, columns=('name', 'nope'))


def test_labels_and_criteria_of_the_tag_catalog():
    # 44 fields are tag criteria properties: same SQUID key and console label.
    criteria = {attribute: criteria_property(attribute) for attribute in FIELDS}
    assert sum(prop is not None for prop in criteria.values()) == 44
    assert all(label(attribute) == prop.label for attribute, prop in criteria.items() if prop)
    assert criteria['custom1'].key == 'EPOComputerProperties.UserProperty1'
    assert criteria['is_laptop'].kind == 'enum' and criteria['tags'] is None
    assert {label(attribute) for attribute in FIELDS if criteria[attribute] is None} == {
        'System ID', 'IP address', 'Tags', 'Excluded Tags', 'Last Communication', 'Managed State',
        'Trellix Agent GUID', 'Agent Version', 'Group', 'Installed Products',
        'Product list last installation time', 'isDomainController'}


def test_tag_criteria_come_from_the_system_properties():
    # systemtree.PROPERTIES is the reference: the Computer Properties of the
    # tag criteria are built from it, in its order.
    from trellix_epo import tagcatalog
    from trellix_epo.systemtree import PROPERTIES
    assert [entry for entry in tagcatalog.PROPERTIES if entry[2] == 'Computer Properties'] == [
        (key, text, 'Computer Properties', kind) for _, key, text, kind, criteria in PROPERTIES
        if criteria]
    assert len([entry for entry in PROPERTIES if entry[4]]) == 58
    # The other properties of the criteria builder are read by System too.
    assert System('PC01', reboot_pending=True, system_model='VMware').value('reboot_pending') == 'True'


def test_system_object():
    system = System('PC01', id=4, custom1='PROD')
    assert system == System('PC01', id=4) and system != System('PC01', id=5)
    with pytest.raises(ValueError, match='Unknown system properties: color'):
        System('PC01', color='red')
