"""
Users and permission sets (trellix_epo.users, trellix_epo.epousers), without
a server.

Fixtures of the ePO 5.10 Update 7 lab: users.json is core.listUsers (the
single sign-on user renamed), permission_sets.xml core.exportPermissionSets
(8 sets, as exported), permission_set_names.json core.listPermSets (with the
test sets "Claude - PermSet" and "Claude - PermSet (imported)"). The answers
of the modifying commands are the ones of the lab tests ("Claude - User"
with Windows authentication, "Claude - Cert" with a certificate).
"""

import doctest
import json
from pathlib import Path
import urllib.parse

import pytest

from trellix_epo import users as module
from trellix_epo import epousers as operations
from trellix_epo import (EPOClient, PermissionSet, PermissionSetList, Role, User,
                         users_to_markdown)
from trellix_epo.epo import EPOError

FIXTURES = Path(__file__).parent / 'fixtures'
USERS = (FIXTURES / 'users.json').read_text(encoding='utf-8')
EXPORT = (FIXTURES / 'permission_sets.xml').read_bytes()
NAMES = (FIXTURES / 'permission_set_names.json').read_text(encoding='utf-8')
CLAUDE = {'id': 32, 'name': 'Claude - User', 'fullName': 'Claude Test',
          'email': 'claude@example.com', 'phoneNumber': '0102030405', 'disabled': False,
          'admin': False, 'authType': 'ntlm', 'authDetails': 'LAB\\claude',
          'notes': 'Claude API test', 'allowedIPs': '192.168.100.0/24'}


def ok(text):
    """
    Returns the answer of the server for a text.
    """
    return 'OK:\r\n' + text


def users_with(*extra):
    """
    Returns core.listUsers with more users.
    """
    return ok(json.dumps(json.loads(USERS) + list(extra)))


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
    assert result.attempted >= 25 and result.failed == 0
    result = doctest.testmod(operations)
    assert result.attempted >= 5 and result.failed == 0


def test_users():
    users = {user.name: user for user in (User.from_json(item) for item in json.loads(USERS))}
    assert set(users) == {'admin', 'sso.user@example.com', 'defaultDxlUser', 'system'}
    assert users['admin'].admin and users['admin'].auth_label == 'ePO password'
    assert users['sso.user@example.com'].auth_type == 'mcafeemvisionsso'
    assert users['system'].disabled
    claude = User.from_json(CLAUDE)
    assert claude.windows_account == ('LAB', 'claude') and claude.subject_dn is None
    assert claude.allowed_ips == ['192.168.100.0/24']


def test_permission_sets_written_as_exported():
    sets = PermissionSetList(EXPORT)
    assert len(sets) == 8 and sets.get_xml_content() == EXPORT
    reviewer = sets.get('Global Reviewer')
    assert reviewer.has_role('role:SOLIDCORE_META.SCOR_AWL.reviewer')
    tree = [role for role in reviewer.roles if role.uri == 'role:epo.dir.access'][0]
    assert tree.systems == ['\\']
    # Same roles in another order: equal (the server changes the order).
    shuffled = PermissionSet('Global Reviewer', list(reversed(reviewer.roles)))
    assert shuffled == reviewer


def test_permission_set_editing():
    sets = PermissionSetList(EXPORT)
    copy = sets.get('Global Reviewer').copy('Claude - PermSet')
    copy.remove_role('role:softman.viewOnly')
    copy.add_role('role:core.query.guest')
    assert not copy.has_role('role:softman.viewOnly')
    with pytest.raises(ValueError, match='has no role role:nope'):
        copy.remove_role('role:nope')
    with pytest.raises(ValueError, match='is named Global Reviewer already'):
        sets.add(sets.get('Global Reviewer').copy('Global Reviewer'))
    new = PermissionSetList()
    new.add(copy)
    again = PermissionSetList(new.get_xml_content())
    assert again.get('Claude - PermSet') == copy
    assert again.get_xml_content().startswith(b'<list id="1">\n  <permissionSet id="2">\n')
    with pytest.raises(ValueError, match='A permission set name is required'):
        PermissionSet(' ')


def test_list_and_get_users():
    epo = FakeServer(ok(USERS), ok(USERS), ok(json.dumps([{'id': 1, 'name': 'Global Reviewer'}])))
    assert len(epo.users.list()) == 4
    epo.users.list(permission_set='Global Reviewer')
    assert epo.requests[1] == ('core.listUsers', {'permSetName': 'Global Reviewer'})
    epo = FakeServer(users_with(CLAUDE), ok(json.dumps([{'id': 1, 'name': 'Global Reviewer'}])))
    users = epo.users.list(with_permission_sets=True)
    claude = [user for user in users if user.name == 'Claude - User'][0]
    assert claude.permission_sets == ['Global Reviewer']
    assert all(user.permission_sets == [] for user in users if user.admin)
    assert epo.requests[1] == ('core.listPermSets', {'userId': '32'})


def test_add_user():
    epo = FakeServer(ok('true'), users_with(CLAUDE))
    user = epo.users.add('Claude - User', windows=('LAB', 'claude'), full_name='Claude Test',
                         allowed_ips=['192.168.100.0/24'])
    assert user.id == 32 and user.auth_type == 'ntlm'
    assert epo.requests[0] == ('core.addUser', {
        'userName': 'Claude - User', 'windowsDomain': 'LAB', 'windowsUserName': 'claude',
        'fullName': 'Claude Test', 'allowedIPs': '192.168.100.0/24', 'admin': 'false',
        'disabled': 'false'})
    epo = FakeServer('Error 0 :\r\nThe name "Claude - User" is already in use.')
    with pytest.raises(EPOError, match='already in use'):
        epo.users.add('Claude - User', subject_dn='CN=Claude')
    with pytest.raises(ValueError, match='Give one authentication'):
        epo.users.add('x')
    # The server saves any text as allowedIPs (lab): checked here.
    with pytest.raises(ValueError, match="Not an IP address or CIDR subnet: 'not-an-ip'"):
        epo.users.add('x', windows=('LAB', 'x'), allowed_ips='not-an-ip')


def test_update_and_remove_user():
    disabled = dict(CLAUDE, disabled=True, email='')
    epo = FakeServer(users_with(CLAUDE), ok('true'), users_with(disabled))
    user = epo.users.update('Claude - User', disabled=True, email='')
    assert user.disabled and user.email == ''
    # email='' is sent (parse_qsl of FakeServer leaves the empty value out).
    assert epo.requests[1] == ('core.updateUser', {'userId': '32', 'disabled': 'true'})
    epo = FakeServer(users_with(CLAUDE))
    with pytest.raises(ValueError, match='Give a value to change'):
        epo.users.update('Claude - User')
    epo = FakeServer(users_with(CLAUDE), ok('true'))
    assert epo.users.remove(32) is True
    assert epo.requests[1] == ('core.removeUser', {'userId': '32'})
    epo = FakeServer(ok(USERS))
    with pytest.raises(ValueError, match='Unknown user: Claude - Cert'):
        epo.users.remove('Claude - Cert')


def test_permission_sets_of_a_user():
    both = ok(json.dumps([{'id': 1, 'name': 'Global Reviewer'}, {'id': 8, 'name': 'Solidcore Reviewer'}]))
    one = ok(json.dumps([{'id': 1, 'name': 'Global Reviewer'}]))
    epo = FakeServer(users_with(CLAUDE), ok('true'), both)
    assert epo.users.add_permission_sets('Claude - User', ['Global Reviewer', 'Solidcore Reviewer']) \
        == ['Global Reviewer', 'Solidcore Reviewer']
    assert epo.requests[1] == ('core.addPermSetsForUser', {
        'userId': '32', 'permSetName': 'Global Reviewer,Solidcore Reviewer'})
    epo = FakeServer(users_with(CLAUDE), both, ok('true'), one)
    assert epo.users.remove_permission_sets('Claude - User', 'Solidcore Reviewer') == [
        'Global Reviewer']
    # The server answers true for a set the user doesn't have (lab).
    epo = FakeServer(users_with(CLAUDE), one)
    with pytest.raises(ValueError, match='Claude - User has no permission set Solidcore Reviewer'):
        epo.users.remove_permission_sets('Claude - User', 'Solidcore Reviewer')
    epo = FakeServer(users_with(CLAUDE), 'Error 0 :\r\nNames of invalid permission sets: Nope')
    with pytest.raises(EPOError, match='invalid permission sets: Nope'):
        epo.users.add_permission_sets('Claude - User', 'Nope')


def test_export_and_names():
    epo = FakeServer(ok(EXPORT.decode() + '\r\n'), ok(NAMES))
    sets = epo.permission_sets.export()
    assert sets.names()[0] == 'Global Reviewer' and sets.get_xml_content() == EXPORT
    assert epo.permission_sets.names()['Global Reviewer'] == 1


def test_import_sets():
    copy = PermissionSetList(EXPORT).get('Global Reviewer').copy('Claude - New')
    after = PermissionSetList(EXPORT)
    after.add(PermissionSet('Claude - New', list(reversed(copy.roles))))
    epo = FakeServer(ok(NAMES), ok('true'), ok(after.get_xml_content().decode()))
    imported = epo.permission_sets.import_sets([copy])
    assert imported[0].name == 'Claude - New'
    command, body = epo.requests[1]
    assert command == 'core.importPermissionSets' and b'name="overwrite"\r\n\r\nfalse' in body
    assert b'<name>Claude - New</name>' in body
    # An existing name without overwrite would be imported as "(imported)".
    epo = FakeServer(ok(NAMES))
    with pytest.raises(ValueError, match=r'the server would import them as "<name> \(imported\)"'):
        epo.permission_sets.import_sets([PermissionSet('Global Reviewer')])
    # Not as imported after the call.
    epo = FakeServer(ok('true'), ok(EXPORT.decode()))
    with pytest.raises(EPOError, match='Global Reviewer is not as imported'):
        epo.permission_sets.import_sets([PermissionSet('Global Reviewer')], overwrite=True)


def test_markdown():
    users = [User.from_json(item) for item in json.loads(USERS)] + [User.from_json(CLAUDE)]
    users[-1].permission_sets = ['Global Reviewer']
    text = users_to_markdown(users)
    assert '| Claude - User | Claude Test | Windows (LAB\\\\claude) |  |  | Global Reviewer | ' \
           '192.168.100.0/24 |' in text
    report = PermissionSetList(EXPORT).to_markdown()
    assert '| Global Reviewer | 44 |' in report and '## Global Reviewer' in report
    assert '| epo | dir.access | \\\\ |' in report
    assert Role('role:issue.auditor?type=issue.type.untyped').parts == (
        'issue', 'auditor?type=issue.type.untyped')
