# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOUsers and EPOPermissionSets, the user operations of
EPOClient (epo.users, epo.permission_sets): list, add, change and remove
users, give or take their permission sets, export and import the
permission sets (core.* user commands).

    epo.users.add('helpdesk', windows=('LAB', 'helpdesk'), full_name='Helpdesk')
    epo.users.add_permission_sets('helpdesk', ['Global Reviewer'])
    epo.users.update('helpdesk', disabled=True, allowed_ips=['192.168.100.0/24'])
    sets = epo.permission_sets.export()                  # PermissionSetList
    epo.permission_sets.import_sets([sets.get('Global Reviewer').copy('Helpdesk')])
    print(users_to_markdown(epo.users.list(with_permission_sets=True)))

The Web API has no command to delete a permission set (console only), to
read one user, or to give the console labels of the rights. A password is
a parameter of add() and update() for the scripts of the users; the
library never stores it.

Server behaviours handled here (checked on ePO 5.10 Update 7 with the
users "Claude - User" (Windows) and "Claude - Cert" (certificate) and the
permission set "Claude - PermSet"):
- core.addUser of an existing name gives 'The name "..." is already in
  use.' (retryTolerant=true answers true without a change);
- core.updateUser clears a field given empty (email=''), refuses a blank
  email ("is not a valid email address"), changes the authentication type
  when given another one, and saves any text as allowedIPs (checked here);
- core.removePermSetsForUser answers true for a set the user doesn't have:
  remove_permission_sets() refuses it;
- core.importPermissionSets without overwrite imports a set whose name
  exists as "<name> (imported)", without a message: import_sets() refuses
  it; with overwrite the set is replaced; the export gives the roles in
  another order and without the duplicates (compared as sets here);
- the ids of the export (XStream) are not the ids of core.listPermSets.
"""

from .epo import EPOError
from .users import PermissionSetList, User, check_allowed_ips


def _done(answer):
    """
    True for the "true" answer of the user commands.

    >>> _done(True), _done('true'), _done('no')
    (True, True, False)
    """
    return answer is True or (isinstance(answer, str) and answer.strip().lower() == 'true')


def _auth(password=None, windows=None, subject_dn=None, required=True):
    """
    Returns the authentication parameters of core.addUser / updateUser:
    one of password, windows (domain, user name) and subject_dn.

    >>> _auth(windows=('LAB', 'claude'))
    {'windowsDomain': 'LAB', 'windowsUserName': 'claude'}
    >>> _auth(subject_dn='CN=Claude', password='x')
    Traceback (most recent call last):
    ...
    ValueError: Give one authentication: password, windows or subject_dn.
    """
    given = [value for value in (password, windows, subject_dn) if value is not None]
    if len(given) > 1 or (required and not given):
        raise ValueError('Give one authentication: password, windows or subject_dn.')
    if password is not None:
        return {'password': password}
    if windows is not None:
        domain, name = windows
        return {'windowsDomain': domain, 'windowsUserName': name}
    if subject_dn is not None:
        return {'subjectDN': subject_dn}
    return {}


def _details(full_name=None, email=None, phone=None, notes=None, allowed_ips=None, admin=None,
             disabled=None):
    """
    Returns the other parameters of core.addUser / updateUser (None left
    out; an empty text clears the field).

    >>> _details(email='', allowed_ips=['10.0.0.0/8', '::1'], admin=False)
    {'email': '', 'allowedIPs': '10.0.0.0/8,::1', 'admin': False}
    """
    params = {}
    for key, value in (('fullName', full_name), ('email', email), ('phoneNumber', phone),
                       ('notes', notes)):
        if value is not None:
            params[key] = value
    if allowed_ips is not None:
        allowed_ips = [allowed_ips] if isinstance(allowed_ips, str) else list(allowed_ips)
        check_allowed_ips(allowed_ips)
        params['allowedIPs'] = ','.join(allowed_ips)
    for key, value in (('admin', admin), ('disabled', disabled)):
        if value is not None:
            params[key] = bool(value)
    return params


def _names(items):
    """
    Returns names given as one text or a list.

    >>> _names('A'), _names(['A', 'B'])
    (['A'], ['A', 'B'])
    """
    return [items] if isinstance(items, str) else list(items)


class EPOUsers():
    """
    The user operations of an EPOClient (epo.users).
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPOUsers of {!r}>'.format(self.epo)

    def list(self, permission_set=None, with_permission_sets=False):
        """
        Returns the users (core.listUsers).

        Example: epo.users.list(with_permission_sets=True).

        :param: permission_set: Keep the users of a permission set (name).
        :param: with_permission_sets: Also read the sets of each user (one
                                      call per user).
        """
        users = [User.from_json(item) for item in self.epo.call(
            'core.listUsers', permSetName=permission_set)]
        if with_permission_sets:
            for user in users:
                user.permission_sets = [] if user.admin else self.permission_sets(user)
        return users

    def get(self, user):
        """
        Returns a user by name (case sensitive) or id, or None.

        Example: epo.users.get('admin').
        """
        if isinstance(user, User):
            user = user.id
        return next((item for item in self.list()
                     if (item.id == user if isinstance(user, int) else item.name == user)), None)

    def require(self, user):
        """
        Returns a user by name, id or User, or raises ValueError.

        Example: epo.users.require('admin').
        """
        found = self.get(user)
        if found is None:
            raise ValueError('Unknown user: {}.'.format(user.name if isinstance(user, User) else user))
        return found

    def add(self, name, password=None, windows=None, subject_dn=None, full_name=None, email=None,
            phone=None, notes=None, allowed_ips=None, admin=False, disabled=False):
        """
        Adds a user (core.addUser) with one authentication: a password, a
        Windows account or a certificate subject DN.

        Example: epo.users.add('helpdesk', windows=('LAB', 'helpdesk')).

        :param: windows: (domain, user name) of a Windows account.
        :param: subject_dn: The subject DN of the personal certificate.
        :param: allowed_ips: Addresses or CIDR subnets the user logs on from.
        :return: The User read back.
        :raise: ValueError: No or several authentications, a bad address.
        :raise: EPOError: The name exists ('The name "..." is already in use.').
        """
        params = _auth(password, windows, subject_dn)
        params.update(_details(full_name, email, phone, notes, allowed_ips, admin, disabled))
        if not _done(self.epo.call('core.addUser', userName=name, **params)):
            raise EPOError('core.addUser', '{} was not added.'.format(name))
        return self.require(name)

    def update(self, user, new_name=None, password=None, windows=None, subject_dn=None,
               full_name=None, email=None, phone=None, notes=None, allowed_ips=None, admin=None,
               disabled=None):
        """
        Changes a user (core.updateUser): the values given (an empty text
        clears a field), another name, another authentication.

        Example: epo.users.update('helpdesk', disabled=True, email='').

        :return: The User read back.
        """
        found = self.require(user)
        params = _auth(password, windows, subject_dn, required=False)
        params.update(_details(full_name, email, phone, notes, allowed_ips, admin, disabled))
        if new_name is not None:
            params['newUserName'] = new_name
        if not params:
            raise ValueError('Give a value to change.')
        if not _done(self.epo.call('core.updateUser', userId=found.id, **params)):
            raise EPOError('core.updateUser', '{} was not updated.'.format(found.name))
        return self.require(found.id)

    def remove(self, user):
        """
        Removes a user (core.removeUser).

        Example: epo.users.remove('helpdesk').

        :raise: ValueError: Unknown user.
        """
        found = self.require(user)
        return _done(self.epo.call('core.removeUser', userId=found.id))

    def permission_sets(self, user):
        """
        Returns the names of the permission sets of a user (core.listPermSets;
        the sets given by an LDAP group are not listed).

        Example: epo.users.permission_sets('helpdesk').
        """
        found = user if isinstance(user, User) else self.require(user)
        return [item['name'] for item in self.epo.call('core.listPermSets', userId=found.id)]

    def add_permission_sets(self, user, names):
        """
        Gives permission sets to a user (core.addPermSetsForUser).

        Example: epo.users.add_permission_sets('helpdesk', ['Global Reviewer']).

        :return: The names of the sets of the user after the change.
        :raise: EPOError: An unknown set ("Names of invalid permission sets: ...").
        """
        found = self.require(user)
        self.epo.call('core.addPermSetsForUser', userId=found.id,
                      permSetName=','.join(_names(names)))
        return self.permission_sets(found)

    def remove_permission_sets(self, user, names):
        """
        Takes permission sets from a user (core.removePermSetsForUser).

        Example: epo.users.remove_permission_sets('helpdesk', 'Global Reviewer').

        :return: The names of the sets of the user after the change.
        :raise: ValueError: The user doesn't have a set (the server would
                            answer true).
        """
        found = self.require(user)
        current = self.permission_sets(found)
        missing = [name for name in _names(names) if name not in current]
        if missing:
            raise ValueError('{} has no permission set {}.'.format(found.name, ', '.join(missing)))
        self.epo.call('core.removePermSetsForUser', userId=found.id,
                      permSetName=','.join(_names(names)))
        return self.permission_sets(found)


class EPOPermissionSets():
    """
    The permission set operations of an EPOClient (epo.permission_sets).
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPOPermissionSets of {!r}>'.format(self.epo)

    def names(self):
        """
        Returns {name: id} of the permission sets (core.listPermSets).

        Example: epo.permission_sets.names()['Global Reviewer'].
        """
        return {item['name']: item['id'] for item in self.epo.call('core.listPermSets')}

    def export(self):
        """
        Returns the permission sets with their roles (core.exportPermissionSets).

        Example: epo.permission_sets.export().get('Global Reviewer').roles.
        """
        return PermissionSetList(self.epo.call('core.exportPermissionSets',
                                               output='terse').strip())

    def get(self, name):
        """
        Returns a permission set with its roles, or None.

        Example: epo.permission_sets.get('Solidcore Reviewer').
        """
        return self.export().get(name)

    def users(self, name):
        """
        Returns the users of a permission set (core.listUsers).

        Example: [user.name for user in epo.permission_sets.users('Global Reviewer')].
        """
        return [User.from_json(item) for item in self.epo.call('core.listUsers', permSetName=name)]

    def import_sets(self, sets, overwrite=False, file_name='permsets.xml'):
        """
        Imports permission sets (core.importPermissionSets) and checks their
        roles in a new export.

        Example: epo.permission_sets.import_sets([PermissionSet('Helpdesk', roles)]).

        :param: sets: A PermissionSetList or a list of PermissionSet.
        :param: overwrite: Replace the sets of the same name.
        :return: The imported sets as read back.
        :raise: ValueError: A set exists and overwrite is False (the server
                            would import it as "<name> (imported)").
        :raise: EPOError: A set is not as imported.
        """
        content = sets if isinstance(sets, PermissionSetList) else PermissionSetList()
        if content is not sets:
            for item in sets:
                content.add(item)
        if not overwrite:
            existing = [name for name in content.names() if name in self.names()]
            if existing:
                raise ValueError('Permission sets exist already (the server would import them as '
                                 '"<name> (imported)"): {}.'.format(', '.join(existing)))
        if not _done(self.epo.call('core.importPermissionSets', overwrite=overwrite,
                                   files={'file': (file_name, content.get_xml_content())})):
            raise EPOError('core.importPermissionSets', 'The permission sets were not imported.')
        after = self.export()
        imported = []
        for item in content:
            found = after.get(item.name)
            if found is None or found.role_set() != item.role_set():
                raise EPOError('core.importPermissionSets', '{} is not as imported.'.format(
                    item.name))
            imported.append(found)
        return imported
