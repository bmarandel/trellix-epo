# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOSystems and EPOGroups, the System Tree operations of
EPOClient (epo.systems and epo.groups): find, add, move, sort and delete
systems, set their description and custom fields (system.* commands), list
the groups, their systems, and create groups (epogroup.findSystems, the
EPOBranchNode table, system.importSystem).

    epo.systems.find('PC')                                   # [System...]
    epo.systems.add(['PC01', 'PC02'], 'My Organization\\Workstations')
    epo.systems.set_properties('PC01', description='Accounting', custom1='PROD')
    epo.systems.move('PC01', 'My Organization\\Servers')
    epo.groups.create('My Organization\\Servers\\Paris')     # Group
    epo.groups.systems('My Organization\\Workstations', subgroups=True)

The Web API has no command to rename or delete a group: do it in the
console (System Tree > System Tree Actions). Groups are created as the
console imports a text file (New Systems > Import systems and System Tree
structure): a line ending with a backslash creates a group without system.
Nothing is created in or moved to Lost and Found (see
systemtree.check_destination()). Agents are not deployed by add(): the
push needs an account of the systems (see the agent deployment of the
console).

Server behaviours handled here (checked on ePO 5.10 Update 7 with dummy
systems, never managed):
- system.importSystem answers "true" at once (the systems exist), but
  ignores a name already in the System Tree without allowDuplicates (not
  copied, not moved): add() refuses these names; an unknown branchNodeID
  gives a NullPointerException: add() and create() check the group;
- system.setUserProperties, system.resort and system.delete answer a list
  of {name, id, message, status}, status -1 for an unknown system in an
  "OK" answer: raised as EPOError here;
- system.setUserProperties leaves out the empty or blank values (a field
  can't be cleared), and fails with an SQL error when no value is left;
- system.move answers "true" for an unknown system, and an SQL error for
  an unknown group: the systems are looked up first; its autoSort takes 0
  or 1 (true/false are refused, despite the help), 1 sets
  EPOLeafNode.ResortEnabled;
- system.resort sends a system with sorting enabled and matching no group
  criteria to Lost and Found (with sorting disabled, it stays);
- with "ids", system.setUserProperties and system.resort give an empty
  name in their answer (system.delete gives it): the names come from the
  systems looked up;
- epogroup.findSystems answers [] for an unknown group;
- system.find.multiple gives its JSON as a text (decoded twice here).
"""

import json

from .epo import EPOError
from .squid import Query
from .systemtree import (GLOBAL_ROOT, CUSTOM_FIELDS, Group, System,
                         check_destination, check_name, import_file, normalize_path)

# Columns of the EPOBranchNode table read for the groups.
GROUP_COLUMNS = ('AutoID', 'NodeName', 'ParentID', 'Type', 'Notes', 'NodeTextPath2')


def _items(value):
    """
    Returns a value or a list of values as a list (the text is one item,
    not a comma separated list: a system name may hold a comma... never in
    practice, but the caller says what it means).

    >>> _items('PC01'), _items(['PC01', 4]), _items(None)
    (['PC01'], ['PC01', 4], [])
    """
    if value is None:
        return []
    if isinstance(value, (str, int, System, Group)):
        return [value]
    return list(value)


def _statuses(command, answer, names=None):
    """
    Checks the list of {name, id, message, status} of setUserProperties,
    resort and delete, and returns the names done: the name of the answer,
    else the one of names (id -> name; the answer has no name when the
    systems are given by id), else the id.

    >>> _statuses('system.delete', [{'name': 'PC01', 'id': '13', 'status': 0,
    ...     'message': 'Computer deleted successfully'}])
    ['PC01']
    >>> _statuses('system.resort', [{'name': '', 'id': '13', 'status': 0,
    ...     'message': 'Computer sorted successfully'}], {13: 'PC01'})
    ['PC01']
    >>> _statuses('system.delete', [{'name': 'PC09', 'id': '-1', 'status': -1,
    ...     'message': 'Unable to take action on the computer because it may not exist'}])
    Traceback (most recent call last):
    ...
    trellix_epo.epo.EPOError: system.delete: PC09: Unable to take action on the computer because it may not exist
    """
    if not isinstance(answer, list):
        raise EPOError(command, 'Unexpected answer: {!r}'.format(answer)[:500])
    names = names or {}

    def name(item):
        # The name of the answer, of the systems looked up, or the id.
        number = int(item['id']) if str(item.get('id', '')).lstrip('-').isdigit() else None
        return item.get('name') or names.get(number) or str(item.get('id'))

    failed = [item for item in answer if item.get('status') != 0]
    if failed:
        raise EPOError(command, '; '.join('{}: {}'.format(name(item), item.get('message'))
                                          for item in failed))
    return [name(item) for item in answer]


def _done(answer):
    """
    True for the "true" answer of system.importSystem and system.move.

    >>> _done(True), _done('true'), _done('other')
    (True, True, False)
    """
    return answer is True or (isinstance(answer, str) and answer.strip().lower() == 'true')


class EPOSystems():
    """
    The system operations of an EPOClient (epo.systems).
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
        return '<EPOSystems of {!r}>'.format(self.epo)

    def find(self, search_text='', name_only=False):
        """
        Returns the systems whose name, IP address, MAC address, user name,
        agent GUID or tag contains the text (system.find), with all their
        properties; all the systems when the text is empty.

        Example: epo.systems.find('W2022', name_only=True).

        :param: search_text: The text (no wildcard).
        :param: name_only: Search the system names only.
        """
        return [System.from_json(item) for item in self.epo.call(
            'system.find', searchText=search_text, searchNameOnly=True if name_only else None)]

    def all(self, batch_size=500):
        """
        Yields every system of the System Tree, by batches of batch_size
        (system.find.multiple), sorted by id. The systems have the fields
        of FLAT_FIELDS only (name, domain, MAC address, OS type, user,
        Last Communication, Managed State, installed products, domain
        controller): use find() or get() for the others.

        Example: names = [system.name for system in epo.systems.all()].
        """
        last = 0
        while True:
            answer = self.epo.call('system.find.multiple', lastNodeId=last, batchSize=batch_size)
            rows = json.loads(answer) if isinstance(answer, str) else answer
            if not rows:
                return
            for row in rows:
                yield System.from_flat(row)
            last = rows[-1]['LeafNodeId']

    def get(self, system):
        """
        Returns a system with all its properties, or None.

        Example: epo.systems.get('PC01'), epo.systems.get(4).

        :param: system: The system name (case insensitive), its id or the
                        System.
        :raise: EPOError: Several systems have the name (duplicates): give
                          the id.
        """
        if isinstance(system, System):
            system = system.id if system.id is not None else system.name
        if isinstance(system, int):
            return next((item for item in self.find() if item.id == system), None)
        found = [item for item in self.find(system, name_only=True)
                 if item.name.lower() == system.lower()]
        if len(found) > 1:
            raise EPOError('system.find', 'Several systems are named {} (ids {}): give the '
                           'id.'.format(system, ', '.join(str(item.id) for item in found)))
        return found[0] if found else None

    def _ids(self, systems):
        """
        Returns {id: name} of systems given by name, id or System (the name
        is None for an id given alone).

        Example: self._ids(['PC01', 12]) gives {4: 'PC01', 12: None}.

        :raise: ValueError: No system, or an unknown system.
        """
        ids = {}
        for system in _items(systems):
            if isinstance(system, System) and system.id is not None:
                ids[system.id] = system.name
            elif isinstance(system, int):
                ids[system] = None
            else:
                found = self.get(system)
                if found is None:
                    raise ValueError('Unknown system: {}.'.format(
                        system.name if isinstance(system, System) else system))
                ids[found.id] = found.name
        if not ids:
            raise ValueError('At least one system is required.')
        return ids

    @staticmethod
    def _ids_parameter(ids):
        """
        Returns the "ids" parameter (comma separated) of {id: name}.

        >>> EPOSystems._ids_parameter({4: 'PC01', 12: None})
        '4,12'
        """
        return ','.join(str(item) for item in ids)

    def add(self, names, group, allow_duplicates=False):
        """
        Adds systems to a group of the System Tree (system.importSystem, New
        Systems of the console), without deploying the agent: they stay
        unmanaged until an agent connects.

        Example: epo.systems.add(['PC01', 'PC02'], 'My Organization\\Workstations').

        :param: names: The system names (NetBIOS name, list or one name).
        :param: group: The group path, id or Group (not Lost and Found).
        :param: allow_duplicates: Add a name already in the System Tree
                                  as another system.
        :return: The systems added (System, read back from the group).
        :raise: ValueError: Unknown group, Lost and Found, a name already in
                            the System Tree.
        :raise: EPOError: A system is not in the group after the import.
        """
        names = _items(names)
        if not names:
            raise ValueError('At least one system name is required.')
        for name in names:
            check_name(name)
        target = self.epo.groups.require(group)
        check_destination(target.path)
        if not allow_duplicates:
            existing = [name for name in names
                        if any(item.name.lower() == name.lower()
                               for item in self.find(name, name_only=True))]
            if existing:
                raise ValueError('Already in the System Tree (the server would ignore them): '
                                 '{}.'.format(', '.join(existing)))
        answer = self.epo.call('system.importSystem', names=','.join(names),
                               branchNodeID=target.id, allowDuplicates=allow_duplicates or None)
        if not _done(answer):
            raise EPOError('system.importSystem', 'Unexpected answer: {!r}'.format(answer)[:500])
        added = [system for system in self.epo.groups.systems(target)
                 if system.name.lower() in {name.lower() for name in names}]
        missing = sorted({name.lower() for name in names} -
                         {system.name.lower() for system in added})
        if missing:
            raise EPOError('system.importSystem', 'Not in {} after the import: {}.'.format(
                target.path, ', '.join(missing)))
        return added

    def move(self, systems, group, auto_sort=False):
        """
        Moves systems to a group (system.move).

        Example: epo.systems.move(['PC01', 'PC02'], 'My Organization\\Servers').

        :param: systems: The systems (names, ids or System, or one of them).
        :param: group: The group path, id or Group (not Lost and Found).
        :param: auto_sort: Enable System Tree sorting on the systems
                           (EPOLeafNode.ResortEnabled), else disable it.
        :return: True once moved.
        :raise: ValueError: Unknown system or group, Lost and Found.
        """
        target = self.epo.groups.require(group)
        check_destination(target.path)
        # autoSort takes 0 or 1 (the server refuses true and false).
        answer = self.epo.call('system.move', ids=self._ids_parameter(self._ids(systems)),
                               parentGroupId=target.id, autoSort=1 if auto_sort else 0)
        if not _done(answer):
            raise EPOError('system.move', 'Unexpected answer: {!r}'.format(answer)[:500])
        return True

    def set_properties(self, systems, description=None, custom1=None, custom2=None,
                       custom3=None, custom4=None):
        """
        Sets the Description and the Custom 1 to 4 fields of systems
        (system.setUserProperties, Edit Description and Custom of the
        console). The fields left to None keep their value; the Web API
        can't clear a field (an empty value is ignored by the server).

        Example: epo.systems.set_properties('PC01', description='Accounting', custom1='PROD').

        :param: systems: The systems (names, ids or System, or one of them).
        :return: The names of the systems updated.
        :raise: ValueError: No value, or an empty value.
        :raise: EPOError: The server failed on a system.
        """
        values = {'description': description}
        values.update(zip(CUSTOM_FIELDS, (custom1, custom2, custom3, custom4)))
        values = {key: value for key, value in values.items() if value is not None}
        if not values:
            raise ValueError('Give the description or a custom field.')
        blank = [key for key, value in values.items() if not str(value).strip()]
        if blank:
            raise ValueError("The Web API can't clear a field (the server ignores empty values): "
                             '{}.'.format(', '.join(blank)))
        params = {('customField' + key[-1] if key.startswith('custom') else key): value
                  for key, value in values.items()}
        ids = self._ids(systems)
        return _statuses('system.setUserProperties', self.epo.call(
            'system.setUserProperties', ids=self._ids_parameter(ids), **params), ids)

    def resort(self, systems):
        """
        Sorts systems into the System Tree by the sorting criteria of the
        groups (system.resort, Sort Now of the console). A system whose
        sorting is disabled (EPOLeafNode.ResortEnabled, move(auto_sort=...))
        stays in its group; a system whose sorting is enabled and that
        matches no criteria goes to Lost and Found (checked on the lab):
        sort only systems the groups' criteria cover.

        Example: epo.systems.resort('PC01').

        :return: The names of the systems sorted.
        """
        ids = self._ids(systems)
        return _statuses('system.resort', self.epo.call(
            'system.resort', ids=self._ids_parameter(ids)), ids)

    def delete(self, systems, uninstall=False, uninstall_software=False):
        """
        Deletes systems from the System Tree (system.delete).

        Example: epo.systems.delete(['PC01', 'PC02']).

        :param: systems: The systems (names, ids or System, or one of them).
        :param: uninstall: Also uninstall the agent at its next connection.
        :param: uninstall_software: Also uninstall the managed products
                                    before the agent.
        :return: The names of the systems deleted.
        :raise: EPOError: The server failed on a system.
        """
        ids = self._ids(systems)
        return _statuses('system.delete', self.epo.call(
            'system.delete', ids=self._ids_parameter(ids), uninstall=uninstall,
            uninstallSoftware=uninstall_software), ids)


class EPOGroups():
    """
    The System Tree group operations of an EPOClient (epo.groups).
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
        return '<EPOGroups of {!r}>'.format(self.epo)

    def list(self):
        """
        Returns the groups of the System Tree (EPOBranchNode table: id,
        path, parent, type, notes), My Organization first, in tree order.

        Example: [group.path for group in epo.groups.list()].
        """
        rows = self.epo.query(Query('EPOBranchNode').select(*GROUP_COLUMNS))
        groups = [Group.from_json(row) for row in rows
                  if row.get('EPOBranchNode.Type') != GLOBAL_ROOT]
        return sorted(groups, key=lambda item: [part.lower() for part in item.path.split('\\')])

    def get(self, group):
        """
        Returns a group, or None.

        Example: epo.groups.get('My Organization\\Workstations'), epo.groups.get(6).

        :param: group: The group path (from My Organization or not, case
                       insensitive), its id or the Group.
        """
        if isinstance(group, Group):
            group = group.id
        if isinstance(group, int):
            return next((item for item in self.list() if item.id == group), None)
        path = normalize_path(group).lower()
        return next((item for item in self.list() if item.path.lower() == path), None)

    def require(self, group):
        """
        Returns a group, or raises ValueError when it doesn't exist.

        Example: epo.groups.require('Workstations').
        """
        found = self.get(group)
        if found is None:
            raise ValueError('Unknown System Tree group: {}.'.format(
                group.path if isinstance(group, Group) else group))
        return found

    def children(self, group, recursive=False):
        """
        Returns the subgroups of a group.

        Example: epo.groups.children('My Organization').

        :param: recursive: All the levels below the group (direct
                           subgroups only by default).
        """
        parent = self.require(group)
        prefix = parent.path.lower() + '\\'
        return [item for item in self.list() if item.path.lower().startswith(prefix) and
                (recursive or item.parent_id == parent.id)]

    def systems(self, group, subgroups=False):
        """
        Returns the systems of a group with all their properties
        (epogroup.findSystems).

        Example: epo.groups.systems('Workstations', subgroups=True).

        :param: subgroups: Also the systems of the subgroups.
        :raise: ValueError: Unknown group (the server answers []).
        """
        target = self.require(group)
        return [System.from_json(item) for item in self.epo.call(
            'epogroup.findSystems', groupId=target.id, searchSubgroups=subgroups)]

    def create(self, path):
        """
        Creates a group and its missing parent groups (system.importSystem
        with a file line "Group\\Subgroup\\": the Web API has no command to
        create, rename or delete a group). An existing group is returned as
        it is.

        Example: epo.groups.create('My Organization\\Servers\\Paris').

        :param: path: The group path (from My Organization or not).
        :return: The Group.
        :raise: ValueError: Lost and Found or one of its subgroups.
        :raise: EPOError: The group is not there after the import.
        """
        path = normalize_path(path)
        check_destination(path)
        groups = {item.path.lower(): item for item in self.list()}
        if path.lower() in groups:
            return groups[path.lower()]
        parts = path.split('\\')
        # The deepest existing group, under which the file creates the others.
        level = max(index for index in range(1, len(parts))
                    if '\\'.join(parts[:index]).lower() in groups)
        parent = groups['\\'.join(parts[:level]).lower()]
        content = import_file([parts[level:] + ['']]).encode('utf-8')
        answer = self.epo.call('system.importSystem', branchNodeID=parent.id,
                               files={'uploadFile': ('groups.txt', content)})
        if not _done(answer):
            raise EPOError('system.importSystem', 'Unexpected answer: {!r}'.format(answer)[:500])
        created = self.get(path)
        if created is None:
            raise EPOError('system.importSystem', '{} was not created.'.format(path))
        return created
