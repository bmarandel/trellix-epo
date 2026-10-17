# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the ePO users and permission sets as objects, without a
server: User (core.listUsers), PermissionSet and Role (the XML of
core.exportPermissionSets, read and written back) and PermissionSetList
(the export file, for core.importPermissionSets).

>>> user = User.from_json({'id': 32, 'name': 'Claude - User', 'authType': 'ntlm',
...     'authDetails': 'LAB\\\\claude', 'admin': False, 'disabled': False,
...     'allowedIPs': '192.168.100.0/24'})
>>> user, user.windows_account, user.allowed_ips
(<User 32 Claude - User (Windows)>, ('LAB', 'claude'), ['192.168.100.0/24'])
>>> sets = PermissionSetList()
>>> sets.add(PermissionSet('Helpdesk', [Role('role:epo.core.view.tree'),
...                                     Role('role:epo.dir.access', systems=['\\\\'])]))
>>> print(sets.get_xml_content().decode())        # doctest: +ELLIPSIS
<list id="1">
  <permissionSet id="2">
    <name>Helpdesk</name>
    <roles>
      <role>
        <roleUri>role:epo.core.view.tree</roleUri>
      </role>
      <role>
        <roleUri>role:epo.dir.access</roleUri>
        <customRoleInfo roleFactoryId="epo.dir">
          <systems>
            <system>\\</system>
...

A role is kept as its URI ("role:<product>.<category>.<right>",
"role:epo.dir.access" with the System Tree groups it gives access to): the
console labels of the rights are not in the Web API. The operations on a
server (epo.users, epo.permission_sets) are in the epousers module.
"""

import ipaddress
import xml.etree.ElementTree as et
from xml.sax.saxutils import escape

from .policies import Policy

# Authentication types (authType of core.listUsers) -> label.
AUTH_TYPES = {'pwd': 'ePO password', 'ntlm': 'Windows', 'cert': 'Certificate',
              'mcafeemvisionsso': 'Single sign-on'}

# Short labels of the authentication types, for the representations.
_AUTH_SHORT = {'pwd': 'password', 'ntlm': 'Windows', 'cert': 'certificate',
               'mcafeemvisionsso': 'SSO'}

# Role of the System Tree access, with the groups it covers.
TREE_ACCESS = 'role:epo.dir.access'
TREE_FACTORY = 'epo.dir'

# The permission set of the administrators in EntitlementView.
ADMIN = '%%ADMIN%%'


def check_allowed_ips(items):
    """
    Checks the allowed IP addresses of a user: IPv4 or IPv6 addresses or
    CIDR subnets. The server accepts any text (checked on ePO 5.10 Update 7:
    "not-an-ip" was saved), which would refuse every login of the user.

    Valid / invalid:

    >>> check_allowed_ips(['192.168.100.0/24', '10.0.0.5', 'fe80::/64'])
    >>> check_allowed_ips(['not-an-ip'])
    Traceback (most recent call last):
    ...
    ValueError: Not an IP address or CIDR subnet: 'not-an-ip'.
    """
    for item in items:
        try:
            ipaddress.ip_network(item, strict=False)
        except ValueError:
            raise ValueError('Not an IP address or CIDR subnet: {!r}.'.format(item))


class User():
    """
    An ePO user (User Management > Users): name, authentication, rights
    (administrator or permission sets), state and contact details.

    >>> User(1, 'admin', admin=True)
    <User 1 admin (password, administrator)>
    """

    def __init__(self, id, name, full_name='', email='', phone='', disabled=False, admin=False,
                 auth_type='pwd', auth_details='', notes='', allowed_ips=(),
                 permission_sets=None):
        """
        :param: id: The user id.
        :param: name: The user name (log on name).
        :param: full_name, email, phone, notes: The details of the user.
        :param: disabled: The user can't log on.
        :param: admin: An administrator (every right; no permission set).
        :param: auth_type: pwd, ntlm (Windows), cert (certificate) or
                           mcafeemvisionsso (single sign-on), see AUTH_TYPES.
        :param: auth_details: DOMAIN\\user for Windows, the subject DN (in
                              lower case) for a certificate.
        :param: allowed_ips: The addresses or subnets the user can log on
                             from (all when empty).
        :param: permission_sets: The names of its permission sets, when read
                                 (epo.users.permission_sets()).
        """
        self.id = id
        self.name = name
        self.full_name = full_name
        self.email = email
        self.phone = phone
        self.disabled = disabled
        self.admin = admin
        self.auth_type = auth_type
        self.auth_details = auth_details
        self.notes = notes
        self.allowed_ips = list(allowed_ips)
        self.permission_sets = permission_sets

    @classmethod
    def from_json(cls, data):
        """
        Returns the user of a line of core.listUsers.
        """
        ips = [item.strip() for item in (data.get('allowedIPs') or '').split(',') if item.strip()]
        return cls(data['id'], data['name'], data.get('fullName') or '', data.get('email') or '',
                   data.get('phoneNumber') or '', bool(data.get('disabled')),
                   bool(data.get('admin')), data.get('authType') or '',
                   data.get('authDetails') or '', data.get('notes') or '', ips)

    def __repr__(self):
        """
        Shows the id, the name, the authentication and the state.
        """
        flags = [_AUTH_SHORT.get(self.auth_type, self.auth_type)] + \
            (['administrator'] if self.admin else []) + (['disabled'] if self.disabled else [])
        return '<User {} {} ({})>'.format(self.id, self.name, ', '.join(flags))

    @property
    def auth_label(self):
        """
        The authentication type label.

        >>> User(2, 'x', auth_type='cert').auth_label
        'Certificate'
        """
        return AUTH_TYPES.get(self.auth_type, self.auth_type)

    @property
    def windows_account(self):
        """
        (domain, user name) of a Windows authenticated user, else None.

        >>> User(2, 'x', auth_type='pwd').windows_account is None
        True
        """
        if self.auth_type != 'ntlm' or '\\' not in self.auth_details:
            return None
        return tuple(self.auth_details.split('\\', 1))

    @property
    def subject_dn(self):
        """
        The certificate subject DN of a certificate authenticated user (as
        the server keeps it: in lower case), else None.

        >>> User(2, 'x', auth_type='cert', auth_details='cn=claude test,o=lab').subject_dn
        'cn=claude test,o=lab'
        """
        return self.auth_details if self.auth_type == 'cert' else None

    def md_row(self):
        """
        Returns the columns of the user table: name, full name,
        authentication, administrator, disabled, permission sets, allowed
        IPs.

        >>> User(1, 'admin', admin=True).md_row()
        ['admin', '', 'ePO password', 'Yes', '', '', '']
        """
        sets = ', '.join(self.permission_sets or [])
        return [Policy.md_escape(value) for value in (
            self.name, self.full_name, self.auth_label + (' ({})'.format(self.auth_details)
                                                          if self.auth_details else ''),
            'Yes' if self.admin else '', 'Yes' if self.disabled else '', sets,
            ', '.join(self.allowed_ips))]


def users_to_markdown(users, title='Users'):
    """
    Returns the users as a Markdown table sorted by name: who is
    administrator, which permission sets the others have.

    >>> print(users_to_markdown([User(1, 'admin', admin=True)]))
    # Users
    <BLANKLINE>
    | User | Full Name | Authentication | Administrator | Disabled | Permission Sets | Allowed IPs |
    |---|---|---|---|---|---|---|
    | admin |  | ePO password | Yes |  |  |  |
    """
    lines = ['# ' + Policy.md_heading(title), '',
             '| User | Full Name | Authentication | Administrator | Disabled | Permission Sets | '
             'Allowed IPs |', '|---|---|---|---|---|---|---|']
    for user in sorted(users, key=lambda item: item.name.lower()):
        lines.append('| ' + ' | '.join(user.md_row()) + ' |')
    return '\n'.join(lines)


class Role():
    """
    A right of a permission set: its URI, and for the System Tree access
    (role:epo.dir.access) the groups it covers ("\\" for all the System
    Tree). The other details the server writes are kept as they are.

    >>> Role('role:SOLIDCORE_META.SCOR_AWL.reviewer').parts
    ('SOLIDCORE_META', 'SCOR_AWL.reviewer')
    """

    def __init__(self, uri, systems=None, info=None):
        """
        :param: uri: The role URI, e.g. role:ENDP_GS_1000.ENDP_GS_1000.reviewer.
        :param: systems: The System Tree paths of a customRoleInfo of the
                         epo.dir factory.
        :param: info: Another customRoleInfo element, kept as read.
        """
        self.uri = uri
        self.systems = systems
        self.info = info

    def __repr__(self):
        """
        Shows the URI.
        """
        return '<Role {}>'.format(self.uri)

    def __eq__(self, other):
        """
        Same URI and same groups.
        """
        return isinstance(other, Role) and (self.uri, self.systems) == (other.uri, other.systems)

    def __hash__(self):
        """
        The hash of the URI.
        """
        return hash(self.uri)

    @property
    def parts(self):
        """
        (product or module, right): the first part of the URI and the rest,
        e.g. ('core', 'query.guest'), ('issue', 'auditor?type=issue.type.untyped').

        >>> Role('role:core.query.guest').parts
        ('core', 'query.guest')
        """
        text = self.uri[len('role:'):] if self.uri.startswith('role:') else self.uri
        head, _, tail = text.partition('.')
        return head, tail

    @classmethod
    def from_element(cls, element):
        """
        Returns the role of a <role> element.
        """
        info = element.find('customRoleInfo')
        systems = None
        if info is not None and info.get('roleFactoryId') == TREE_FACTORY:
            systems = [item.text or '' for item in info.iter('system')]
            info = None
        return cls(element.findtext('roleUri') or '', systems, info)

    def to_xml(self, indent='      '):
        """
        Returns the <role> element as the server exports it.

        >>> print(Role('role:core.dash.viewer').to_xml(''))
        <role>
          <roleUri>role:core.dash.viewer</roleUri>
        </role>
        """
        lines = [indent + '<role>', indent + '  <roleUri>{}</roleUri>'.format(escape(self.uri))]
        if self.systems is not None:
            lines.append(indent + '  <customRoleInfo roleFactoryId="{}">'.format(TREE_FACTORY))
            lines.append(indent + '    <systems>')
            lines += [indent + '      <system>{}</system>'.format(escape(path))
                      for path in self.systems]
            lines.append(indent + '    </systems>')
            lines.append(indent + '  </customRoleInfo>')
        elif self.info is not None:
            text = et.tostring(self.info, encoding='unicode').rstrip()
            lines += [indent + '  ' + line for line in text.splitlines()]
        lines.append(indent + '</role>')
        return '\n'.join(lines)


class PermissionSet():
    """
    A permission set (User Management > Permission Sets): its name and its
    roles. Two permission sets with the same roles in another order are
    equal (the server changes the order).

    >>> PermissionSet('Helpdesk', [Role('role:core.query.guest')])
    <PermissionSet Helpdesk: 1 role>
    """

    def __init__(self, name, roles=()):
        """
        :param: name: The permission set name.
        :param: roles: The Role objects.
        """
        if not name or not name.strip():
            raise ValueError('A permission set name is required.')
        self.name = name
        self.roles = list(roles)

    def __repr__(self):
        """
        Shows the name and the number of roles.
        """
        return '<PermissionSet {}: {} role{}>'.format(self.name, len(self.roles),
                                                      '' if len(self.roles) == 1 else 's')

    def __eq__(self, other):
        """
        Same name and same roles, in any order.
        """
        return isinstance(other, PermissionSet) and self.name == other.name and \
            self.role_set() == other.role_set()

    def role_set(self):
        """
        Returns the roles as a set of (URI, groups) to compare permission sets.

        >>> PermissionSet('A', [Role('role:x'), Role('role:x')]).role_set()
        {('role:x', None)}
        """
        return {(role.uri, tuple(role.systems) if role.systems is not None else None)
                for role in self.roles}

    def has_role(self, uri):
        """
        True when the set has a role URI.

        >>> PermissionSet('A', [Role('role:core.query.guest')]).has_role('role:core.query.guest')
        True
        """
        return any(role.uri == uri for role in self.roles)

    def add_role(self, uri, systems=None):
        """
        Adds a role (nothing when the set has it).

        >>> PermissionSet('A').add_role('role:core.query.guest')
        <PermissionSet A: 1 role>
        """
        if not self.has_role(uri):
            self.roles.append(Role(uri, systems))
        return self

    def remove_role(self, uri):
        """
        Removes a role.

        :raise: ValueError: The set has no such role.
        """
        if not self.has_role(uri):
            raise ValueError('{} has no role {}.'.format(self.name, uri))
        self.roles = [role for role in self.roles if role.uri != uri]
        return self

    def copy(self, name):
        """
        Returns a copy of the set under another name.

        >>> PermissionSet('Global Reviewer', [Role('role:x')]).copy('Helpdesk')
        <PermissionSet Helpdesk: 1 role>
        """
        return PermissionSet(name, [Role(role.uri, list(role.systems) if role.systems is not None
                                         else None, role.info) for role in self.roles])

    def to_markdown(self):
        """
        Returns the set as Markdown: its roles by product or module (the
        URIs, the console labels are not in the Web API).

        >>> print(PermissionSet('A', [Role('role:core.query.guest'),
        ...                           Role('role:epo.dir.access', ['\\\\'])]).to_markdown())
        # A
        <BLANKLINE>
        | Product / Module | Right | System Tree |
        |---|---|---|
        | core | query.guest |  |
        | epo | dir.access | \\\\ |
        """
        lines = ['# ' + Policy.md_heading(self.name), '', '| Product / Module | Right | System Tree |',
                 '|---|---|---|']
        for role in sorted(self.roles, key=lambda item: item.uri.lower()):
            head, tail = role.parts
            lines.append('| {} | {} | {} |'.format(Policy.md_escape(head), Policy.md_escape(tail),
                                                   Policy.md_escape(', '.join(role.systems or []))))
        return '\n'.join(lines)


class PermissionSetList():
    """
    The permission sets of core.exportPermissionSets, or a file to import
    with core.importPermissionSets; written back as the server writes it
    (XStream: <list id="1">, then the ids of the sets from 2, two-space
    indent, LF ends).
    """

    def __init__(self, xml=None):
        """
        :param: xml: The export (text or bytes), None for an empty list.
        """
        self.sets = []
        if xml:
            root = et.fromstring(xml.encode('utf-8') if isinstance(xml, str) else xml)
            for element in root.findall('permissionSet'):
                roles = [Role.from_element(item) for item in element.iter('role')]
                self.sets.append(PermissionSet(element.findtext('name') or '', roles))

    def __repr__(self):
        """
        Shows the number of sets.
        """
        return '<PermissionSetList {} sets>'.format(len(self.sets))

    def __iter__(self):
        """
        The permission sets.
        """
        return iter(self.sets)

    def __len__(self):
        """
        The number of sets.
        """
        return len(self.sets)

    def names(self):
        """
        Returns the names of the sets.
        """
        return [item.name for item in self.sets]

    def get(self, name):
        """
        Returns a set by name (case sensitive), or None.
        """
        return next((item for item in self.sets if item.name == name), None)

    def add(self, permission_set):
        """
        Adds a set.

        :raise: ValueError: A set has the name.
        """
        if self.get(permission_set.name) is not None:
            raise ValueError('A permission set is named {} already.'.format(permission_set.name))
        self.sets.append(permission_set)

    def remove(self, name):
        """
        Removes a set from the list (not from the server).

        :raise: ValueError: No set has the name.
        """
        if self.get(name) is None:
            raise ValueError('No permission set named {}.'.format(name))
        self.sets = [item for item in self.sets if item.name != name]

    def get_xml_content(self):
        """
        Returns the XML of the list as the server exports it (bytes, UTF-8).
        """
        lines = ['<list id="1">']
        for number, item in enumerate(self.sets, 2):
            lines.append('  <permissionSet id="{}">'.format(number))
            lines.append('    <name>{}</name>'.format(escape(item.name)))
            lines.append('    <roles>')
            lines += [role.to_xml() for role in item.roles]
            lines.append('    </roles>')
            lines.append('  </permissionSet>')
        lines.append('</list>')
        return '\n'.join(lines).encode('utf-8')

    def save_to_file(self, file_path):
        """
        Writes the file to import (core.importPermissionSets or the console).
        """
        with open(file_path, 'wb') as output:
            output.write(self.get_xml_content())

    @classmethod
    def load_from_file(cls, file_path):
        """
        Reads an export file.
        """
        with open(file_path, 'rb') as source:
            return cls(source.read())

    def to_markdown(self, title='Permission Sets'):
        """
        Returns the sets as Markdown: a summary table, then the roles of each
        set.

        >>> sets = PermissionSetList()
        >>> sets.add(PermissionSet('A', [Role('role:core.query.guest')]))
        >>> print(sets.to_markdown().splitlines()[2:5])
        ['| Permission Set | Roles |', '|---|---|', '| A | 1 |']
        """
        lines = ['# ' + Policy.md_heading(title), '', '| Permission Set | Roles |', '|---|---|']
        for item in sorted(self.sets, key=lambda value: value.name.lower()):
            lines.append('| {} | {} |'.format(Policy.md_escape(item.name), len(item.roles)))
        for item in sorted(self.sets, key=lambda value: value.name.lower()):
            lines += ['', item.to_markdown().replace('# ', '## ', 1)]
        return '\n'.join(lines)
