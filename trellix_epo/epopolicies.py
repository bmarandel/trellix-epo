# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOPolicies, the Policy Catalog operations of EPOClient
(epo.policies): find, export and import the policies, assign them to System
Tree groups and systems, reset the inheritance, and read the assignments and
the policies applied to a system (policy.* commands, EPOBrokenInherintanceView
and EPOAssignedPolicy tables).

    epo.policies.find('Ransomware')                          # [PolicyRef...]
    policy = epo.policies.get('Demo (Ransomware)', 'On-Access Scan')
    epo.policies.assign(policy, group='My Organization\\Workstations')
    epo.policies.assign(policy, systems=['PC01', 'PC02'])
    epo.policies.reset('On-Access Scan', 'ENDP_AM_1000', group='Workstations')
    epo.policies.assignments(group='Workstations')           # [Assignment...]
    epo.policies.applied('PC01')                             # [AppliedPolicy...]

The assignments work as the Assigned Policies page of a group or a system
(Systems > System Tree > Assigned Policies > Edit Assignment): assigning a
policy breaks the inheritance of its category, reset() inherits it again.
The Web API has no command to lock the inheritance, to remove one policy of
a multi-slot category or to read the policies of My Organization (not in
EPOBrokenInherintanceView): use the console.

Server behaviours handled here (checked on ePO 5.10 Update 7 with the
"Claude - Template" policies, a test group and a dummy system):
- policy.assignToGroup and policy.assignToSystem replace the policy of a
  single-slot category, and add one to a multi-slot category (Exploit
  Prevention, Solidcore rules...);
- resetInheritance resets the whole category (every policy of a
  multi-slot one): the objectId only tells the category;
- resetting a category the node inherits fails with "Invalid product ID":
  reset() checks the assignments first;
- policy.assignToSystem takes the typeId number of policy.find, and refuses
  a wrong one ("Policy Object typeID must match with Policy typeID on
  policy assignment"); it answers {name, id, message, status} per system,
  status -1 for an unknown system in an "OK" answer: raised as EPOError;
- unknown policy, product or group: "Invalid policy object ID", "Invalid
  product ID", "Invalid group ID";
- EPOAssignedPolicy has no row for a system that never connected.
"""

from .epo import EPOError
from .policies import Policies
from .policycatalog import (AppliedPolicy, Assignment, PolicyRef, label_key)
from .eposystemtree import _done, _statuses

# Columns of the tables read for the assignments and the applied policies.
ASSIGNMENT_COLUMNS = ('nodetype2', 'nodetextpath', 'policyobjectid', 'editflags',
                      'ForceInheritance', 'PolicyDesc', 'FeatureTextID')
APPLIED_COLUMNS = ('NodeName', 'UserName', 'PolicyObjectID', 'upToDate', 'PolicyDesc',
                   'FeatureTextID', 'ServerID', 'EditFlags', 'Origin')


def _select(table, columns):
    """
    Returns the select clause of a SQUID query on columns of a table.

    >>> _select('EPOAssignedPolicy', ('NodeName', 'Origin'))
    '(select EPOAssignedPolicy.NodeName EPOAssignedPolicy.Origin)'
    """
    return '(select {})'.format(' '.join('{}.{}'.format(table, column) for column in columns))


def _matches(policy, product_id=None, category=None):
    """
    True when a policy is of the product (productId or featureId) and of the
    category (label, or typeid of the export), when they are given.

    >>> policy = PolicyRef(1, 'A', 'SOLIDCORE_META', 'SCOR_AWL', 70,
    ...                    'Application Control Rules (Windows)')
    >>> _matches(policy, 'SCOR_AWL', 'AWL Rules (Windows)'), _matches(policy, 'ENDP_AM_1000')
    (True, False)
    """
    if product_id and product_id not in (policy.product_id, policy.feature_id):
        return False
    if category and label_key(category) not in (label_key(policy.category),
                                                label_key(policy.type_id or '')):
        return False
    return True


class EPOPolicies():
    """
    The Policy Catalog operations of an EPOClient (epo.policies).
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
        return '<EPOPolicies of {!r}>'.format(self.epo)

    # ------------------------------ Policy Catalog ------------------------------
    def find(self, search_text='', product_id=None, category=None):
        """
        Returns the policies whose name, product, category or feature
        contains the text (policy.find, no wildcard), as PolicyRef.

        Example: epo.policies.find(product_id='ENDP_AM_1000', category='Exploit Prevention').

        :param: product_id: Keep the policies of a product id (productId or
                            featureId, e.g. SOLIDCORE_META or SCOR_AWL).
        :param: category: Keep a category (label as On-Access Scan, or typeid
                          of the export as EAM_General_Policies).
        """
        return [policy for policy in (PolicyRef.from_json(item) for item in
                                      self.epo.call('policy.find', searchText=search_text))
                if _matches(policy, product_id, category)]

    def get(self, name, category=None, product_id=None):
        """
        Returns a policy by name (case sensitive, as the console), or None;
        the category and the product tell apart the policies of the same
        name ("My Default" exists in every category).

        Example: epo.policies.get('My Default', 'On-Access Scan').

        :raise: EPOError: Several policies have the name: give the category
                          (and the product).
        """
        found = [policy for policy in self.find(name, product_id, category) if policy.name == name]
        if len(found) > 1:
            raise EPOError('policy.find', 'Several policies are named {}: give the category and '
                           'the product ({}).'.format(name, ', '.join(
                               '{} / {}'.format(policy.product_id, policy.category)
                               for policy in found[:5])))
        return found[0] if found else None

    def require(self, policy, category=None, product_id=None):
        """
        Returns a PolicyRef given as a PolicyRef, an id or a name (with its
        category and product), or raises ValueError.

        Example: epo.policies.require('My Default', 'On-Access Scan').
        """
        if isinstance(policy, PolicyRef):
            return policy
        if isinstance(policy, int):
            found = next((item for item in self.find() if item.id == policy), None)
        else:
            found = self.get(policy, category, product_id)
        if found is None:
            raise ValueError('Unknown policy: {}{}.'.format(policy, ' ({})'.format(category)
                                                             if category else ''))
        return found

    def export(self, product_id):
        """
        Returns all the policies of a product (policy.export), as the policy
        class of the product (EPOClient.PRODUCTS, e.g. ESTPPolicies for
        'ENDP_AM_1000'), or as Policies for a product the library doesn't
        support.

        Example: policies = epo.policies.export('ENDP_AM_1000').

        :raise: EPOError: Unknown product, e.g. "Invalid ProductID 'NOPE'".
        """
        text = self.epo._text('policy.export', productId=product_id)
        return self.epo.PRODUCTS.get(product_id, Policies)(text.strip().encode('utf-8'))

    def import_policies(self, policies, force=False, file_name='policies.xml'):
        """
        Imports policies into ePO (policy.importPolicy) and returns the server
        message, e.g. "Number of imported policies: 1 Number of matching
        policies that were not overwritten: 1" (the second count is wrong:
        the server gives it for a new policy too, checked on the lab).

        Example: epo.policies.import_policies(policies, force=True).

        :param: policies: A Policies object (or any object with
                          get_xml_content(), which writes the non-ASCII
                          characters as XML references: the Web API import
                          reads the file as ISO-8859-1), or the XML as bytes.
        :param: force: Replace the existing policies with the same name;
                       without it they are kept.
        :param: file_name: The file name sent with the upload.
        """
        content = policies if isinstance(policies, bytes) else policies.get_xml_content()
        return self.epo._text('policy.importPolicy', force=force,
                              files={'file': (file_name, content)}, output='terse').strip()

    # ------------------------------ Assignments ------------------------------
    def assignments(self, group=None, system=None):
        """
        Returns the policies assigned to groups and systems that don't
        inherit them (EPOBrokenInherintanceView), with their PolicyRef; all
        of them when no group or system is given. My Organization is not
        listed (the server doesn't give its policies).

        Example: epo.policies.assignments(group='Workstations').

        :param: group: Keep the assignments of a group (path, id or Group).
        :param: system: Keep the assignments of a system (name).
        """
        rows = self.epo.query('EPOBrokenInherintanceView',
                              _select('EPOBrokenInherintanceView', ASSIGNMENT_COLUMNS))
        policies = {policy.id: policy for policy in self.find()}
        found = [Assignment.from_json(row, policies) for row in rows]
        if group is not None:
            path = self.epo.groups.require(group).path.lower()
            found = [item for item in found if item.system is None and item.path.lower() == path]
        if system is not None:
            found = [item for item in found if (item.system or '').lower() == system.lower()]
        return found

    def applied(self, systems=None):
        """
        Returns the policies applied to systems (EPOAssignedPolicy: the
        Applied Policies of the systems), with their PolicyRef, in one
        query; nothing for a system that never connected.

        Example: epo.policies.applied('PC01'), epo.policies.applied() for
        every system.

        :param: systems: A system name, a list of names, or None for all.
        """
        names = [systems] if isinstance(systems, str) else list(systems or [])
        conditions = ['(eq EPOAssignedPolicy.NodeName "{}")'.format(name.replace('"', ''))
                      for name in names]
        where = (None if not conditions else conditions[0] if len(conditions) == 1 else
                 '(or {})'.format(' '.join(conditions)))
        rows = self.epo.query('EPOAssignedPolicy', _select('EPOAssignedPolicy', APPLIED_COLUMNS),
                              where)
        policies = {policy.id: policy for policy in self.find()}
        return [AppliedPolicy.from_json(row, policies) for row in rows]

    def assign(self, policy, group=None, systems=None, category=None, product_id=None):
        """
        Assigns a policy to a group or to systems (policy.assignToGroup,
        policy.assignToSystem): the policy replaces the one of its category
        (single-slot) or is added to them (multi-slot), and the inheritance
        of the category is broken for the group or the systems.

        Example: epo.policies.assign('Demo (Ransomware)', group='Workstations',
        category='On-Access Scan').

        :param: policy: The PolicyRef, its id, or its name with category
                        and product_id.
        :param: group: The group (path, id or Group).
        :param: systems: The systems (names, ids or System, or one of them).
        :return: The assignments of the group for the category, or the names
                 of the systems.
        :raise: ValueError: Unknown policy, group or system; both or none of
                            group and systems.
        :raise: EPOError: The policy is not assigned after the call.
        """
        if (group is None) == (systems is None):
            raise ValueError('Give a group or systems.')
        policy = self.require(policy, category, product_id)
        if group is not None:
            target = self.epo.groups.require(group)
            answer = self.epo.call('policy.assignToGroup', groupId=target.id,
                                   productId=policy.product_id, objectId=policy.id)
            if not _done(answer):
                raise EPOError('policy.assignToGroup',
                               'Unexpected answer: {!r}'.format(answer)[:500])
            found = [item for item in self.assignments(group=target)
                     if item.policy and item.policy.slot == policy.slot]
            if policy.id not in {item.policy_id for item in found}:
                raise EPOError('policy.assignToGroup', '{} is not assigned to {} after the '
                               'call.'.format(policy.name, target.path))
            return found
        ids = self.epo.systems._ids(systems)
        return _statuses('policy.assignToSystem', self.epo.call(
            'policy.assignToSystem', ids=self.epo.systems._ids_parameter(ids),
            productId=policy.product_id, typeId=policy.type_number, objectId=policy.id), ids)

    def reset(self, category, product_id=None, group=None, systems=None):
        """
        Inherits a category again (policy.assign* with resetInheritance,
        "Inherit from" of the Assigned Policies page): every policy of the
        category assigned to the group or systems is removed.

        Example: epo.policies.reset('Exploit Prevention', 'ENDP_AM_1000', group='Workstations').

        :param: category: The category (label or typeid of the export), or a
                          policy of the category (PolicyRef or id).
        :param: product_id: The product id (productId or featureId) of the
                            category, when category is a label.
        :param: group: The group (path, id or Group).
        :param: systems: The systems (names; ids or System also).
        :return: The names of the group or systems reset.
        :raise: ValueError: Unknown category, group or system; the node
                            inherits the category already.
        """
        if (group is None) == (systems is None):
            raise ValueError('Give a group or systems.')
        if isinstance(category, (PolicyRef, int)):
            policy = self.require(category)
        else:
            found = self.find(product_id=product_id, category=category)
            if not found:
                raise ValueError('Unknown policy category: {}{}.'.format(
                    category, ' ({})'.format(product_id) if product_id else ''))
            if len({item.slot for item in found}) > 1:
                raise ValueError('Several products have the category {}: give the product '
                                 'id.'.format(category))
            policy = found[0]
        assigned = [item for item in self.assignments()
                    if item.policy and item.policy.slot == policy.slot]
        if group is not None:
            target = self.epo.groups.require(group)
            if not any(item.system is None and item.path == target.path for item in assigned):
                # The server answers "Invalid product ID".
                raise ValueError('{} inherits {} / {} already.'.format(
                    target.path, policy.product_name or policy.product_id, policy.category))
            answer = self.epo.call('policy.assignToGroup', groupId=target.id,
                                   productId=policy.product_id, objectId=policy.id,
                                   resetInheritance=True)
            if not _done(answer):
                raise EPOError('policy.assignToGroup',
                               'Unexpected answer: {!r}'.format(answer)[:500])
            return [target.path]
        ids = self.epo.systems._ids(systems)
        # The names of the systems given by id (the view lists the names).
        ids = {number: name or self.epo.systems.get(number).name for number, name in ids.items()}
        with_assignment = {(item.system or '').lower() for item in assigned}
        inheriting = [name for name in ids.values() if name.lower() not in with_assignment]
        if inheriting:
            raise ValueError('{} {} {} / {} already.'.format(
                ', '.join(inheriting), 'inherits' if len(inheriting) == 1 else 'inherit',
                policy.product_name or policy.product_id, policy.category))
        return _statuses('policy.assignToSystem', self.epo.call(
            'policy.assignToSystem', ids=self.epo.systems._ids_parameter(ids),
            productId=policy.product_id, typeId=policy.type_number, objectId=policy.id,
            resetInheritance=True), ids)
