# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the Policy Catalog of ePO as objects, without a server:
the policy categories (CATEGORIES, MULTI_SLOT), the policies as policy.find
lists them (PolicyRef), the policies assigned to a group or a system
(Assignment, the EPOBrokenInherintanceView table: the nodes that don't
inherit a category) and the policies applied to a system (AppliedPolicy,
the EPOAssignedPolicy table).

>>> policy = PolicyRef.from_json({'objectId': 201, 'objectName': 'Demo (Ransomware)',
...     'productId': 'ENDP_AM_1000', 'featureId': 'ENDP_AM_1000', 'typeId': 25,
...     'typeName': 'On-Access Scan', 'productName': 'Endpoint Security Threat Prevention ',
...     'featureName': ' Policy Category', 'objectNotes': ''})
>>> policy
<PolicyRef 201 Endpoint Security Threat Prevention / On-Access Scan: Demo (Ransomware)>
>>> policy.type_id, policy.multi_slot
('EAM_General_Policies', False)

This module is the reference of the policy categories: the Policy
Assignment Rules (assignmentrules) import them. The operations on a server
(epo.policies: find, export, import, assign, reset, assignments, applied)
are in the epopolicies module.
"""

import re

from .policies import Policy
from .systemtree import normalize_path

# Policy categories of the products the library supports: (featureid,
# typeid) of the policy export -> (product, category) as the rule wizard
# shows them. policy.find gives the featureid (featureId) and the category
# label (typeName), with a typeId number of the server instead of the typeid.
CATEGORIES = {
    ('EPOAGENTMETA', 'General'): ('Trellix Agent', 'General'),
    ('EPOAGENTMETA', 'Repository'): ('Trellix Agent', 'Repository'),
    ('EPOAGENTMETA', 'Troubleshooting'): ('Trellix Agent', 'Troubleshooting'),
    ('EPOAGENTMETA', 'CustomProps'): ('Trellix Agent', 'Custom Properties'),
    ('EPOAGENTMETA', 'Telemetry'): ('Trellix Agent', 'Product Improvement Program'),
    ('ENDP_AM_1000', 'EAM_General_Policies'): ('Endpoint Security Threat Prevention',
                                               'On-Access Scan'),
    ('ENDP_AM_1000', 'EAM_OnDemandScan_Policies'): ('Endpoint Security Threat Prevention',
                                                    'On-Demand Scan'),
    ('ENDP_AM_1000', 'EAM_CommonScan_Policies'): ('Endpoint Security Threat Prevention', 'Options'),
    ('ENDP_AM_1000', 'EAM_BehaviorBlock_Policies'): ('Endpoint Security Threat Prevention',
                                                     'Access Protection'),
    ('ENDP_AM_1000', 'EAM_BufferOverflow_Policies'): ('Endpoint Security Threat Prevention',
                                                      'Exploit Prevention'),
    ('ENDP_FW_META_FW', 'FW_StatusMode'): ('Endpoint Security Firewall', 'Options'),
    ('ENDP_FW_META_FW', 'FireCore_FW_Rules'): ('Endpoint Security Firewall', 'Rules'),
    ('ENDP_GS_1000', 'EGS_Product_Configuration_Policies'): ('Endpoint Security Common',
                                                             'Options'),
    ('TIEClientMETA', 'General'): ('Endpoint Security Adaptive Threat Protection', 'Options'),
    ('TIEClientMETA', 'TIE_DynamicApplicationContainment_Policies'): (
        'Endpoint Security Adaptive Threat Protection', 'Dynamic Application Containment'),
    ('ENDP_WP_1000', 'EWC_General'): ('Endpoint Security Web Control', 'Options'),
    ('ENDP_WP_1000', 'EWC_EnforcementMessaging'): ('Endpoint Security Web Control',
                                                   'Enforcement Messaging'),
    ('ENDP_WP_1000', 'EWC_BlockAndAllowList'): ('Endpoint Security Web Control',
                                                'Block and Allow List'),
    ('ENDP_WP_1000', 'EWC_ContentFiltering'): ('Endpoint Security Web Control', 'Content Actions'),
    ('ENDP_WP_1000', 'EWC_BrowserControl'): ('Endpoint Security Web Control', 'Browser Control'),
    ('VSESTOMD1300', 'VSES1000_Icap_Policies'): ('Endpoint Security Storage Protection',
                                                 'ICAP Policies'),
    ('VSESTOMD1300', 'VSES1000_Netapp_Policies'): ('Endpoint Security Storage Protection',
                                                   'NetApp Policies'),
    ('SCOR_AWL', 'AWL Rules (Windows)'): ('Solidcore:Application Control',
                                          'Application Control Rules (Windows)'),
    ('SCOR_AWL', 'AWL Rules (Unix)'): ('Solidcore:Application Control',
                                       'Application Control Rules (Unix)'),
    ('SCOR_AWL', 'AWL Options (Windows)'): ('Solidcore:Application Control',
                                            'Application Control Options (Windows)'),
    ('SCOR_AWL', 'AWL Options (Unix)'): ('Solidcore:Application Control',
                                         'Application Control Options (Unix)'),
    ('SCOR_CC', 'CC Rules (Windows)'): ('Solidcore:Change Control',
                                        'Change Control Rules (Windows)'),
    ('SCOR_CC', 'CC Rules (Unix)'): ('Solidcore:Change Control', 'Change Control Rules (Unix)'),
    ('SCOR_FIM', 'Mon Rules (Windows)'): ('Solidcore:Integrity Monitor',
                                          'Integrity Monitoring Rules (Windows)'),
    ('SCOR_FIM', 'Mon Rules (Unix)'): ('Solidcore:Integrity Monitor',
                                       'Integrity Monitoring Rules (Unix)'),
    ('SCOR_GEN', 'Lockdown Rules'): ('Solidcore:General', 'Configuration (Client)'),
    ('SCOR_GEN', 'Attr Rules (Windows)'): ('Solidcore:General', 'Exception Rules (Windows)'),
    ('SCOR_GEN', 'Attr Rules (Unix)'): ('Solidcore:General', 'Exception Rules (Unix)'),
    ('SIR_____1000_COLLECT_DATA', 'General'): ('System Information Reporter:Collect Data',
                                               'General'),
    ('SIR_____1000_SET_REGISTRY', 'General'): ('System Information Reporter:Set Registry',
                                               'Registry General'),
    ('XCLIENT_META', 'General'): ('Trellix EDR with Forensics', 'General'),
    ('XCLIENT_META', 'Streaming'): ('Trellix EDR with Forensics', 'Streaming'),
    ('XCLIENT_META', 'Detection'): ('Trellix EDR with Forensics', 'Detection'),
    ('XCLIENT_META', 'Investigation'): ('Trellix EDR with Forensics', 'Investigation'),
    ('XCLIENT_META', 'Remediation'): ('Trellix EDR with Forensics', 'Remediation'),
}

# Policy categories (featureid, typeid) marked "(Multi-slot)" in the rule
# wizard: a rule can assign several policies of these categories. The other
# categories take one policy per rule.
MULTI_SLOT = frozenset([
    ('ENDP_AM_1000', 'EAM_BufferOverflow_Policies'),
    ('ENDP_WP_1000', 'EWC_BlockAndAllowList'),
    ('ENDP_WP_1000', 'EWC_ContentFiltering'),
    ('SCOR_AWL', 'AWL Rules (Windows)'),
    ('SCOR_AWL', 'AWL Rules (Unix)'),
    ('SCOR_CC', 'CC Rules (Windows)'),
    ('SCOR_CC', 'CC Rules (Unix)'),
    ('SCOR_FIM', 'Mon Rules (Windows)'),
    ('SCOR_FIM', 'Mon Rules (Unix)'),
    ('SCOR_GEN', 'Lockdown Rules'),
    ('SCOR_GEN', 'Attr Rules (Windows)'),
    ('SCOR_GEN', 'Attr Rules (Unix)'),
])

# Node types of EPOBrokenInherintanceView (nodetype2): a system or a group.
SYSTEM_NODE = 1
GROUP_NODE = 3

# Names of the policies the server creates (read-only, EditFlags 1).
DEFAULT_POLICY = 'Trellix Default'


def label_key(label):
    """
    Returns a console label to compare: lower case, without the product
    versions and the blanks around ":".

    >>> label_key('System Information Reporter :Collect Data')
    'system information reporter:collect data'
    >>> label_key('Solidcore 8.4.5:General')
    'solidcore:general'
    """
    label = re.sub(r'\s+\d+(\.\d+)+', '', label.strip().lower())
    return re.sub(r'\s*:\s*', ':', label)


def type_id_of(feature_id, category):
    """
    Returns the typeid of the policy export of a category given as
    policy.find gives it (featureId and typeName), or None for a category
    the library doesn't know.

    >>> type_id_of('SCOR_GEN', 'Configuration (Client)')
    'Lockdown Rules'
    >>> type_id_of('DXLCLNT_META', 'General') is None
    True
    """
    for (feature, type_id), labels in CATEGORIES.items():
        if feature == feature_id and label_key(labels[1]) == label_key(category):
            return type_id
    return None


class PolicyRef():
    """
    A policy of the Policy Catalog as policy.find lists it: id, name,
    product, feature and category, without its settings (see
    epo.policies.export() for those).

    >>> PolicyRef(43, 'My Default', 'ENDP_GS_1000', 'ENDP_GS_1000', 20, 'Options')
    <PolicyRef 43 ENDP_GS_1000 / Options: My Default>
    """

    def __init__(self, id, name, product_id, feature_id, type_number, category, product_name='',
                 feature_name='', notes=''):
        """
        :param: id: The policy id (objectId).
        :param: name: The policy name (objectName).
        :param: product_id: The product id of the Policy Catalog
                            (productId, e.g. SOLIDCORE_META, ENDP_FW_META).
        :param: feature_id: The feature (featureId, the featureid of the
                            export, e.g. SCOR_AWL, ENDP_FW_META_FW).
        :param: type_number: The category number of the server (typeId,
                             e.g. 25), which policy.assignToSystem takes.
        :param: category: The category label (typeName, e.g. On-Access Scan).
        :param: product_name: The product label (productName).
        :param: feature_name: The feature label (featureName).
        :param: notes: The policy notes (objectNotes).
        """
        self.id = id
        self.name = name
        self.product_id = product_id
        self.feature_id = feature_id
        self.type_number = type_number
        self.category = category
        self.product_name = product_name
        self.feature_name = feature_name
        self.notes = notes

    @classmethod
    def from_json(cls, data):
        """
        Returns the policy of a line of policy.find (the labels of the
        server have blanks around them: removed).
        """
        return cls(data['objectId'], data['objectName'], data['productId'], data['featureId'],
                   data['typeId'], (data.get('typeName') or '').strip(),
                   (data.get('productName') or '').strip(),
                   (data.get('featureName') or '').strip(), data.get('objectNotes') or '')

    def __repr__(self):
        """
        Shows the id, the product, the category and the name.
        """
        return '<PolicyRef {} {} / {}: {}>'.format(self.id, self.product_name or self.product_id,
                                                  self.category, self.name)

    def __eq__(self, other):
        """
        Two policies are equal when their ids are.
        """
        return isinstance(other, PolicyRef) and self.id == other.id

    def __hash__(self):
        """
        The hash of the id.
        """
        return hash(self.id)

    @property
    def type_id(self):
        """
        The typeid of the policy export (e.g. EAM_General_Policies), None for
        a category the library doesn't know.

        >>> PolicyRef(1, 'A', 'SOLIDCORE_META', 'SCOR_AWL', 70,
        ...           'Application Control Rules (Windows)').type_id
        'AWL Rules (Windows)'
        """
        return type_id_of(self.feature_id, self.category)

    @property
    def slot(self):
        """
        What the policy is assigned for: (feature, category label). A
        single-slot category has one policy per group or system, a
        multi-slot one several.

        >>> PolicyRef(1, 'A', 'ENDP_AM_1000', 'ENDP_AM_1000', 29, 'Exploit Prevention').slot
        ('ENDP_AM_1000', 'exploit prevention')
        """
        return self.feature_id, label_key(self.category)

    @property
    def multi_slot(self):
        """
        True when a group or a system can have several policies of this
        category (they add up; another assignment adds one, checked on ePO
        5.10 Update 7 with Exploit Prevention).

        >>> PolicyRef(1, 'A', 'ENDP_AM_1000', 'ENDP_AM_1000', 29, 'Exploit Prevention').multi_slot
        True
        """
        return (self.feature_id, self.type_id) in MULTI_SLOT

    @property
    def read_only(self):
        """
        True for the policies the server creates and the console can't
        change (Trellix Default).

        >>> PolicyRef(57, 'Trellix Default', 'ENDP_AM_1000', 'ENDP_AM_1000', 28,
        ...           'Access Protection').read_only
        True
        """
        return self.name == DEFAULT_POLICY

    def md_row(self):
        """
        Returns the columns of the policy table: product, category, name,
        id, notes.

        >>> PolicyRef(43, 'My Default', 'ENDP_GS_1000', 'ENDP_GS_1000', 20, 'Options',
        ...           'Endpoint Security Common').md_row()
        ['Endpoint Security Common', 'Options', 'My Default', '43', '']
        """
        return [Policy.md_escape(value) for value in (
            self.product_name or self.product_id, self.category, self.name, str(self.id),
            self.notes)]


def policies_to_markdown(policies, title='Policy Catalog'):
    """
    Returns the policies as a Markdown table sorted by product, category
    and name, as the Policy Catalog.

    >>> print(policies_to_markdown([PolicyRef(43, 'My Default', 'ENDP_GS_1000',
    ...     'ENDP_GS_1000', 20, 'Options', 'Endpoint Security Common')]))
    # Policy Catalog
    <BLANKLINE>
    | Product | Category | Policy | ID | Notes |
    |---|---|---|---|---|
    | Endpoint Security Common | Options | My Default | 43 |  |
    """
    lines = ['# ' + Policy.md_heading(title), '', '| Product | Category | Policy | ID | Notes |',
             '|---|---|---|---|---|']
    for policy in sorted(policies, key=lambda item: (
            (item.product_name or item.product_id).lower(), item.category.lower(),
            item.name.lower())):
        lines.append('| ' + ' | '.join(policy.md_row()) + ' |')
    return '\n'.join(lines)


class Assignment():
    """
    A policy assigned to a group or a system, which doesn't inherit it from
    its parent: a row of the EPOBrokenInherintanceView table ("Break
    inheritance" of the Assigned Policies page). A multi-slot category may
    have several rows for a node.

    >>> Assignment.from_json({'EPOBrokenInherintanceView.nodetype2': 1,
    ...     'EPOBrokenInherintanceView.nodetextpath': '\\\\Workstations\\\\PC01',
    ...     'EPOBrokenInherintanceView.policyobjectid': 38,
    ...     'EPOBrokenInherintanceView.FeatureTextID': 'EPOAGENTMETA',
    ...     'EPOBrokenInherintanceView.ForceInheritance': 0})
    <Assignment PC01 (My Organization\\Workstations): policy 38>
    """

    def __init__(self, path, policy_id, feature_id, system=None, locked=False, policy=None):
        """
        :param: path: The group path (from My Organization), or the group of
                      the system.
        :param: policy_id: The policy id.
        :param: feature_id: The feature (FeatureTextID).
        :param: system: The system name for a system assignment, None for a
                        group.
        :param: locked: The inheritance is locked for the subgroups and
                        systems (ForceInheritance, set in the console only).
        :param: policy: The PolicyRef (epo.policies.assignments() sets it).
        """
        self.path = normalize_path(path)
        self.policy_id = policy_id
        self.feature_id = feature_id
        self.system = system
        self.locked = locked
        self.policy = policy

    @classmethod
    def from_json(cls, data, policies=None):
        """
        Returns the assignment of a row of EPOBrokenInherintanceView.

        :param: policies: {id: PolicyRef} to set the policy.
        """
        prefix = 'EPOBrokenInherintanceView.'
        path = data[prefix + 'nodetextpath']
        system = None
        if data.get(prefix + 'nodetype2') == SYSTEM_NODE:
            path, _, system = path.rstrip('\\').rpartition('\\')
        policy_id = data[prefix + 'policyobjectid']
        return cls(path, policy_id, data.get(prefix + 'FeatureTextID'), system,
                   bool(data.get(prefix + 'ForceInheritance')), (policies or {}).get(policy_id))

    def __repr__(self):
        """
        Shows the node and the policy.
        """
        node = '{} ({})'.format(self.system, self.path) if self.system else self.path
        policy = self.policy.name if self.policy else 'policy {}'.format(self.policy_id)
        return '<Assignment {}: {}>'.format(node, policy)

    def md_row(self):
        """
        Returns the columns of the assignment table: group, system, product,
        category, policy, locked.
        """
        policy = self.policy
        return [Policy.md_escape(value) for value in (
            self.path, self.system or '', policy.product_name if policy else self.feature_id,
            policy.category if policy else '', policy.name if policy else str(self.policy_id),
            'Yes' if self.locked else '')]


def assignments_to_markdown(assignments, title='Policy Assignments'):
    """
    Returns the assignments as a Markdown table, by group, system, product
    and category.

    >>> print(assignments_to_markdown([Assignment('Workstations', 43, 'ENDP_GS_1000',
    ...     policy=PolicyRef(43, 'My Default', 'ENDP_GS_1000', 'ENDP_GS_1000', 20, 'Options',
    ...                      'Endpoint Security Common'))]))
    # Policy Assignments
    <BLANKLINE>
    | Group | System | Product | Category | Policy | Locked |
    |---|---|---|---|---|---|
    | My Organization\\\\Workstations |  | Endpoint Security Common | Options | My Default |  |
    """
    lines = ['# ' + Policy.md_heading(title), '',
             '| Group | System | Product | Category | Policy | Locked |', '|---|---|---|---|---|---|']
    for assignment in sorted(assignments, key=lambda item: [
            item.path.lower(), (item.system or '').lower()] + [
                value.lower() for value in item.md_row()[2:5]]):
        lines.append('| ' + ' | '.join(assignment.md_row()) + ' |')
    return '\n'.join(lines)


class AppliedPolicy():
    """
    A policy applied to a system (EPOAssignedPolicy table, the Applied
    Policies of the system): the result of the System Tree inheritance, of
    the system assignments and of the Policy Assignment Rules. The table
    has no row for a system that never connected.

    >>> AppliedPolicy.from_json({'EPOAssignedPolicy.NodeName': 'PC01',
    ...     'EPOAssignedPolicy.PolicyObjectID': 201, 'EPOAssignedPolicy.FeatureTextID':
    ...     'ENDP_AM_1000', 'EPOAssignedPolicy.Origin': 'tree', 'EPOAssignedPolicy.upToDate': True,
    ...     'EPOAssignedPolicy.EditFlags': 0})
    <AppliedPolicy PC01: policy 201 (tree)>
    """

    def __init__(self, system, policy_id, feature_id, origin='tree', up_to_date=True,
                 read_only=False, user=None, policy=None):
        """
        :param: system: The system name.
        :param: policy_id: The policy id.
        :param: feature_id: The feature (FeatureTextID).
        :param: origin: Where the policy comes from (Origin): tree for the
                        System Tree (inheritance or assignment).
        :param: up_to_date: The system has the last settings (upToDate).
        :param: read_only: A Trellix Default policy (EditFlags 1).
        :param: user: The user of a user based policy (UserName).
        :param: policy: The PolicyRef (epo.policies.applied() sets it).
        """
        self.system = system
        self.policy_id = policy_id
        self.feature_id = feature_id
        self.origin = origin
        self.up_to_date = up_to_date
        self.read_only = read_only
        self.user = user
        self.policy = policy

    @classmethod
    def from_json(cls, data, policies=None):
        """
        Returns the applied policy of a row of EPOAssignedPolicy.

        :param: policies: {id: PolicyRef} to set the policy.
        """
        prefix = 'EPOAssignedPolicy.'
        policy_id = data[prefix + 'PolicyObjectID']
        return cls(data[prefix + 'NodeName'], policy_id, data.get(prefix + 'FeatureTextID'),
                   data.get(prefix + 'Origin'), bool(data.get(prefix + 'upToDate')),
                   data.get(prefix + 'EditFlags') == 1,
                   (data.get(prefix + 'UserName') or '').strip() or None,
                   (policies or {}).get(policy_id))

    def __repr__(self):
        """
        Shows the system, the policy and its origin.
        """
        policy = self.policy.name if self.policy else 'policy {}'.format(self.policy_id)
        return '<AppliedPolicy {}: {} ({})>'.format(self.system, policy, self.origin)


def applied_to_markdown(applied, title='Applied Policies'):
    """
    Returns the policies applied to systems as a Markdown table, by system,
    product and category.

    >>> print(applied_to_markdown([AppliedPolicy('PC01', 201, 'ENDP_AM_1000')]))
    # Applied Policies
    <BLANKLINE>
    | System | Product | Category | Policy | Origin | Up-To-Date |
    |---|---|---|---|---|---|
    | PC01 | ENDP\\_AM\\_1000 |  | 201 | tree | Yes |
    """
    rows = []
    for item in applied:
        policy = item.policy
        rows.append([Policy.md_escape(value) for value in (
            item.system, policy.product_name if policy else item.feature_id,
            policy.category if policy else '', policy.name if policy else str(item.policy_id),
            item.origin or '', 'Yes' if item.up_to_date else 'No')])
    lines = ['# ' + Policy.md_heading(title), '',
             '| System | Product | Category | Policy | Origin | Up-To-Date |',
             '|---|---|---|---|---|---|']
    for row in sorted(rows, key=lambda values: [value.lower() for value in values[:3]]):
        lines.append('| ' + ' | '.join(row) + ' |')
    return '\n'.join(lines)
