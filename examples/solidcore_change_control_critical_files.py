#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
solidcore_change_control_critical_files.py

Example for the trellix_epo package, working directly against an ePO
server with the ePO Web API client of the library (EPOClient).

It creates (or updates) a Solidcore Change Control Rules (Windows) policy which
protects some of the files of the "Windows Critical Config Files" Rule Group
(created by solidcore_fim_windows_critical_files.py), read from ePO:
  - Write-Protect File: the name resolution files (hosts, lmhosts.sam,
    networks, protocol, services): no program can modify them, only updaters;
  - Write-Protect Registry: the machine Run and RunOnce keys, the most common
    autostart locations (T1547.001).
Integrity Monitor only reports changes; Change Control blocks them.

Note: the Read-Protect feature of Change Control is not used here on purpose:
it is disabled by default because of its significant impact on the system
performance.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 solidcore_change_control_critical_files.py [--dry-run]
"""

import sys

from trellix_epo import SCCCPolicyRules, SCRuleGroups
from epo_connection import connect, parser

TYPE_ID = 'CC Rules (Windows)'
CRITICAL_RULE_GROUP = 'Windows Critical Config Files'

# Files of the Rule Group to protect, by the end of their path.
WRITE_PROTECT = ('\\etc\\hosts', '\\etc\\lmhosts.sam', '\\etc\\networks', '\\etc\\protocol',
                 '\\etc\\services')
REGISTRY_WRITE_PROTECT = [
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
]


def main():
    args_parser = parser('Create a Change Control policy protecting Windows critical files.')
    args_parser.add_argument('--policy', default='CC Windows Critical Files Sample',
                             help='policy name (default: %(default)s)')
    args = args_parser.parse_args()
    epo = connect(args)

    critical_group = epo.export_rule_group(SCRuleGroups.WINDOWS, SCRuleGroups.INTEGRITY_MONITOR,
                                           CRITICAL_RULE_GROUP)
    if critical_group is None:
        sys.exit('Rule Group "{}" not found in ePO: run '
                 'solidcore_fim_windows_critical_files.py first.'.format(CRITICAL_RULE_GROUP))
    paths = [f['pattern'] for f in critical_group.get_file_list()]

    policies = epo.export_policies('SOLIDCORE_META')
    policy_xml = policies.get_policy(TYPE_ID, args.policy)
    if policy_xml is None:
        policy_xml = policies.new_empty_policy(TYPE_ID, args.policy)
        if policy_xml is None:
            sys.exit('No "{}" policy in ePO to use as a template: duplicate "Blank Template" '
                     'in the Policy Catalog first.'.format(TYPE_ID))
        print('Policy "{}" created from a blank policy.'.format(args.policy))
    else:
        print('Policy "{}" found in ePO.'.format(args.policy))
    policy = SCCCPolicyRules(policy_xml)

    for path in paths:
        if path.lower().endswith(WRITE_PROTECT) and policy.add_write_protect_file(path):
            print('  Write-Protect File: {}'.format(path))
    for key in REGISTRY_WRITE_PROTECT:
        if policy.add_write_protect_registry(key):
            print('  Write-Protect Registry: {}'.format(key))

    policy_file = '{}.xml'.format(args.policy)
    policy.save_to_file(policy_file)
    if args.dry_run:
        print('Dry run: saved "{}"'.format(policy_file))
        return 0
    print(epo.import_policies(policy, force=True, file_name=policy_file))
    print('Policy "{}" imported into ePO.'.format(args.policy))
    return 0


if __name__ == '__main__':
    sys.exit(main())
