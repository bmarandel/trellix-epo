#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
solidcore_application_control.py

Example for the trellix_epo package: from a Solidcore export (all the
Solidcore policies, as returned by the ePO API command
"policy.export productId=SOLIDCORE_META"), list the policies, then create a
copy of an Application Control Rules (Windows) policy with an updater, a
trusted directory and an execution control rule added, and save it as a new
policy ready to be imported into ePO.

Usage:
    python3 solidcore_application_control.py <solidcore_export.xml> <template policy name>
"""

import sys

from trellix_epo import SCPolicies, SCAWLPolicyRules

TYPE_ID = 'AWL Rules (Windows)'


def main():
    if len(sys.argv) != 3:
        print('Usage: python3 solidcore_application_control.py <solidcore_export.xml> '
              '<template policy name>', file=sys.stderr)
        return 1

    with open(sys.argv[1], 'rb') as export_file:
        policies = SCPolicies(export_file.read())

    print('Solidcore policies in the export:')
    for row in policies.list():
        print('  {:24} {}'.format(row['typeid'], row['name']))

    # The copy keeps the shared Rule Groups referenced by the template.
    new_name = '{} - copy'.format(sys.argv[2])
    new_policy = policies.new_policy(TYPE_ID, new_name, template=sys.argv[2])
    if new_policy is None:
        print('No "{}" policy named "{}" in the export.'.format(TYPE_ID, sys.argv[2]),
              file=sys.stderr)
        return 1
    policy = SCAWLPolicyRules(new_policy)
    print('Rule Groups referenced by "{}": {}'.format(new_name, policy.get_rule_group_names()))

    policy.add_updater('C:\\Program Files\\MyApp\\updater.exe', 'MyApp updater')
    policy.add_trusted_directory('\\\\fileserver\\deploy\\')
    policy.add_execution_control_rule('powershell.exe', 'block',
                                      [('command_line', 'matches', '.*-enc.*')],
                                      'Block encoded PowerShell commands')

    policy.save_to_file('solidcore_awl_rules_updated.xml')
    print('  -> saved to solidcore_awl_rules_updated.xml')
    return 0


if __name__ == '__main__':
    sys.exit(main())
