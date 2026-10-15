#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
solidcore_rule_groups.py

Example for the trellix_epo package: create a user defined Solidcore
Application Control Rule Group (Windows) and make an Application Control Rules
policy use it.

Inputs, from the ePO API:
  - <solidcore_export.xml>: "policy.export productId=SOLIDCORE_META"
  - <policy name>: an "Application Control Rules (Windows)" policy of the export

Outputs, to import with the ePO API in this order (ePO links the policy to the
Rule Group by its name, so the Rule Group must exist first):
  1. rule_group.xml: "scor.rulegroup.import file=rule_group.xml"
  2. policy.xml:     "policy.importPolicy file=policy.xml force=true"

Usage:
    python3 solidcore_rule_groups.py <solidcore_export.xml> <policy name> <rule group name>
"""

import sys

from trellix_epo import SCPolicies, SCAWLPolicyRules, SCRuleGroups, SCException


def main():
    if len(sys.argv) != 4:
        print('Usage: python3 solidcore_rule_groups.py <solidcore_export.xml> <policy name> '
              '<rule group name>', file=sys.stderr)
        return 1

    # 1. A new Rule Group, edited with the same methods as the policy tabs.
    rule_groups = SCRuleGroups()
    rule_group = rule_groups.new_rule_group(sys.argv[3], SCRuleGroups.APPLICATION_CONTROL,
                                            SCRuleGroups.WINDOWS)
    rule_group.add_updater('C:\\Program Files\\MyApp\\updater.exe', 'MyApp updater')
    rule_group.add_exclusion(SCException.EXCLUDE_ALLOW_LIST, 'C:\\Program Files\\MyApp\\Data\\')
    rule_groups.save_to_file('rule_group.xml')
    print('Rule Group "{}" saved to rule_group.xml'.format(rule_group.get_name()))

    # 2. The policy, now referencing the Rule Group.
    with open(sys.argv[1], 'rb') as export_file:
        policies = SCPolicies(export_file.read())
    policy_xml = policies.get_policy('AWL Rules (Windows)', sys.argv[2])
    if policy_xml is None:
        print('No "Application Control Rules (Windows)" policy named "{}".'.format(sys.argv[2]),
              file=sys.stderr)
        return 1
    policy = SCAWLPolicyRules(policy_xml)
    policy.add_rule_group(rule_group)
    policy.save_to_file('policy.xml')
    print('Policy "{}" now uses: {}'.format(policy.get_name(), policy.get_rule_group_names()))
    print('  -> saved to policy.xml')
    return 0


if __name__ == '__main__':
    sys.exit(main())
