#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
firewall_rule_editing.py

Example for the trellix_epo package: load an ENS Firewall Rules
policy, print its rule tree, then - as in the console "Add Group" / "Add
Rule" dialogs - add a group with a location holding a rule (networks,
application, schedule), move a rule into the group, disable a rule and
remove another one.

Usage:
    python3 firewall_rule_editing.py <policy.xml>
"""

import sys

from trellix_epo import (ESFWPolicyRules, FWRule, FWGroup, FWNetwork, FWApplication,
                                 FWExecutable, FWLocation)


def print_tree(rules, indent=''):
    for rule in rules:
        if rule.is_group:
            print('{}+ {} ({})'.format(indent, rule.name, 'location: ' + rule.location.name
                                       if rule.location else 'no location'))
            print_tree(rule.rules, indent + '  ')
        else:
            print('{}- {} [{} {}{}]'.format(indent, rule.name, rule.action, rule.direction,
                                            '' if rule.enabled else ', disabled'))


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 firewall_rule_editing.py <policy.xml>', file=sys.stderr)
        return 1

    policy = ESFWPolicyRules()
    policy.load_from_file(sys.argv[1])
    policy.load_policy()
    print_tree(policy.get_rules())

    # A rule allowing the backup agent to reach the backup servers at night.
    rule = FWRule('Allow backup server', FWRule.ALLOW, FWRule.OUT, log=True,
                  notes='Added by firewall_rule_editing.py example',
                  transport_protocol=FWRule.TCP, remote_ports=['443', '8400-8410'],
                  remote_networks=[FWNetwork('Backup servers',
                                             ['10.10.0.0/24', 'backup.example.com'])],
                  applications=[FWApplication('Backup agent', [
                      FWExecutable('Backup agent', path='**\\backupagent.exe',
                                   signer='CN=Example Corp')])])
    rule.set_schedule(['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'],
                      '20:00', '23:59')

    # A group applied only on the office network (location awareness).
    group = FWGroup('Office', notes='Added by firewall_rule_editing.py example',
                    location=FWLocation('Office LAN', dns_suffixes=['corp.example.com'],
                                        default_gateways=['10.0.0.1']),
                    rules=[rule])
    # After the first group ("Trellix core networking" in the default policies).
    policy.add_rule(group, position=1)

    snmp = policy.get_rule('Allow SNMP traffic')
    if snmp is not None:
        policy.move_rule(snmp, group, 0)
        snmp.enabled = False
        policy.update_rule(snmp)

    if policy.get_rule('Allow all outbound traffic on high UDP ports') is not None:
        policy.remove_rule('Allow all outbound traffic on high UDP ports')

    print()
    print_tree(policy.get_rules())
    output_path = 'fw_rules_updated.xml'
    policy.save_to_file(output_path)
    print('Updated policy written to {}'.format(output_path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
