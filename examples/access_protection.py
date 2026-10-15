#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
access_protection.py

Example for the trellix_epo package: load an ENS Threat Prevention
Access Protection policy, list its rules, then - as in the console - create
a rule blocking ransomware file extensions and the change of the Run
registry key, block a Trellix-defined rule and add an exclusion.

Usage:
    python3 access_protection.py <policy.xml>
"""

import sys

from trellix_epo import (ESTPPolicyAccessProtection, APRule, APSubRule, APTarget,
                                 APExecutable, APUserName)


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 access_protection.py <policy.xml>', file=sys.stderr)
        return 1

    policy = ESTPPolicyAccessProtection()
    policy.load_from_file(sys.argv[1])

    print('Policy "{}" - Access Protection enabled: {}'.format(policy.get_name(),
                                                               policy.access_protection))
    for rule in policy.get_rules():
        print('  [{}{}] {} ({}, {})'.format('B' if rule.block else '-', 'R' if rule.report else '-',
                                           rule.name, rule.origin, rule.os))

    # A user-defined rule: Name, Action, Executables, User Names, Subrules.
    rule = APRule('Block ransomware extensions', block=True, report=True,
                  notes='Added by access_protection.py example')
    rule.add_executable(APExecutable('Backup agent', path='**\\backupagent.exe',
                                     inclusion='exclude'))
    rule.add_user_name(APUserName('Local\\System', inclusion='exclude'))
    rule.add_subrule(APSubRule('Ransomware extensions', APSubRule.FILES, ['create', 'rename'],
                               targets=[APTarget('*.locky'), APTarget('*.lockbit')]))
    rule.add_subrule(APSubRule('Run key', APSubRule.REGISTRY_KEY, ['write', 'create'],
                               targets=[APTarget('HKLM\\SOFTWARE\\Microsoft\\Windows\\'
                                                 'CurrentVersion\\Run')]))
    policy.add_rule(rule)

    # A Trellix-defined rule: only Block/Report, executables and notes change.
    policy.set_rule_block('PREVENT_MIMIKATZ_CREATION', '1')

    # An exclusion (applies to all the rules).
    policy.add_exclusion(APExecutable('Admin tool', path='C:\\Tools\\admintool.exe',
                                      signer=APExecutable.ANY_SIGNATURE))

    output_path = 'ap_updated.xml'
    policy.save_to_file(output_path)
    print('Updated policy written to {}'.format(output_path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
