#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
firewall_rules.py

Example for the trellix_epo package: load an ENS Firewall Rules
policy and export its rule tree as a Markdown report.

To change the rules, see firewall_rule_editing.py.

Usage:
    python3 firewall_rules.py <policy.xml> [output.md]
"""

import sys

from trellix_epo import ESFWPolicyRules


def main():
    if len(sys.argv) not in (2, 3):
        print('Usage: python3 firewall_rules.py <policy.xml> [output.md]', file=sys.stderr)
        return 1

    policy = ESFWPolicyRules()
    policy.load_from_file(sys.argv[1])
    print(policy)           # e.g. <ESFWPolicyRules 'Demo': 10 groups, 56 rules>

    output_path = sys.argv[2] if len(sys.argv) == 3 else 'firewall_rules.md'
    policy.save_markdown(output_path)
    print('Report written to {}'.format(output_path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
