#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
assignment_rule_suspicious.py

Example for the trellix_epo package: writes a Policy Assignment Rule file
to import in the ePO console (Policy > Policy Assignment Rules > Actions >
Import). The ePO Web API has no command for these rules.

The rule "Suspicious systems" assigns harder policies to every system of
the System Tree that has the "Suspicious" tag (set by the helpdesk): an ENS
Threat Prevention On-Access Scan policy and, optionally, Exploit Prevention
policies (a "Multi-slot" category: several policies can be assigned).

The imported rule is added at the end of the list (lowest priority) and
enabled: move it to the top with Actions > Edit Priority so that it wins
over the other rules. Importing the file again replaces the rule and keeps
its priority.

With --check, the names (tag, group, policies) are checked on the server
first: the import refuses an unknown group or policy, and imports a rule
with an unknown tag without its tag criteria - the rule would then apply to
every system.

Usage:
    python3 assignment_rule_suspicious.py --oas "Suspicious" \\
        [--ep "Suspicious EP"]... [--tag Suspicious] [--output rules.xml]
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 assignment_rule_suspicious.py --oas "Suspicious" --check
"""

import sys

from trellix_epo.assignmentrules import (AssignmentRule, AssignmentRuleList, PolicyAssignment,
                                         RuleTagCriteria)
from epo_connection import connect, parser


def build_rule(tag, oas, exploit_prevention):
    """
    Returns the rule: all the systems (My Organization and its subgroups)
    with the tag get the policies.
    """
    rule = AssignmentRule('Suspicious systems', 'My Organization',
                          tags=RuleTagCriteria([(tag, True)]),
                          notes='Harder policies for the systems tagged "{}" by the helpdesk.'
                          .format(tag))
    rule.add_policy(PolicyAssignment.from_console('Endpoint Security Threat Prevention',
                                                  'On-Access Scan', oas))
    for name in exploit_prevention:
        rule.add_policy(PolicyAssignment.from_console('Endpoint Security Threat Prevention',
                                                      'Exploit Prevention', name))
    return rule


def main():
    """
    Writes the rule file (and checks its names on the server with --check).
    """
    args_parser = parser('Write the "Suspicious systems" Policy Assignment Rule file.')
    args_parser.add_argument('--tag', default='Suspicious', help='tag set by the helpdesk')
    args_parser.add_argument('--oas', required=True, help='ENS TP On-Access Scan policy name')
    args_parser.add_argument('--ep', action='append', default=[],
                             help='ENS TP Exploit Prevention policy name (repeatable)')
    args_parser.add_argument('--output', default='suspicious_rule.xml', help='file to write')
    args_parser.add_argument('--check', action='store_true',
                             help='check the tag, group and policy names on the ePO server')
    args = args_parser.parse_args()

    rules = AssignmentRuleList()
    rules.add(build_rule(args.tag, args.oas, args.ep))
    print(rules.to_markdown())
    if args.check:
        problems = rules.check_server(connect(args))
        for problem in problems:
            print('ERROR: ' + problem)
        if problems:
            return 1
    rules.save_to_file(args.output)
    print('Saved {}: import it in the console (Policy Assignment Rules > Actions > Import), '
          'then move the rule to the top (Actions > Edit Priority).'.format(args.output))
    return 0


if __name__ == '__main__':
    sys.exit(main())
