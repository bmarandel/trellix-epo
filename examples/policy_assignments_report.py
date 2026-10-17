#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
policy_assignments_report.py

Example for the trellix_epo package: a Markdown report of the policy
assignments of an ePO server, read with the Web API (nothing is changed):

1. the groups and systems that don't inherit a policy category from their
   parent (the assignments of the Assigned Policies pages), by group;
2. the policies applied to the systems (all those that connected, or the
   systems given with --systems), with the origin and the Up-To-Date state;
   the systems whose policies are not up to date are listed at the top.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 policy_assignments_report.py [--systems PC01,PC02] [--output assignments.md]
"""

from trellix_epo import applied_to_markdown, assignments_to_markdown
from epo_connection import connect, parser


def main():
    """
    Writes the report.
    """
    args_parser = parser('Write the policy assignments of an ePO server as Markdown.')
    args_parser.add_argument('--systems', help='systems (comma separated, default: all)')
    args_parser.add_argument('--output', default='policy_assignments.md', help='file to write')
    args = args_parser.parse_args()
    epo = connect(args)

    names = [name.strip() for name in (args.systems or '').split(',') if name.strip()]
    applied = epo.policies.applied(names or None)
    names = sorted({item.system for item in applied})
    outdated = sorted({item.system for item in applied if not item.up_to_date})

    text = ['# Policy assignments', '']
    if outdated:
        text += ['Systems whose policies are not up to date: ' + ', '.join(outdated), '']
    text += [assignments_to_markdown(epo.policies.assignments(),
                                     'Groups and systems with their own policies')
             .replace('# ', '## ', 1), '',
             applied_to_markdown(applied, 'Applied policies').replace('# ', '## ', 1), '']
    with open(args.output, 'w', encoding='utf-8') as output:
        output.write('\n'.join(text))
    print('{}: {} systems, {} applied policies'.format(args.output, len(names), len(applied)))


if __name__ == '__main__':
    main()
