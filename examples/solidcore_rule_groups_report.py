#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
solidcore_rule_groups_report.py

Example for the trellix_epo package: a Markdown document of the Solidcore
Rule Groups of an ePO server (Menu > Configuration > Solidcore Rules), read
with the Web API: a summary table, then the properties and the rules of each
Rule Group (the tables of the policy tabs), with the policies using it.

scor.rulegroup.export without a name only gives the user defined Rule
Groups: the script exports each Rule Group by its name, so the ones
predefined by Trellix are documented too.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 solidcore_rule_groups_report.py [--platform WIN|UNIX]
        [--type APPLICATION_CONTROL|CHANGE_CONTROL|INTEGRITY_MONITOR]
        [--name "Rule Group"] [--user-defined] [--output rule_groups.md]
"""

from trellix_epo import SCRuleGroups
from epo_connection import connect, parser

TYPES = {'APPLICATION_CONTROL': SCRuleGroups.APPLICATION_CONTROL,
         'CHANGE_CONTROL': SCRuleGroups.CHANGE_CONTROL,
         'INTEGRITY_MONITOR': SCRuleGroups.INTEGRITY_MONITOR}


def main():
    """
    Exports the Rule Groups and writes their Markdown document.
    """
    args_parser = parser('Write the Solidcore Rule Groups of an ePO server as Markdown.')
    args_parser.add_argument('--platform', choices=('WIN', 'UNIX'), default='WIN')
    args_parser.add_argument('--type', choices=sorted(TYPES), default='APPLICATION_CONTROL')
    args_parser.add_argument('--name', help='one Rule Group only')
    args_parser.add_argument('--user-defined', action='store_true',
                             help='leave out the Rule Groups predefined by Trellix')
    args_parser.add_argument('--output', default='rule_groups.md', help='file to write')
    args = args_parser.parse_args()
    epo = connect(args)

    group_type = TYPES[args.type]
    policies = epo.export_policies('SOLIDCORE_META')
    names = [args.name] if args.name else epo.find_rule_groups(args.platform, group_type)
    groups = SCRuleGroups()
    for name in names:
        group = epo.export_rule_group(args.platform, group_type, name)
        if group is None:
            raise SystemExit('No {} {} Rule Group named {!r}.'.format(args.platform, args.type, name))
        if not (args.user_defined and group.is_read_only()):
            groups.add_rule_group(group)
    if args.name:
        groups.get_rule_group(args.name).save_markdown(args.output, policies)
    else:
        title = '{} Rule Groups ({})'.format(args.type.replace('_', ' ').title(),
                                              'Windows' if args.platform == 'WIN' else 'Unix')
        groups.save_markdown(args.output, policies, title)
    print('{}: {}'.format(args.output, groups))


if __name__ == '__main__':
    main()
