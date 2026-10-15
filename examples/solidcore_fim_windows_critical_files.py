#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
solidcore_fim_windows_critical_files.py

Example for the trellix_epo package, working directly against an ePO
server with the ePO Web API client of the library (EPOClient).

It creates (or updates) a Solidcore Integrity Monitoring Rules (Windows) policy
for Windows Server 2019, starting from a blank policy:
  1. adds the Trellix Rule Group "Windows 2019 Server (64 bit) Base Filters";
  2. creates the user defined Rule Group "Windows Critical Config Files" (see
     CRITICAL_FILES below), imports it into ePO, and adds it to the policy;
  3. imports the policy into ePO.

"Windows Critical Config Files" only lists data/configuration files (no
executable, script or library), chosen from Windows hardening and file
integrity monitoring practice (PCI DSS requirement 11.5, CIS Benchmarks) and
from the MITRE ATT&CK techniques they relate to:
  - name resolution and network services (hosts, services...): traffic
    redirection;
  - local Group Policy and security templates (T1484.001 Group Policy
    Modification) and audit policy;
  - unattended setup answer files, which may hold credentials (T1552.001
    Credentials In Files);
  - scheduled tasks and Startup folder (T1053.005 Scheduled Task, T1547.001
    Startup Folder), application control policies (WDAC, AppLocker);
  - .NET and IIS configuration, legacy win.ini/system.ini autostart entries.
Small text files get Content Change Tracking, to see what was changed. Log,
temporary and trace files are excluded, as they change all the time.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 solidcore_fim_windows_critical_files.py [--dry-run]
"""

import sys

from trellix_epo import SCFIMPolicyRules, SCRuleGroups
from epo_connection import connect, parser

TYPE_ID = 'Mon Rules (Windows)'
TRELLIX_RULE_GROUP = 'Windows 2019 Server (64 bit) Base Filters'
CRITICAL_RULE_GROUP = 'Windows Critical Config Files'

ETC = '%SystemRoot%\\System32\\drivers\\etc\\'
GPO = '%SystemRoot%\\System32\\GroupPolicy\\'

# (path, change tracking, file encoding): a path ending with "\" is a directory.
CRITICAL_FILES = [
    # Name resolution and network services.
    (ETC + 'hosts', True, 'AutoDetect'),
    (ETC + 'lmhosts.sam', True, 'AutoDetect'),
    (ETC + 'networks', True, 'AutoDetect'),
    (ETC + 'protocol', True, 'AutoDetect'),
    (ETC + 'services', True, 'AutoDetect'),
    # Local Group Policy, security template (user rights, password policy...)
    # and advanced audit policy.
    (GPO + 'gpt.ini', True, 'AutoDetect'),
    (GPO + 'Machine\\Registry.pol', False, None),
    (GPO + 'User\\Registry.pol', False, None),
    (GPO + 'Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf', True, 'UTF-16'),
    (GPO + 'Machine\\Microsoft\\Windows NT\\Audit\\audit.csv', True, 'AutoDetect'),
    # Unattended setup answer files (may contain credentials).
    ('%SystemRoot%\\Panther\\Unattend.xml', True, 'AutoDetect'),
    ('%SystemRoot%\\Panther\\Unattend\\Unattend.xml', True, 'AutoDetect'),
    ('%SystemRoot%\\System32\\Sysprep\\Unattend.xml', True, 'AutoDetect'),
    # Persistence: scheduled task definitions and the common Startup folder.
    ('%SystemRoot%\\System32\\Tasks\\', False, None),
    ('%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\', False, None),
    # Application control policies (Windows Defender Application Control, AppLocker).
    ('%SystemRoot%\\System32\\CodeIntegrity\\', False, None),
    ('%SystemRoot%\\System32\\AppLocker\\', False, None),
    # .NET and IIS configuration.
    ('%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\machine.config', True,
     'AutoDetect'),
    ('%SystemRoot%\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\web.config', True,
     'AutoDetect'),
    ('%SystemRoot%\\System32\\inetsrv\\config\\applicationHost.config', True, 'AutoDetect'),
    # Legacy autostart entries (load=/run= in win.ini, shell= in system.ini).
    ('%SystemRoot%\\win.ini', True, 'AutoDetect'),
    ('%SystemRoot%\\system.ini', True, 'AutoDetect'),
]
# Files changing all the time, not relevant in the folders above.
EXCLUDED_EXTENSIONS = ['log', 'tmp', 'etl']


def build_critical_rule_group():
    """
    Returns the "Windows Critical Config Files" Rule Group.
    """
    rule_groups = SCRuleGroups()
    group = rule_groups.new_rule_group(CRITICAL_RULE_GROUP, SCRuleGroups.INTEGRITY_MONITOR,
                                       SCRuleGroups.WINDOWS)
    for path, change_tracking, encoding in CRITICAL_FILES:
        if change_tracking:
            group.add_file(path, change_tracking=True, encoding=encoding)
        else:
            group.add_file(path)
    for extension in EXCLUDED_EXTENSIONS:
        group.add_extension(extension)
    return rule_groups, group


def main():
    args_parser = parser('Create a Windows Server 2019 Integrity Monitoring policy.')
    args_parser.add_argument('--policy', default='FIM Windows Server 2019 Sample',
                             help='policy name (default: %(default)s)')
    args = args_parser.parse_args()
    epo = connect(args)

    # 1. A blank policy, or the policy created by a previous run.
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
    policy = SCFIMPolicyRules(policy_xml)

    trellix_group = epo.export_rule_group(SCRuleGroups.WINDOWS, SCRuleGroups.INTEGRITY_MONITOR,
                                          TRELLIX_RULE_GROUP)
    if trellix_group is None:
        sys.exit('Rule Group "{}" not found in ePO.'.format(TRELLIX_RULE_GROUP))
    if policy.add_rule_group(trellix_group):
        print('  added Rule Group "{}" ({} rules)'.format(TRELLIX_RULE_GROUP,
                                                          len(trellix_group.get_rules())))

    # 2. The "Windows Critical Config Files" Rule Group, imported before the policy.
    rule_groups, critical_group = build_critical_rule_group()
    rule_groups.save_to_file('windows_critical_config_files.xml')
    print('Rule Group "{}": {} files and folders, {} excluded extensions'.format(
        CRITICAL_RULE_GROUP, len(critical_group.get_file_list()),
        len(critical_group.get_extension_list())))
    policy_file = '{}.xml'.format(args.policy)
    if args.dry_run:
        policy.add_rule_group(critical_group)
        policy.save_to_file(policy_file)
        print('Dry run: saved windows_critical_config_files.xml and "{}"'.format(policy_file))
        return 0
    exists = epo.rule_group_exists(SCRuleGroups.WINDOWS, SCRuleGroups.INTEGRITY_MONITOR,
                                   CRITICAL_RULE_GROUP)
    epo.import_rule_groups(rule_groups, override=exists,
                           file_name='windows_critical_config_files.xml')
    print('  {} in ePO.'.format('updated' if exists else 'created'))
    if policy.add_rule_group(critical_group):
        print('  added to the policy.')

    # 3. The policy.
    policy.save_to_file(policy_file)
    print(epo.import_policies(policy, force=True, file_name=policy_file))
    print('Policy "{}" imported into ePO, Rule Groups: {}'.format(
        args.policy, ', '.join(policy.get_rule_group_names())))
    return 0


if __name__ == '__main__':
    sys.exit(main())
