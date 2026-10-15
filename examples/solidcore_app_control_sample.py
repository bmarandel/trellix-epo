#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
solidcore_app_control_sample.py

Example for the trellix_epo package, working directly against an ePO
server with the ePO Web API client of the library (EPOClient).

It retrieves the Application Control Rules (Windows) policy "App CTRL Windows
Sample" from ePO - a policy using the Trellix Rule Groups and the Rule Groups
allowing Windows to update itself. If it doesn't exist yet, it is created
(empty, with those Rule Groups).

Then, as an example, it adds one item of each tab of the policy (an updater by
name and by checksum, a certificate, an installer, a trusted directory, a
trusted user, executable files allowed and banned, an exclusion, filters and an
execution control rule), creates a user defined Rule Group for a database
server (Microsoft SQL Server), imports it into ePO and adds it to the policy,
before importing the updated policy back into ePO.

The values used are examples: adapt them to your environment. The script can
be run again: items already in the policy are not added twice.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 solidcore_app_control_sample.py [--certificate signer.cer] [--dry-run]
"""

import base64
import sys

from trellix_epo import SCAWLPolicyRules, SCRuleGroups, SCException
from epo_connection import connect, parser

TYPE_ID = 'AWL Rules (Windows)'

# Rule Groups predefined by Trellix: the Trellix products, Windows itself, and
# the updaters Windows needs to update itself (Windows Update, Defender...).
TRELLIX_RULE_GROUPS = ['Trellix', 'Windows', 'Windows Component', 'Windows Update',
                       'Windows Defender', 'Microsoft Security Tools']

DATABASE_RULE_GROUP = 'Sample - Microsoft SQL Server'


def read_certificate(path):
    """
    Returns a certificate file (PEM, or DER as exported by Windows) as PEM text.
    """
    with open(path, 'rb') as cert_file:
        data = cert_file.read()
    if b'-----BEGIN CERTIFICATE-----' in data:
        return data.decode('ascii').strip()
    body = base64.encodebytes(data).decode('ascii').replace('\n', '')
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return '-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----'.format('\n'.join(lines))


def get_or_create_policy(epo, name):
    """
    Returns the policy from ePO, or a new one with the Trellix Rule Groups.
    """
    policies = epo.export_policies('SOLIDCORE_META')
    policy_xml = policies.get_policy(TYPE_ID, name)
    if policy_xml is not None:
        print('Policy "{}" found in ePO.'.format(name))
        return SCAWLPolicyRules(policy_xml)
    policy_xml = policies.new_empty_policy(TYPE_ID, name)
    if policy_xml is None:
        sys.exit('No "{}" policy in ePO to use as a template: duplicate "Blank Template" '
                 'in the Policy Catalog first.'.format(TYPE_ID))
    policy = SCAWLPolicyRules(policy_xml)
    print('Policy "{}" not found: creating it.'.format(name))
    for group_name in TRELLIX_RULE_GROUPS:
        rule_group = epo.export_rule_group(SCRuleGroups.WINDOWS, SCRuleGroups.APPLICATION_CONTROL,
                                           group_name)
        if rule_group is None:
            print('  ! Rule Group "{}" not found in ePO, skipped.'.format(group_name))
            continue
        policy.add_rule_group(rule_group)
    return policy


def build_database_rule_group():
    """
    Returns a user defined Rule Group for a Microsoft SQL Server database server.
    """
    rule_groups = SCRuleGroups()
    group = rule_groups.new_rule_group(DATABASE_RULE_GROUP, SCRuleGroups.APPLICATION_CONTROL,
                                       SCRuleGroups.WINDOWS)
    # The SQL Server setup engine installs the cumulative updates.
    group.add_updater('ScenarioEngine.exe', 'SQL Server Setup Engine')
    # Don't track the database files: they change all the time and are not code.
    group.add_exclusion(SCException.EXCLUDE_FILE_OPERATIONS,
                        'C:\\Program Files\\Microsoft SQL Server\\MSSQL16.MSSQLSERVER\\MSSQL\\DATA\\')
    # A database engine has no reason to start a command shell (xp_cmdshell abuse).
    group.add_execution_control_rule('cmd.exe', 'block',
                                     [('parent_process_name', 'equals', 'sqlservr.exe')],
                                     'Block cmd.exe started by SQL Server (xp_cmdshell)')
    return rule_groups, group


def add_sample_items(policy, certificate):
    """
    Adds one example item in each tab of the policy, unless already there.
    """
    added = []

    def once(already_there, label, add):
        if not already_there:
            add()
            added.append(label)

    labels = [u.get('tag') for u in policy.get_updaters()]
    # Updater Processes: by name, and by checksum (SHA-256).
    once('Sample Updater' in labels, 'updater (name)', lambda: policy.add_updater(
        'C:\\Program Files\\Sample\\Updater\\SampleUpdater.exe', 'Sample Updater',
        parent='services.exe'))
    once('Sample Updater SHA-256' in labels, 'updater (SHA-256)',
         lambda: policy.add_updater_by_checksum(
             '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
             'Sample Updater SHA-256'))
    # Certificates: a publisher whose signed files are allowed to run (and update).
    if certificate:
        once(any(c['pem'] == certificate for c in policy.get_certificates()), 'certificate',
             lambda: policy.add_certificate(certificate, 'Sample Publisher', updater=True))
    # Installers: an installation package allowed to install software.
    once(any(i.get('tag') == 'Sample Installer' for i in policy.get_installers()), 'installer',
         lambda: policy.add_installer('2fd4e1c67a2d28fced849ee1bb76e7391b93eb12',
                                      'Sample Installer', 'Sample Application', '1.0',
                                      'Sample Vendor'))
    # Directories: a trusted network share (software deployment).
    once(any(d['path'] == '\\\\fileserver\\deploy\\' for d in policy.get_trusted_directories()),
         'trusted directory', lambda: policy.add_trusted_directory('\\\\fileserver\\deploy\\'))
    # Users: a deployment service account.
    once(any(u['user'] == 'CONTOSO\\svc_deploy' for u in policy.get_trusted_users()),
         'trusted user', lambda: policy.add_trusted_user('CONTOSO\\svc_deploy',
                                                          'Deployment account', 'Deployment'))
    # Executable Files: allow a tool by checksum, ban another one by name.
    names = [f['name'] for f in policy.get_executable_files()]
    once('Sample Allowed Tool' in names, 'executable file (allow)',
         lambda: policy.add_executable_file(
             'Sample Allowed Tool',
             'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'))
    once('Ban PsExec' in names, 'executable file (ban)',
         lambda: policy.add_executable_file('Ban PsExec', 'psexec.exe', ban=True))
    # Exclusions: a legacy application incompatible with buffer overflow protection.
    once(policy.contains_exclusion(SCException.CASP, 'legacyapp.exe'), 'exclusion',
         lambda: policy.add_exclusion(SCException.CASP, 'legacyapp.exe'))
    # Filters: don't report the observations (and events) of a noisy program,
    # and keep the files of a vendor out of the inventory.
    once(any(f['conditions'][0]['pattern'] == 'C:\\Program Files\\Sample\\noisy.exe'
             for f in policy.get_filters()), 'filter (observations and events)',
         lambda: policy.add_filter([('Process', 'equals', 'C:\\Program Files\\Sample\\noisy.exe')],
                                   apply_to_events=True))
    once(any(f['conditions'][0]['pattern'] == 'Sample Vendor'
             for f in policy.get_inventory_filters()), 'filter (inventory)',
         lambda: policy.add_inventory_filter([('vendor-name', 'equals', 'Sample Vendor')]))
    # Execution Control: block PowerShell encoded commands.
    once(any(r['description'] == 'Block PowerShell encoded commands'
             for r in policy.get_execution_control_rules()), 'execution control rule',
         lambda: policy.add_execution_control_rule(
             'powershell.exe', 'block', [('command_line', 'matches', '.*-[eE][nN][cC].*')],
             'Block PowerShell encoded commands'))
    return added


def main():
    args_parser = parser('Update the "App CTRL Windows Sample" Application Control policy.')
    args_parser.add_argument('--policy', default='App CTRL Windows Sample',
                             help='policy name (default: %(default)s)')
    args_parser.add_argument('--certificate',
                             help='a certificate file (.cer/.pem) to add as a trusted publisher')
    args = args_parser.parse_args()
    epo = connect(args)
    certificate = read_certificate(args.certificate) if args.certificate else None

    policy = get_or_create_policy(epo, args.policy)
    print('  Rule Groups: {}'.format(', '.join(policy.get_rule_group_names()) or 'none'))
    added = add_sample_items(policy, certificate)
    print('  Items added: {}'.format(', '.join(added) or 'none (already there)'))
    if not certificate:
        print('  (no --certificate given: no certificate added)')

    # The database Rule Group must exist in ePO before the policy using it.
    rule_groups, group = build_database_rule_group()
    rule_groups.save_to_file('sample_rule_group.xml')
    policy_file = '{}.xml'.format(args.policy)
    if args.dry_run:
        policy.add_rule_group(group)
        policy.save_to_file(policy_file)
        print('Dry run: saved sample_rule_group.xml and "{}"'.format(policy_file))
        return 0
    exists = epo.rule_group_exists(SCRuleGroups.WINDOWS, SCRuleGroups.APPLICATION_CONTROL,
                                   DATABASE_RULE_GROUP)
    epo.import_rule_groups(rule_groups, override=exists, file_name='sample_rule_group.xml')
    print('Rule Group "{}" {} in ePO.'.format(DATABASE_RULE_GROUP,
                                              'updated' if exists else 'created'))
    if policy.add_rule_group(group):
        print('  added to the policy.')
    policy.save_to_file(policy_file)
    print(epo.import_policies(policy, force=True, file_name=policy_file))
    print('Policy "{}" imported into ePO.'.format(args.policy))
    return 0


if __name__ == '__main__':
    sys.exit(main())
