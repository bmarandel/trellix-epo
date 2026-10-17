#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
client_tasks_solidcore_enable.py

Example for the trellix_epo package: the Solidcore "SC: Enable" client task
that activates Change Control and/or Application Control, imported into the
ePO Client Task Catalog with the Web API.

The console has one page per kind of client, chosen with --platform:
- windows: Windows "All except NT/2000", the page of the current clients:
  full feature activation (the system restarts) or --limited (no restart),
  and with Application Control the initial scan priority (--priority),
  --inventory (Inventory Mode) or --observe (Observe Mode), and Pull
  Inventory (on by default);
- windows-nt: Windows NT/2000, linux: Linux/Solaris/Windriver Linux,
  aix-hpux: AIX/HP-UX (Change Control only): the features and "Reboot
  endpoint" only (--no-reboot to leave the restart to the user).

By default the task enables both features ("full" Solidcore) with a
restart, e.g. "SC Enable Full & Reboot (Linux)" for --platform linux.

The task is checked as in the console (an option of Application Control
without it, Inventory Mode with Observe Mode, Application Control on
AIX/HP-UX...): the script stops on the error the console would show. A task
of the same name is replaced and keeps its assignments. With --run, the
task runs now on the systems (clienttask.run, "Run Client Task Now"):
enabling Solidcore restarts them unless --limited or --no-reboot.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 client_tasks_solidcore_enable.py --platform linux [--dry-run]
    python3 client_tasks_solidcore_enable.py --platform windows --features application-control \\
        --limited --observe [--run W10ENTB01]
"""

import sys

from trellix_epo import ClientTaskList, SCEnableTask
from epo_connection import connect, parser

# --platform -> platform and sub platform of SCEnableTask, label of the name.
PLATFORMS = {
    'windows': ('WIN', 'OTHERS', 'Windows'),
    'windows-nt': ('WIN', 'WINNT_2K', 'Windows NT/2000'),
    'linux': ('UNIX', 'LIN_SOL_WR', 'Linux'),
    'aix-hpux': ('UNIX', 'AIX_HPUX', 'AIX/HP-UX'),
}
FEATURES = ('change-control', 'application-control')


def build_task(args):
    """
    Returns the SC: Enable task of the command line options.

    :raise: ValueError: The options break a rule of the console page.
    """
    platform, sub_platform, label = PLATFORMS[args.platform]
    features = [feature.strip() for feature in args.features.split(',') if feature.strip()]
    unknown = [feature for feature in features if feature not in FEATURES]
    if unknown:
        raise ValueError('Unknown feature(s): {} (use {}).'.format(', '.join(unknown),
                                                                  ', '.join(FEATURES)))
    task = SCEnableTask('', change_control='change-control' in features,
                        application_control='application-control' in features,
                        platform=platform, sub_platform=sub_platform, reboot=not args.no_reboot,
                        scan_priority=args.priority, limited_activation=args.limited,
                        inventory_mode=args.inventory, observe_mode=args.observe)
    restart = not args.limited if task.current_page else task.reboot
    what = 'Full' if len(features) == 2 else \
        'Change Control' if task.change_control else 'Application Control'
    task.name = args.name or 'SC Enable {}{} ({})'.format(what, ' & Reboot' if restart else '',
                                                         label)
    task.description = 'Enables Solidcore {} on {} clients{}.'.format(
        ' and '.join(feature.replace('-', ' ') for feature in features), label,
        ', with a restart' if restart else ', without a restart')
    return task


def main():
    """
    Creates the SC: Enable task.
    """
    args_parser = parser('Create the Solidcore "SC: Enable" client task.')
    args_parser.add_argument('--name', help='task name (default: from the options)')
    args_parser.add_argument('--platform', default='windows', choices=list(PLATFORMS),
                             help='kind of client (console page)')
    args_parser.add_argument('--features', default=','.join(FEATURES),
                             help='features to enable (comma separated): ' + ', '.join(FEATURES))
    args_parser.add_argument('--no-reboot', action='store_true',
                             help='windows-nt, linux, aix-hpux: don\'t reboot the endpoint')
    args_parser.add_argument('--limited', action='store_true',
                             help='windows: Limited Feature Activation (no restart)')
    args_parser.add_argument('--priority', default='normal', choices=('low', 'normal', 'high'),
                             help='windows, Application Control: Initial Scan Priority')
    args_parser.add_argument('--inventory', action='store_true',
                             help='windows, Application Control: start Inventory Mode')
    args_parser.add_argument('--observe', action='store_true',
                             help='windows, Application Control: start Observe Mode')
    args_parser.add_argument('--run', help='systems (comma separated) to enable Solidcore on now')
    args_parser.add_argument('--output', default='client_tasks.xml', help='file to write')
    args = args_parser.parse_args()

    try:
        tasks = ClientTaskList()
        tasks.add(build_task(args))
    except ValueError as error:
        print('ERROR: {}'.format(error))
        return 1
    print(tasks.to_markdown())
    epo = connect(args)
    tasks.save_to_file(args.output)
    problems = tasks.check_server(epo)
    for problem in problems:
        print('ERROR: ' + problem)
    if problems or args.dry_run:
        print('Saved {} (not imported).'.format(args.output))
        return 1 if problems else 0
    print('Imported {} client task(s).'.format(epo.client_tasks.import_tasks(tasks)))
    if args.run:
        print('{}: {}'.format(tasks.tasks[0].name,
                              epo.client_tasks.run(tasks.tasks[0], args.run.split(','))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
