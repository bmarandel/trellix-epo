#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
client_tasks_product_update.py

Example for the trellix_epo package: a Trellix Agent "Product Update"
client task, imported into the ePO Client Task Catalog with the Web API.

By default the task is "Update All": all the packages of the repository,
without the "Update in Progress" dialog box, as the usual daily update task.
With --packages, the task updates the selected packages only, e.g. the
content of the day (AMCore content, Exploit Prevention content):

    --packages AMCORDAT2000,ENDPCNT_1000

--list-packages shows the packages of the repository that a Product Update
task can select (signatures, engines, content, updates).

--show-progress shows the "Update in Progress" dialog box on the Windows
systems; --postpones lets the users postpone the update (it needs the
dialog box), with --postpone-timeout and --postpone-text.

The task is checked as in the console (the Engine with the DAT only,
postpone 1 to 999 times...) and against the server (check_server(): the
selected packages are in the repository). A task of the same name is
replaced and keeps its assignments. With --run, the task runs now on the
systems (clienttask.run, "Run Client Task Now").

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 client_tasks_product_update.py [--name "Update All"] [--run W10ENTB01] [--dry-run]
    python3 client_tasks_product_update.py --name "Update Content" \\
        --packages AMCORDAT2000,ENDPCNT_1000 --show-progress --postpones 3
    python3 client_tasks_product_update.py --list-packages
"""

import sys

from trellix_epo import ClientTaskList, TAUpdateTask
from epo_connection import connect, parser


def list_packages(epo):
    """
    Prints the packages of the repository a Product Update task can select:
    every package type but Install.
    """
    for package in sorted(epo.repository.packages(), key=lambda item: item.product_id):
        if package.package_type != 'Install':
            print('{:<24} {:<10} {:<10} {}'.format(package.product_id, package.type_label,
                                                   package.branch, package.name))


def main():
    """
    Creates the Product Update task (or lists the packages with --list-packages).
    """
    args_parser = parser('Create a Trellix Agent Product Update client task.')
    args_parser.add_argument('--name', default='Update All', help='task name')
    args_parser.add_argument('--packages',
                             help='product ids (comma separated) to update (default: all)')
    args_parser.add_argument('--show-progress', action='store_true',
                             help='show the "Update in Progress" dialog box')
    args_parser.add_argument('--postpones', type=int,
                             help='allow the users to postpone the update this many times')
    args_parser.add_argument('--postpone-timeout', type=int, default=20,
                             help='seconds before the postpone option expires')
    args_parser.add_argument('--postpone-text', default='', help='text of the postpone dialog')
    args_parser.add_argument('--run', help='systems (comma separated) to update now')
    args_parser.add_argument('--output', default='client_tasks.xml', help='file to write')
    args_parser.add_argument('--list-packages', action='store_true',
                             help='list the packages of the repository a task can select')
    args = args_parser.parse_args()
    epo = connect(args)

    if args.list_packages:
        list_packages(epo)
        return 0
    packages = None
    if args.packages:
        packages = [code.strip() for code in args.packages.split(',') if code.strip()]
    try:
        tasks = ClientTaskList()
        tasks.add(TAUpdateTask(args.name, packages, show_progress=args.show_progress,
                               allow_postpone=args.postpones is not None,
                               max_postpones=args.postpones or 1,
                               postpone_timeout=args.postpone_timeout,
                               postpone_text=args.postpone_text,
                               description='All the packages of the repository.' if packages is None
                               else 'Updates ' + ', '.join(packages) + '.'))
    except ValueError as error:
        print('ERROR: {}'.format(error))
        return 1
    print(tasks.to_markdown())
    tasks.save_to_file(args.output)
    problems = tasks.check_server(epo)
    for problem in problems:
        print('ERROR: ' + problem)
    if problems or args.dry_run:
        print('Saved {} (not imported).'.format(args.output))
        return 1 if problems else 0
    print('Imported {} client task(s).'.format(epo.client_tasks.import_tasks(tasks)))
    if args.run:
        print('{}: {}'.format(args.name, epo.client_tasks.run(tasks.tasks[0],
                                                               args.run.split(','))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
