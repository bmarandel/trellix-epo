#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
client_tasks_solidcore_maintenance.py

Example for the trellix_epo package: the client tasks of a Solidcore
maintenance window (a change request), created in the ePO Client Task
Catalog with the Web API and run on the systems of the change:

- "SC: Begin Update Mode <change>": opens the update window, the changes
  made on the systems are tagged with the Workflow ID (the change number);
- "SC: End Update Mode": closes it (the client returns to Enabled mode);
- "SC: Pull Inventory": loads the new software inventory into ePO.

The tasks are checked as in the console (Workflow ID of 100 characters, no
comment without Workflow ID) and against the server (check_server(): a task
of the same type whose name differs by case only would be skipped by the
import). An existing task of the same name is replaced and keeps its
assignments. With --begin or --end, the task runs now on the systems
(clienttask.run, "Run Client Task Now"); the run is then in the Server Task
Log as "RunNow Task For :  <task name>".

With --markdown, the client tasks of the server are written as a Markdown
document (Solidcore, Trellix Agent and SIR tasks with the labels of their
console page).

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 client_tasks_solidcore_maintenance.py --change CHG0012345 \\
        --comment "Patch Tuesday" [--begin W10ENTB01,W2022CORE] [--dry-run]
    python3 client_tasks_solidcore_maintenance.py --change CHG0012345 --end W10ENTB01
    python3 client_tasks_solidcore_maintenance.py --markdown client_tasks.md
"""

import sys

from trellix_epo import (ClientTaskList, SCBeginUpdateTask, SCEndUpdateTask,
                         SCPullInventoryTask)
from epo_connection import connect, parser


def build_tasks(change, comment):
    """
    Returns the tasks of the maintenance window of a change.
    """
    tasks = ClientTaskList()
    tasks.add(SCBeginUpdateTask('SC: Begin Update Mode {}'.format(change), workflow_id=change,
                                comment=comment,
                                description='Update window of the change {}.'.format(change)))
    tasks.add(SCEndUpdateTask('SC: End Update Mode',
                              description='Closes the update window (Enabled mode).'))
    tasks.add(SCPullInventoryTask('SC: Pull Inventory',
                                  description='Loads the software inventory into ePO.'))
    return tasks


def main():
    """
    Creates the tasks (or writes the documentation with --markdown).
    """
    args_parser = parser('Create the Solidcore client tasks of a maintenance window.')
    args_parser.add_argument('--change', help='change number, used as Workflow ID')
    args_parser.add_argument('--comment', default='', help='comment of the update window')
    args_parser.add_argument('--begin', help='systems (comma separated) to open the window on now')
    args_parser.add_argument('--end', help='systems (comma separated) to close the window on now')
    args_parser.add_argument('--output', default='client_tasks.xml', help='file to write')
    args_parser.add_argument('--markdown', help='write the client tasks of the server to this '
                                                'Markdown file instead')
    args = args_parser.parse_args()
    epo = connect(args)

    if args.markdown:
        with open(args.markdown, 'w', encoding='utf-8') as md_file:
            md_file.write(epo.client_tasks.export().to_markdown() + '\n')
        print('Saved {}.'.format(args.markdown))
        return 0
    if not args.change:
        args_parser.error('--change is required (or --markdown).')

    tasks = build_tasks(args.change, args.comment)
    print(tasks.to_markdown())
    tasks.save_to_file(args.output)
    problems = tasks.check_server(epo)
    for problem in problems:
        print('ERROR: ' + problem)
    if problems or args.dry_run:
        print('Saved {} (not imported).'.format(args.output))
        return 1 if problems else 0
    print('Imported {} client task(s).'.format(epo.client_tasks.import_tasks(tasks)))
    for systems, task in ((args.begin, tasks.tasks[0]), (args.end, tasks.tasks[1])):
        if systems:
            print('{}: {}'.format(task.name, epo.client_tasks.run(task, systems.split(','))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
