#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
server_task_run.py

Example for the trellix_epo package: runs an ePO server task with the Web
API, waits for its end and prints its status, subtasks and messages, so an
outside scheduler or a deployment pipeline can chain on it (exit code 0 when
the task completed, 1 when it failed or was cancelled, 2 when it is still
running after --timeout). --log shows the latest runs of the task instead.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 server_task_run.py "Update Main Repository" [--timeout 1800]
    python3 server_task_run.py "Update Main Repository" --log 10
"""

import sys

from trellix_epo import task_log_to_markdown
from epo_connection import connect, parser


def main():
    """
    Runs the task (or shows its log with --log) and returns the exit code.
    """
    args_parser = parser('Run an ePO server task and wait for its end.')
    args_parser.add_argument('task', help='server task name (as in the console) or id')
    args_parser.add_argument('--timeout', type=int, default=1800, help='seconds to wait')
    args_parser.add_argument('--log', type=int, metavar='N',
                             help="show the N latest runs of the task, don't run it")
    args = args_parser.parse_args()
    epo = connect(args)
    task = epo.server_tasks.require(int(args.task) if args.task.isdigit() else args.task)

    if args.log:
        print(task_log_to_markdown(epo.server_tasks.log(task=task, limit=args.log), task.name))
        return 0
    if args.dry_run:
        print('Would run {} (id {}).'.format(task.name, task.id))
        return 0
    try:
        entry = epo.server_tasks.run(task, wait=True, timeout=args.timeout)
    except TimeoutError as error:
        print(error)
        return 2
    print(entry.to_markdown())
    return 0 if entry.succeeded else 1


if __name__ == '__main__':
    sys.exit(main())
