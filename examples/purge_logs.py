#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
purge_logs.py

Example for the trellix_epo package: purges the ePO logs older than a
retention period with the Web API, as the purge server tasks of the
console do. By default it only shows what it would delete (dry run): add
--apply to purge.

The default retention follows the Trellix best practices (Product Guide
5.10): 6 months for the Audit Log, the Server Task Log and the client
events, 3 months for the threat events (purged every day by Trellix: set
your own retention policy) and 1 year for the Compliance History.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 purge_logs.py                         # what would be deleted
    python3 purge_logs.py --threat 30 days --apply
    python3 purge_logs.py --only audit tasklog --apply
"""

import sys

from epo_connection import connect, parser

# Log -> (default age, unit, purge method of epo.events, label).
LOGS = {
    'audit': (6, 'months', 'purge_audit_log', 'Audit Log'),
    'tasklog': (6, 'months', 'purge_task_log', 'Server Task Log'),
    'threat': (3, 'months', 'purge_threat_events', 'Threat events'),
    'client': (6, 'months', 'purge_client_events', 'Client events'),
    'compliance': (1, 'years', 'purge_compliance_history', 'Compliance History'),
}


def main():
    """
    Shows (or with --apply, purges) the rows older than the retention.
    """
    args_parser = parser('Purge the ePO logs older than a retention period.')
    for log, (age, unit, _, label) in LOGS.items():
        args_parser.add_argument('--' + log, nargs=2, metavar=('AGE', 'UNIT'),
                                 default=[str(age), unit],
                                 help='{} retention (default {} {})'.format(label, age, unit))
    args_parser.add_argument('--only', nargs='+', choices=sorted(LOGS), help='logs to purge')
    args_parser.add_argument('--apply', action='store_true', help='purge (default: dry run)')
    args = args_parser.parse_args()
    epo = connect(args)

    for log, (_, _, method, label) in LOGS.items():
        if args.only and log not in args.only:
            continue
        age, unit = getattr(args, log)
        count = getattr(epo.events, method)(int(age), unit, dry_run=not args.apply)
        print('{:20} older than {} {}: {} {}'.format(
            label, age, unit, count, 'deleted' if args.apply else 'to delete (dry run)'))
    if not args.apply:
        print('Dry run: nothing deleted, add --apply to purge.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
