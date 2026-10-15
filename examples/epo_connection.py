# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
epo_connection.py

Helper shared by the examples that work directly against an ePO server: the
command line options and the connection of the library ePO Web API client
(trellix_epo.EPOClient).

Connection settings are read from the command line (--url, --user), then from
the EPO_URL, EPO_USER and EPO_PASSWORD environment variables. The password is
asked interactively if it isn't set: it is never passed on the command line.
"""

import argparse
import getpass
import os
import sys

from trellix_epo import EPOClient


def parser(description):
    """
    Returns an argparse parser with the ePO connection options (--url,
    --user, --insecure) and --dry-run.
    """
    result = argparse.ArgumentParser(description=description)
    result.add_argument('--url', default=os.environ.get('EPO_URL'),
                        help='ePO server URL, e.g. https://epo.example.com:8443 (or EPO_URL)')
    result.add_argument('--user', default=os.environ.get('EPO_USER'),
                        help='ePO user name (or EPO_USER)')
    result.add_argument('--insecure', action='store_true',
                        help="don't check the ePO server certificate (lab servers only)")
    result.add_argument('--dry-run', action='store_true',
                        help="write the XML files but don't import anything into ePO")
    return result


def connect(args):
    """
    Returns an EPOClient set with the options of parser(); the password comes
    from EPO_PASSWORD, or is asked.
    """
    if not args.url or not args.user:
        sys.exit('The ePO server URL and user are required (--url/--user or EPO_URL/EPO_USER).')
    password = os.environ.get('EPO_PASSWORD') or getpass.getpass(
        'ePO password for {}: '.format(args.user))
    return EPOClient(args.url, args.user, password, verify=not args.insecure)
