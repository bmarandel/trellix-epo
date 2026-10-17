#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
system_tree_import.py

Example for the trellix_epo package: builds the ePO System Tree from a CSV
list of systems (an inventory, a CMDB export) with the Web API, or writes
the System Tree as a Markdown document.

The CSV file has a header line and the columns name and group, then
optionally description and custom1 to custom4:

    name,group,description,custom1
    SRV01,Servers\\Paris,SQL Server,PROD
    PC01,Workstations\\Accounting,,

For each line, the group is created with its missing parents
(epo.groups.create()), the system is added to it (epo.systems.add(),
without agent: it stays unmanaged until an agent connects) and its
description and custom fields are set. A system already in the System Tree
is left where it is, unless --move: then it is moved to its group; its
fields are set in both cases. Lost and Found is never used as a group: the
server fills it with the systems deployed outside the console.

--dry-run shows what would be done without changing the server; --markdown
writes the groups and systems of the server instead.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 system_tree_import.py systems.csv [--move] [--dry-run]
    python3 system_tree_import.py --markdown system_tree.md
"""

import csv
import sys

from trellix_epo import groups_to_markdown, systems_to_markdown
from trellix_epo.systemtree import CUSTOM_FIELDS, check_destination, check_name, normalize_path
from epo_connection import connect, parser


def read_csv(path):
    """
    Returns the lines of the CSV file as dictionaries (name, group,
    description, custom1-4), checked: a name, a group out of Lost and Found.
    """
    with open(path, newline='', encoding='utf-8-sig') as csv_file:
        rows = list(csv.DictReader(csv_file))
    for number, row in enumerate(rows, 2):
        try:
            check_name(row.get('name') or '')
            row['group'] = normalize_path(row.get('group') or '')
            check_destination(row['group'])
        except ValueError as error:
            sys.exit('{} line {}: {}'.format(path, number, error))
    return rows


def write_markdown(epo, path):
    """
    Writes the groups of the System Tree, then its systems, as Markdown.
    """
    groups = epo.groups.list()
    paths = {group.id: group.path for group in groups}
    systems = epo.systems.find()
    text = [groups_to_markdown(groups), '']
    for group in groups:
        members = [system for system in systems if system.group_id == group.id]
        if members:
            text += [systems_to_markdown(members, title=paths[group.id]).replace('# ', '## ', 1),
                     '']
    with open(path, 'w', encoding='utf-8') as output:
        output.write('\n'.join(text))
    print('{}: {} groups, {} systems'.format(path, len(groups), len(systems)))


def main():
    """
    Imports the CSV list of systems (or writes the System Tree with --markdown).
    """
    args_parser = parser('Build the ePO System Tree from a CSV list of systems.')
    args_parser.add_argument('csv', nargs='?', help='CSV file: name,group[,description,custom1-4]')
    args_parser.add_argument('--move', action='store_true',
                             help='move the systems already in the System Tree to their group')
    args_parser.add_argument('--markdown', help='write the System Tree to this Markdown file')
    args = args_parser.parse_args()
    if not args.csv and not args.markdown:
        args_parser.error('give the CSV file, or --markdown')
    epo = connect(args)

    if args.markdown:
        write_markdown(epo, args.markdown)
        return

    for row in read_csv(args.csv):
        name, group_path = row['name'].strip(), row['group']
        fields = {key: row.get(key) for key in ('description',) + CUSTOM_FIELDS
                  if (row.get(key) or '').strip()}
        group = epo.groups.get(group_path)
        system = epo.systems.get(name)
        actions = []
        if group is None:
            actions.append('create group')
        if system is None:
            actions.append('add')
        elif args.move and (group is None or system.group_id != group.id):
            actions.append('move')
        if fields:
            actions.append('set ' + ', '.join(fields))
        print('{}: {} -> {}'.format(name, ', '.join(actions) or 'nothing to do', group_path))
        if args.dry_run:
            continue
        if group is None:
            group = epo.groups.create(group_path)
        if system is None:
            system = epo.systems.add(name, group)[0]
        elif 'move' in actions:
            epo.systems.move(system, group)
        if fields:
            epo.systems.set_properties(system, **fields)


if __name__ == '__main__':
    main()
