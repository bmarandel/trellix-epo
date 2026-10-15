#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
tags_off_low_space.py

Example for the trellix_epo package, working directly against an ePO
server with the ePO Web API client of the library (EPOClient, epo.tags).

It sets up, in the "Policy Management" tag group (created if missing):
  - "OFF": a manual tag (no criteria), set by hand on the systems that must
    get the OFF policies (with a policy assignment rule on this tag);
  - "Low-Space": a criteria tag set on the systems with less than 2 GB free
    on the C drive ("Free C Drive Space", a property of the "Computer
    Properties" category), evaluated on each agent-server communication.
    The systems without a C drive (Linux, macOS) report 0 MB free: the
    criteria also requires a C drive ("Total C Drive Space" above 0).
The script can be run again: an existing "OFF" tag keeps its notes and
systems (only its group is set), "Low-Space" is updated.

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 tags_off_low_space.py [--dry-run] [--run-criteria]
"""

import sys

from trellix_epo import Tag, TagCriteria, TagList
from epo_connection import connect, parser

GROUP = 'Policy Management'
OFF = Tag('OFF', 'Will be used to apply OFF policies on endpoints.', group=GROUP)
# Less than 2 GB free (the console stores the size in MB: 2048), on systems
# that have a C drive (the others report 0 MB free).
LOW_SPACE = Tag('Low-Space', 'Systems with less than 2 GB free on the C drive.',
                TagCriteria().add('Free C Drive Space', 'lt', '2 GB')
                             .add('Total C Drive Space', 'gt', 0),
                evaluate_on_asci=True, group=GROUP)


def setup_off(epo):
    """
    Creates the "OFF" tag, or moves the existing one to the group without
    changing its notes and systems.
    """
    existing = epo.tags.get(OFF.name)
    if existing is None:
        print('Tag created: {!r}'.format(epo.tags.create(OFF)))
    elif existing.group.lower() != GROUP.lower():
        print(epo.tags.move(OFF.name, GROUP))
    else:
        print('Tag "{}" already in "{}".'.format(OFF.name, GROUP))


def main():
    """
    Creates the group and the two tags (or, with --dry-run, writes the tag
    import file only).
    """
    args_parser = parser('Create the "OFF" and "Low-Space" tags in the "{}" tag group.'
                         .format(GROUP))
    args_parser.add_argument('--run-criteria', action='store_true',
                             help='evaluate the "Low-Space" criteria on all the systems now')
    args = args_parser.parse_args()
    for tag in (OFF, LOW_SPACE):
        tag.check()
    print('Low-Space criteria: {}'.format(LOW_SPACE.criteria.to_squid()))
    if args.dry_run:
        tags = TagList()
        tags.tags.extend([OFF, LOW_SPACE])
        with open('tags_off_low_space.xml', 'wb') as xml_file:
            xml_file.write(tags.get_xml_content())
        print('Dry run: saved tags_off_low_space.xml (the format of system.importTag)')
        return 0

    epo = connect(args)
    group = epo.tags.groups.create(GROUP)
    print('Tag group "{}" (id {}).'.format(group['path'], group['id']))
    setup_off(epo)
    print('Tag saved: {!r}'.format(epo.tags.save(LOW_SPACE)))
    if args.run_criteria:
        print('Low-Space criteria run: {} system(s) affected, tagged: {}'.format(
            epo.tags.run_criteria(LOW_SPACE.name), epo.tags.systems(LOW_SPACE.name)['tagged']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
