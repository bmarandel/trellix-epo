#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
agent_general_repository.py

Example for the trellix_epo package: load a McAfee Agent "General"
policy and a McAfee Agent "Repository" policy, read and adjust a few common
settings, and save the result.

Usage:
    python3 agent_general_repository.py <general_policy.xml> <repository_policy.xml>

Both files must be single-policy exports from the ePO Policy Catalog (the
same shape produced when extracting one policy from a Policies collection),
not a raw multi-policy export.
"""

import sys
import xml.etree.ElementTree as et

from trellix_epo import (
    TAPolicyGeneral,
    TAPolicyRepository,
    RepositoryList,
)


def load_policy(policy_class, file_path):
    """
    TAPolicyGeneral/Repository take their policy element directly
    at construction time (no optional default, unlike the ENS classes), so
    parse the file and pass the root explicitly instead of calling
    load_from_file() on an empty instance.
    """
    root = et.parse(file_path).getroot()
    return policy_class(root)


def main():
    if len(sys.argv) != 3:
        print('Usage: python3 agent_general_repository.py <general_policy.xml> '
              '<repository_policy.xml>', file=sys.stderr)
        return 1

    general = load_policy(TAPolicyGeneral, sys.argv[1])
    print('General policy "{}" from server {}'.format(
        general.get_name(), general.get_epo_server()))
    print('  Agent-to-server communication interval: {} minutes'.format(general.asci))
    print('  Policy enforcement interval: {} minutes'.format(
        general.policy_enforcement_interval))

    # Slow down both intervals a bit, as an example edit.
    general.asci = 30
    general.policy_enforcement_interval = 30
    general.save_to_file('general_updated.xml')
    print('  -> saved to general_updated.xml')

    repository = load_policy(TAPolicyRepository, sys.argv[2])
    print()
    print('Repository policy "{}"'.format(repository.get_name()))
    repo_list = RepositoryList(repository.get_site_list())
    print(repo_list)

    # Make sure the first repository is enabled and move it to the top, as an example edit.
    sites = repo_list.get_repo_list()
    if sites:
        first_site = sites[0][0]
        repo_list.enable(first_site)
        repo_list.move_top(first_site)
        repository.set_site_list(repo_list.get_repo_list())
        repository.save_to_file('repository_updated.xml')
        print('  -> saved to repository_updated.xml')

    return 0


if __name__ == '__main__':
    sys.exit(main())
