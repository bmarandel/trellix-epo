#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
client_tasks_ens_deployment.py

Example for the trellix_epo package: the Trellix Agent "Product Deployment"
client task that installs Endpoint Security (ENS) on Windows, built from the
packages of the master repository and imported into the ePO Client Task
Catalog with the Web API.

The default modules are those of a usual ENS deployment: Endpoint Security
Platform, Threat Prevention, Adaptive Threat Protection, Firewall and Web
Control (--modules to choose them; Storage Protection is also available).
A module needs the module it depends on in the repository
(Package.dependency: Platform for Threat Prevention, Firewall and Web
Control, Threat Prevention for Adaptive Threat Protection and Storage
Protection): it is added when missing. Each line takes the version of the
package in the branch (--branch, Current by default, read with
epo.repository.packages()), so the task can't point to a version that is
no longer in the repository.

Run the script again after a new ENS version is checked in: the task of the
same name is replaced with the new versions and keeps its id, its
assignments and its schedules. That's why the default name has no version:
with a version in the name (--name "Install ENS 26.8"), the next version
gives a new task, to assign again.

The task is checked against the server before the import (check_server():
packages in the repository and made for Windows). With --run, the task runs
now on the systems (clienttask.run, "Run Client Task Now").

Usage:
    export EPO_URL=https://epo.example.com:8443 EPO_USER=admin
    python3 client_tasks_ens_deployment.py [--name "Install ENS"] [--branch Current] \\
        [--modules platform,threat-prevention,firewall] [--run W10ENTB01] [--dry-run]
"""

import sys

from trellix_epo import ClientTaskList, DeploymentItem, TADeploymentTask
from epo_connection import connect, parser

# ENS modules for Windows: option name -> product id of the package, in the
# order of the task lines (the Platform first).
MODULES = {
    'platform': 'ENDP_GS_1070',
    'threat-prevention': 'ENDP_AM_1070',
    'adaptive-threat-protection': 'ENDPATP_1070',
    'firewall': 'ENDP_FW_1070',
    'web-control': 'ENDP_WP_1070',
    'storage-protection': 'ENDP_SP_2000',
}
DEFAULT_MODULES = 'platform,threat-prevention,adaptive-threat-protection,firewall,web-control'


def find_packages(epo, branch, product_ids):
    """
    Returns the Install packages (Package) of the branch for the product
    ids, with the modules they depend on, in the order of MODULES: {product
    id: package}. A package of several languages is taken Language Neutral
    (0000) first.

    :raise: ValueError: A module (or a module it depends on) has no package
                        in the branch.
    """
    found = {}
    for package in epo.repository.packages(branch=branch, package_type='Install'):
        if package.product_id not in MODULES.values():
            continue
        current = found.get(package.product_id)
        if current is None or (current.language != '0000' and package.language == '0000'):
            found[package.product_id] = package
    wanted = list(product_ids)
    for product_id in wanted:
        if product_id not in found:
            raise ValueError('No {} package in the {} branch.'.format(product_id, branch))
        dependency = found[product_id].dependency
        if dependency and dependency not in wanted:
            print('Adding {}: {} depends on it.'.format(dependency, product_id))
            wanted.append(dependency)
    return {product_id: found[product_id] for product_id in MODULES.values()
            if product_id in wanted}


def build_task(name, packages):
    """
    Returns the Product Deployment task of the packages (Windows, no
    postpone, as created in the console).
    """
    platform = packages.get(MODULES['platform'])
    version = '{} build {}'.format(platform.version, platform.minor_version) if platform else ''
    return TADeploymentTask(name, [DeploymentItem.from_package(package)
                                   for package in packages.values()],
                            description='Endpoint Security {}: {}.'.format(
                                version, ', '.join(package.name for package in packages.values())))


def main():
    """
    Creates the ENS deployment task.
    """
    args_parser = parser('Create the client task that deploys Endpoint Security on Windows.')
    args_parser.add_argument('--name', default='Install ENS', help='task name')
    args_parser.add_argument('--branch', default='Current', choices=('Current', 'Previous',
                                                                     'Evaluation'),
                             help='repository branch of the packages')
    args_parser.add_argument('--modules', default=DEFAULT_MODULES,
                             help='modules (comma separated) among ' + ', '.join(MODULES))
    args_parser.add_argument('--run', help='systems (comma separated) to deploy on now')
    args_parser.add_argument('--output', default='client_tasks.xml', help='file to write')
    args = args_parser.parse_args()
    modules = [module.strip() for module in args.modules.split(',') if module.strip()]
    unknown = [module for module in modules if module not in MODULES]
    if unknown:
        args_parser.error('Unknown module(s): {}.'.format(', '.join(unknown)))
    epo = connect(args)

    try:
        packages = find_packages(epo, args.branch, [MODULES[module] for module in modules])
        tasks = ClientTaskList()
        tasks.add(build_task(args.name, packages))
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
