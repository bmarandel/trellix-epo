# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPORepository, the repository operations of EPOClient
(epo.repository): the packages of the Main Repository, check in, branch
change and delete of a package, pull from a source site, replication to
the distributed repositories, and the repositories themselves
(repository.* and RepositoryMgmt.* commands).

    epo.repository.packages(branch='Current', package_type='Install')   # [Package...]
    platform = epo.repository.get('ENDP_GS_1070')
    epo.repository.check_in('ENS_26.8.0.zip', branch='Evaluation')
    epo.repository.change_branch(platform, 'Previous')
    epo.repository.pull('Trellix HTTPS', ['AMCORDAT2000'])

The package operations work as Software > Main Repository and the
repository ones as Configuration > Server Settings > Source Sites and
Distributed Repositories.

Server behaviours handled here (checked on ePO 5.10 Update 7 with the
Stinger package and a pull from "Trellix HTTPS"):
- check in, branch change and delete answer "true" (returned as True);
  check_in() without force raises EPOError "This package already exists
  in the Main Repository and was not overwritten.", delete() of a package
  not in the branch "the server was unable to find package ...";
- repository.changeBranch doesn't check packageVersion and
  packageMinorVersion (a wrong version copies the package too): the
  package of the source branch is copied or moved;
- repository.pull is synchronous and answers "success" with an "updated:
  <branch>\\<product>\\<version>\\<type>\\<language>" line per package;
  an unknown product id gives "success" alone (pull() returns the updated
  packages: [] then); an unknown site raises "Invalid source site was
  specified.";
- repository.replicate without a distributed repository raises "Not
  enough repository sites";
- repository.importRepositories skips a site of the same name without
  overwrite ("skipped (conflict): <name>").
"""

import os
import re

from .epo import EPOError
from .repository import AGENT_PACKAGES, Package, Repository, check_branch

# Options of repository.checkInPackage for the DAT packages of a SuperDAT
# or ExtraDAT file.
CHECK_IN_OPTIONS = ('superdat', 'extradat')
# Kinds of repositories of importRepositories.
REPOSITORY_TYPES = ('source', 'distributed')


def _done(answer):
    """
    Returns True for the "true" answer of the package commands (check in,
    branch change, delete), else the answer.

    >>> _done('true'), _done(True), _done('other')
    (True, True, 'other')
    """
    if answer is True or (isinstance(answer, str) and answer.strip().lower() == 'true'):
        return True
    return answer


def _package(package, package_type=None, branch=None):
    """
    Returns (product id, package type, branch) of a Package, or of a product
    id with its package type and branch.

    >>> _package(Package('ENDP_GS_1070', branch='Evaluation'))
    ('ENDP_GS_1070', 'Install', 'Evaluation')
    >>> _package('VSCANDAT1000', 'DAT', 'Previous')
    ('VSCANDAT1000', 'DAT', 'Previous')
    >>> _package('VSCANDAT1000')
    Traceback (most recent call last):
    ...
    ValueError: Give a Package, or the product id with its package type and branch.
    """
    if isinstance(package, Package):
        return package.product_id, package.package_type, package.branch
    if not package or not package_type or not branch:
        raise ValueError('Give a Package, or the product id with its package type and branch.')
    return package, package_type, branch


class EPORepository():
    """
    The repository operations of an EPOClient (epo.repository).
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPORepository of {!r}>'.format(self.epo)

    # ------------------------------ Packages ------------------------------
    def packages(self, search_text='', branch=None, package_type=None, product_id=None,
                 include_placeholders=False):
        """
        Returns the packages of the Main Repository (repository.findPackages)
        as Package objects, as the Main Repository page lists them.

        :param: search_text: Text of the name or product id (no wildcard).
        :param: branch: Current, Previous or Evaluation to keep one branch.
        :param: package_type: Install, DAT, Engine, Content, Update,
                              Plugin... to keep one type.
        :param: product_id: A product id to keep its packages only.
        :param: include_placeholders: Also return the ExtraDAT and SuperDAT
                                      entries (no branch, not on the page).
        """
        if branch is not None:
            check_branch(branch)
        packages = [Package.from_json(item)
                    for item in self.epo.call('repository.findPackages', searchText=search_text)]
        return [package for package in packages
                if (include_placeholders or not package.placeholder) and
                branch in (None, package.branch) and
                package_type in (None, package.package_type) and
                product_id in (None, package.product_id)]

    def get(self, product_id, branch='Current', package_type='Install', language=None):
        """
        Returns the package of a product in a branch, or None.

        :param: product_id: The product id, e.g. ENDP_GS_1070.
        :param: branch: The branch.
        :param: package_type: The package type (Install by default).
        :param: language: The language code when the package has several
                          (e.g. 0409).
        :raise: EPOError: Several languages of the package are in the
                          branch: give the language.
        """
        found = [package for package in self.packages(product_id, branch, package_type, product_id)
                 if language in (None, package.language)]
        if len(found) > 1:
            raise EPOError('repository.findPackages', '{} is in the {} branch in several '
                           'languages ({}): give the language.'.format(
                               product_id, branch, ', '.join(p.language for p in found)))
        return found[0] if found else None

    def agent_package(self, package='Windows', branch='Current'):
        """
        Returns an Install package of the Trellix Agent, as the "Agent
        version" lists of the console offer them (agent deployment,
        deployment URL, custom install package): the package of a platform
        in a branch, or the package of a repository path.

        Example: epo.repository.agent_package('Linux').deployment_path gives
        'Current/EPOAGENT3700LYNX/Install/0409'.

        :param: package: Windows, Linux or Mac, a repository path
                         ("Current/EPOAGENT3000/Install/0409", / or \\), or
                         a Package (checked).
        :param: branch: Current, Previous or Evaluation (for a platform).
        :raise: ValueError: Unknown platform or path, not an agent Install
                            package, or no agent package of the platform in
                            the branch.
        """
        if isinstance(package, Package):
            if package.agent_platform is None:
                raise ValueError('Not an Install package of the Trellix Agent: {!r}.'.format(
                    package))
            return package
        text = str(package)
        if '/' in text or '\\' in text:
            path = text.replace('\\', '/').strip('/').lower()
            found = [item for item in self.packages(package_type='Install')
                     if item.agent_platform and item.deployment_path.lower() == path]
            if not found:
                raise ValueError('No Trellix Agent package at {} in the repository.'.format(text))
            return found[0]
        products = {label.lower(): product for product, label in AGENT_PACKAGES.items()}
        if text.lower() not in products:
            raise ValueError('The agent platform must be one of {}: {!r}.'.format(
                ', '.join(AGENT_PACKAGES.values()), package))
        found = self.get(products[text.lower()], branch)
        if found is None:
            raise ValueError('No Trellix Agent package for {} in the {} branch.'.format(
                package, branch))
        return found

    def check_in(self, file_path, branch='Current', option=None, force=True, server_path=False):
        """
        Checks a package (a ZIP file) into the Main Repository
        (repository.checkInPackage, "Check In Package" of the page). A
        package already in the branch is replaced (force).

        :param: file_path: The ZIP file to upload, or with server_path a path
                           on the ePO server (e.g. "C:\\Packages\\X.zip").
        :param: branch: Current, Previous or Evaluation.
        :param: option: superdat or extradat for the DATs of a SuperDAT or
                        ExtraDAT file, None for a package.
        :param: force: Replace a package already in the branch.
        :param: server_path: file_path is a path on the ePO server.
        :return: True once the package is checked in.
        :raise: EPOError: The package is in the branch and force is False.
        """
        check_branch(branch)
        if option is not None and option not in CHECK_IN_OPTIONS:
            raise ValueError('Option must be one of {}: {!r}.'.format(', '.join(CHECK_IN_OPTIONS),
                                                                     option))
        params = {'branch': branch, 'option': '/' + option if option else None, 'force': force}
        if server_path:
            return _done(self.epo.call('repository.checkInPackage', packageLocation=file_path,
                                       **params))
        with open(file_path, 'rb') as package_file:
            content = package_file.read()
        return _done(self.epo.call('repository.checkInPackage',
                                   files={'file': (os.path.basename(file_path), content)},
                                   **params))

    def change_branch(self, package, target_branch, move=False):
        """
        Copies or moves a package to another branch (repository.changeBranch,
        "Change Branch" of the page).

        :param: package: The Package (epo.repository.get()).
        :param: target_branch: Current, Previous or Evaluation.
        :param: move: Remove the package from its branch (copy by default).
        :return: True once the package is copied or moved (a package of the
                 target branch is replaced).
        """
        check_branch(target_branch)
        if not isinstance(package, Package):
            raise ValueError('Give the Package (epo.repository.get()).')
        if target_branch == package.branch:
            raise ValueError('{} is already in the {} branch.'.format(package.name,
                                                                     target_branch))
        return _done(self.epo.call('repository.changeBranch', productId=package.product_id,
                                   packageType=package.package_type, sourceBranch=package.branch,
                                   targetBranch=target_branch, packageVersion=package.version,
                                   packageMinorVersion=package.minor_version, move=move))

    def delete(self, package, package_type=None, branch=None):
        """
        Deletes a package from a branch of the Main Repository
        (repository.deletePackage).

        :param: package: The Package, or its product id with package_type
                         and branch.
        :return: True once the package is deleted.
        :raise: EPOError: The package is not in the branch.
        """
        product_id, package_type, branch = _package(package, package_type, branch)
        check_branch(branch)
        return _done(self.epo.call('repository.deletePackage', productId=product_id,
                                   packageType=package_type, branch=branch))

    def pull(self, source, products, branch='Current', move_to_previous=False):
        """
        Pulls packages from a source site into the Main Repository
        (repository.pull, "Pull Now" of the page).

        :param: source: The source site name (Repository.name of a mirror
                        or fallback site, case sensitive), e.g. "Trellix HTTPS".
        :param: products: The product ids to pull (list or comma separated
                          text).
        :param: branch: Current, Previous or Evaluation.
        :param: move_to_previous: Move the package of the branch to Previous
                                  before (Current only in the console).
        :return: The packages updated, as the server lists them:
                 "<branch>\\<product id>\\<version>\\<type>\\<language>"
                 ([] when nothing was pulled, e.g. an unknown product id).
        :raise: EPOError: Unknown source site.
        """
        check_branch(branch)
        products = [products] if isinstance(products, str) else list(products)
        products = ','.join(item.strip() for item in products if item.strip())
        if not products:
            raise ValueError('At least one product id is required.')
        answer = self.epo.call('repository.pull', sourceRepository=source, targetBranch=branch,
                               moveToPrevious=move_to_previous, productList=products)
        return re.findall(r'^updated:\s*(.+?)\s*$', answer, re.MULTILINE)

    def replicate(self, repositories=None, incremental=None):
        """
        Replicates the Main Repository to the distributed repositories
        (repository.replicate, "Replicate Now").

        :param: repositories: The distributed repository names (all when None).
        :param: incremental: True for an incremental replication, False for
                             a full one (server default when None).
        :return: The server answer.
        :raise: EPOError: No distributed repository ("Not enough repository
                          sites").
        """
        if repositories is not None and not isinstance(repositories, str):
            repositories = '|'.join(repositories)
        return self.epo.call('repository.replicate', repositoryList=repositories,
                             incremental=incremental)

    # ------------------------------ Repositories ------------------------------
    def repositories(self, search_text='', kind=None):
        """
        Returns the repositories (repository.find) as Repository objects:
        source sites (mirror), fallback site, Main Repository (master) and
        distributed repositories.

        :param: search_text: Text of the name (no wildcard).
        :param: kind: mirror, fallback, master... to keep one kind.
        """
        return [repository for repository in
                (Repository.from_json(item)
                 for item in self.epo.call('repository.find', searchText=search_text))
                if kind in (None, repository.kind)]

    def export_sites(self):
        """
        Returns the source and fallback sites as a site list (repository.export,
        the XML of "Export Sitelist"; passwords encrypted).
        """
        return self.epo.call('repository.export', output='terse').strip()

    def import_sites(self, xml, repository_type='source', overwrite=False,
                     file_name='SiteList.xml'):
        """
        Imports source sites or distributed repositories from a site list
        (repository.importRepositories).

        :param: xml: The site list (text or bytes), e.g. from export_sites().
        :param: repository_type: source or distributed.
        :param: overwrite: Replace a repository of the same name.
        :return: The lines of the answer after "success", e.g. "skipped
                 (conflict): Local Source" for a site of the same name
                 without overwrite.
        """
        if repository_type not in REPOSITORY_TYPES:
            raise ValueError('Repository type must be one of {}: {!r}.'.format(
                ', '.join(REPOSITORY_TYPES), repository_type))
        content = xml.encode('utf-8') if isinstance(xml, str) else xml
        answer = self.epo.call('repository.importRepositories',
                               files={'file': (file_name, content)},
                               repositoryType=repository_type, overwrite=overwrite)
        return [line.strip() for line in answer.splitlines()
                if line.strip() and line.strip() != 'success']

    def create_http_repository(self, name, url, unc_path, download_user, download_password,
                               upload_user, upload_password, inclusions=None, exclusions=None,
                               secure_port=None, certificate_id=None):
        """
        Creates an HTTP distributed repository (RepositoryMgmt.createHttpRepository):
        the agents download from the URL, the server replicates to the UNC path.

        :param: name: The repository name.
        :param: url: The server and path the agents use.
        :param: unc_path: The share the server replicates to.
        :param: download_user, download_password: The account of the agents.
        :param: upload_user, upload_password: The account of the replication.
        :param: inclusions: The packages to replicate (all when None).
        :param: exclusions: The packages not to replicate.
        :param: secure_port: The HTTPS port.
        :param: certificate_id: The id of the repository certificate.
        :return: The server answer.
        """
        return self.epo.call('RepositoryMgmt.createHttpRepository', name=name, url=url,
                             uncPath=unc_path, downloadUser=download_user,
                             downloadPassword=download_password, uploadUser=upload_user,
                             uploadPassword=upload_password,
                             softwareInclusionList=_list(inclusions),
                             softwareExclusionList=_list(exclusions),
                             secureRepositoryPort=secure_port,
                             repositoryCertificateId=certificate_id)

    def create_unc_repository(self, name, unc_path, download_user, download_password,
                              upload_user, upload_password, inclusions=None, exclusions=None):
        """
        Creates a UNC distributed repository (RepositoryMgmt.createUncRepository).

        :param: name: The repository name.
        :param: unc_path: The share of the repository.
        :param: download_user, download_password: The account of the agents.
        :param: upload_user, upload_password: The account of the replication.
        :param: inclusions: The packages to replicate (all when None).
        :param: exclusions: The packages not to replicate.
        :return: The server answer.
        """
        return self.epo.call('RepositoryMgmt.createUncRepository', name=name, uncPath=unc_path,
                             downloadUser=download_user, downloadPassword=download_password,
                             uploadUser=upload_user, uploadPassword=upload_password,
                             softwareInclusionList=_list(inclusions),
                             softwareExclusionList=_list(exclusions))


def _list(items):
    """
    Returns a list parameter of RepositoryMgmt (comma separated), or None.

    >>> _list(['ENDP_GS_1070', 'ENDP_AM_1070']), _list(None)
    ('ENDP_GS_1070,ENDP_AM_1070', None)
    """
    if items is None or isinstance(items, str):
        return items
    return ','.join(items)
