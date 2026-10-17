# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the packages of the ePO Main Repository and the
repositories (source and fallback sites, the Main Repository, distributed
repositories) as objects, without a server: Package and Repository, read
from the JSON of repository.findPackages and repository.find, and the
platform, language and branch codes they use.

>>> package = Package.from_json({'productID': 'ENDP_GS_1070',
...     'productName': 'Endpoint Security Platform', 'packageType': 'Install',
...     'productDetectionProductVersion': '26.8.0', 'buildNumber': '22584',
...     'packageBranch': 'Current', 'packageLangID': '0000',
...     'productDetectionPlatformID': 'WVSTS:6:1:0|WNT7W|WIN8W|WIN8S|WINXW|WINXS',
...     'checkinDate': '2026-10-17T10:30:05+02:00'})
>>> package
<Package Endpoint Security Platform 26.8.0 22584 (Install, Current, 0000)>
>>> package.build_version, package.platform_labels
('26.8.022584', ['Windows'])

The operations on a server (epo.repository: packages, check in, branch
change, delete, pull, replication) are in the eporepository module.
"""

import datetime

from .policies import Policy

# Target platforms of the Product Deployment page: check box label ->
# platform codes written in the platform attribute, in the order of the
# page script (updateSelectedPlatforms of deployment_task.jsp, agent
# extension 5.8.7). The packages use the same codes (and others, e.g. SCM).
PLATFORMS = {
    'Windows': 'WIN95|WIN98|WINME|WNTS|WNTW|WXPW|WXPS|WXPHE|WXPE|W2KS|W2KW|WVST|WVSTS|WNT7W|'
               'WIN8W|WIN8S|WINXW|WINXS',
    'Linux': 'LINUX',
    'Trellix Linux OS': 'MLOS',
    'SLOS': 'SLOS',
    'Wind River Linux': 'WRLNX',
    'Mac': 'MAC',
    'Solaris': 'SLR',
    'AIX': 'AIX',
    'HP-UX': 'HPUX|HPIA',
}

# Languages of the Product Deployment page (LangMap of deployment_task.jsp):
# code of the Language setting -> label. A package lists the codes it has.
LANGUAGES = {
    '0000': 'Language Neutral', '0401': 'Arabic', '0404': 'Chinese (Traditional)',
    '0405': 'Czech', '0406': 'Danish', '0407': 'German', '0408': 'Greek', '0409': 'English',
    '040a': 'Spanish', '040b': 'Finnish', '040c': 'French', '040d': 'Hebrew',
    '040e': 'Hungarian', '0410': 'Italian', '0411': 'Japanese', '0412': 'Korean',
    '0413': 'Dutch', '0414': 'Norwegian', '0415': 'Polish', '0416': 'Portuguese (Brazilian)',
    '0419': 'Russian', '041d': 'Swedish', '041f': 'Turkish', '0804': 'Chinese (Simplified)',
    '0816': 'Portuguese',
}

# Branches of the Main Repository (packageBranch, PackagePathType of the
# deployment tasks).
BRANCHES = ('Current', 'Previous', 'Evaluation')

# Package types of repository.findPackages -> label of the Main Repository
# page (Type column), when it differs.
TYPE_LABELS = {'Plugin': 'Plug-in'}


def platform_codes(text):
    """
    Returns the platform codes of a package (productDetectionPlatformID of
    repository.findPackages), without the minimum versions that some codes
    carry ("WVSTS:6:1:0" is WVSTS from version 6.1.0).

    >>> sorted(platform_codes('WVSTS:6:1:0|WNT7W|WINXS'))
    ['WINXS', 'WNT7W', 'WVSTS']
    """
    return {code.split(':', 1)[0] for code in (text or '').split('|') if code}


def check_branch(branch):
    """
    Checks a branch name of the Main Repository (the Web API takes these
    three names only).

    Valid / invalid (the case matters):

    >>> check_branch('Evaluation')
    >>> check_branch('current')
    Traceback (most recent call last):
    ...
    ValueError: Branch must be one of Current, Previous, Evaluation: 'current'.
    """
    if branch not in BRANCHES:
        raise ValueError('Branch must be one of {}: {!r}.'.format(', '.join(BRANCHES), branch))


def _date(text):
    """
    Returns the datetime of a date of the Web API ("2026-10-17T10:30:05+02:00"),
    or None.

    >>> _date('2026-10-17T10:30:05+02:00').isoformat()
    '2026-10-17T10:30:05+02:00'
    >>> _date(None) is None
    True
    """
    return datetime.datetime.fromisoformat(text) if text else None


class Package():
    """
    A package of the Main Repository (a line of Software > Main Repository):
    product, version and minor version, type, branch and language, as given
    by repository.findPackages (epo.repository.packages()).

    >>> Package('VSCANDAT1000', 'DAT', '11937.0000', package_type='DAT')
    <Package DAT 11937.0000 (DAT, Current, 0000)>
    """

    def __init__(self, product_id, name='', version='', minor_version='', package_type='Install',
                 branch='Current', language='0000', platforms='', checkin_date=None,
                 distribution='', dependency=None, conflicts=(), signer='', size=None, raw=None):
        """
        :param: product_id: The product id, e.g. ENDP_GS_1070.
        :param: name: The package name, e.g. Endpoint Security Platform.
        :param: version: The Version column (productDetectionProductVersion).
        :param: minor_version: The Minor Version column (buildNumber), e.g.
                               the build of an Install package; empty for
                               the DATs.
        :param: package_type: Install, DAT, Engine, Content, Update, Plugin...
        :param: branch: Current, Previous or Evaluation (None for the
                        ExtraDAT and SuperDAT entries, which are not
                        packages of the repository).
        :param: language: The language code (LANGUAGES), 0000 for Language
                          Neutral.
        :param: platforms: The platform codes of the package, as the Web API
                           gives them (productDetectionPlatformID).
        :param: checkin_date: The Check-In Date (datetime).
        :param: distribution: The Distribution Type (licensed, evaluation...).
        :param: dependency: The product id of the package it needs
                            (dependencyProductID), e.g. ENDP_GS_1070 for the
                            Endpoint Security Firewall.
        :param: conflicts: The packages it can't be deployed with
                           (conflictingPackageItems).
        :param: signer: The signer of the package (signerName).
        :param: size: The packageTotalSize of the Web API (the console
                      doesn't show it).
        :param: raw: The JSON of repository.findPackages, for the other fields.
        """
        self.product_id = product_id
        self.name = name or product_id
        self.version = version
        self.minor_version = minor_version
        self.package_type = package_type
        self.branch = branch
        self.language = language
        self.platform_text = platforms
        self.checkin_date = checkin_date
        self.distribution = distribution
        self.dependency = dependency
        self.conflicts = list(conflicts)
        self.signer = signer
        self.size = size
        self.raw = raw or {}

    @classmethod
    def from_json(cls, data):
        """
        Returns the package of a line of repository.findPackages.

        >>> Package.from_json({'productID': 'SIR_____1000', 'productName':
        ...     'System Information Reporter', 'productDetectionProductVersion': '1.0.3',
        ...     'buildNumber': '252', 'packageType': 'Install', 'packageBranch': 'Current',
        ...     'packageLangID': '0409'})
        <Package System Information Reporter 1.0.3 252 (Install, Current, 0409)>
        """
        size = data.get('packageTotalSize')
        return cls(data['productID'], data.get('productName') or '',
                   data.get('productDetectionProductVersion') or '',
                   data.get('buildNumber') or '', data.get('packageType') or '',
                   data.get('packageBranch'), data.get('packageLangID') or '0000',
                   data.get('productDetectionPlatformID') or '', _date(data.get('checkinDate')),
                   data.get('distributionType') or '', data.get('dependencyProductID'),
                   data.get('conflictingPackageItems') or (), data.get('signerName') or '',
                   int(size) if size and str(size).isdigit() else None, data)

    def __repr__(self):
        """
        Shows the name, the version and minor version, the type, the branch
        and the language.
        """
        version = ' '.join(item for item in (self.version, self.minor_version) if item)
        return '<Package {} {} ({}, {}, {})>'.format(self.name, version, self.package_type,
                                                     self.branch, self.language)

    def __eq__(self, other):
        """
        Two packages are equal when their product, type, branch, language,
        version and minor version are.
        """
        return isinstance(other, Package) and self.key == other.key and \
            (self.version, self.minor_version) == (other.version, other.minor_version)

    @property
    def key(self):
        """
        What tells a package from the others in the repository: (product id,
        type, branch, language). A branch has one version of a package.

        >>> Package('ENDP_GS_1070', branch='Evaluation').key
        ('ENDP_GS_1070', 'Install', 'Evaluation', '0000')
        """
        return self.product_id, self.package_type, self.branch, self.language

    @property
    def build_version(self):
        """
        The version as the Product Deployment tasks write it (BuildVersion):
        the version followed by the minor version, without a separator
        (checked on the lab: 1.0.3 build 252 is "1.0.3252").

        >>> Package('SIR_____1000', version='1.0.3', minor_version='252').build_version
        '1.0.3252'
        """
        return '{}{}'.format(self.version or '', self.minor_version or '')

    @property
    def platforms(self):
        """
        The platform codes of the package, without their minimum versions.

        >>> sorted(Package('A', platforms='LINUX|WVSTS:6:1:0').platforms)
        ['LINUX', 'WVSTS']
        """
        return platform_codes(self.platform_text)

    @property
    def platform_labels(self):
        """
        The target platforms of the Product Deployment page (labels of
        PLATFORMS) the package is made for: those with one of its codes.

        >>> Package('A', platforms='MAC|LINUX|WINXS').platform_labels
        ['Windows', 'Linux', 'Mac']
        """
        codes = self.platforms
        return [label for label, family in PLATFORMS.items() if set(family.split('|')) & codes]

    @property
    def placeholder(self):
        """
        True for the ExtraDAT and SuperDAT entries of repository.findPackages:
        no branch and no check-in date, not listed on the Main Repository
        page (they stand for the /extradat and /superdat check-in options).

        >>> Package('EXTRADAT1000', package_type='DAT', branch=None).placeholder
        True
        """
        return self.branch is None and self.checkin_date is None

    @property
    def type_label(self):
        """
        The Type column of the Main Repository page (Plug-in for Plugin).

        >>> Package('EPOAGENT3000META', package_type='Plugin').type_label
        'Plug-in'
        """
        return TYPE_LABELS.get(self.package_type, self.package_type)

    def md_row(self):
        """
        Returns the columns of the Main Repository page: Name, Type, Version,
        Minor Version, Check-In Date, Distribution Type, Branch, plus the
        product id and the language.

        >>> Package('ENDP_GS_1070', 'Endpoint Security Platform', '26.8.0', '22584',
        ...         distribution='licensed').md_row()
        ['Endpoint Security Platform', 'Install', '26.8.0', '22584', '', 'Licensed', 'Current', 'ENDP\\\\_GS\\\\_1070', 'Language Neutral']
        """
        date = self.checkin_date.strftime('%Y-%m-%d %H:%M') if self.checkin_date else ''
        return [Policy.md_escape(value) for value in (
            self.name, self.type_label, self.version, self.minor_version, date,
            self.distribution.capitalize(), self.branch or '', self.product_id,
            LANGUAGES.get(self.language, self.language))]


def packages_to_markdown(packages, title='Main Repository'):
    """
    Returns the packages as a Markdown table with the columns of the Main
    Repository page, sorted by name as the page.

    >>> print(packages_to_markdown([Package('VSCANDAT1000', 'DAT', '11937.0000',
    ...                                     package_type='DAT')]))
    # Main Repository
    <BLANKLINE>
    | Name | Type | Version | Minor Version | Check-In Date | Distribution Type | Branch | Product ID | Language |
    |---|---|---|---|---|---|---|---|---|
    | DAT | DAT | 11937.0000 |  |  |  | Current | VSCANDAT1000 | Language Neutral |
    """
    lines = ['# ' + Policy.md_heading(title), '',
             '| Name | Type | Version | Minor Version | Check-In Date | Distribution Type | '
             'Branch | Product ID | Language |', '|---|---|---|---|---|---|---|---|---|']
    for package in sorted(packages, key=lambda item: (item.name.lower(), item.branch or '')):
        lines.append('| ' + ' | '.join(package.md_row()) + ' |')
    return '\n'.join(lines)


class Repository():
    """
    A repository of repository.find: a source site (mirror), the fallback
    site, the Main Repository of the server (master) or a distributed
    repository. The passwords are never read (the server gives them
    encrypted or empty).

    >>> Repository.from_json({'repositoryName': 'Trellix HTTPS', 'repositoryTypeString':
    ...     'fallback', 'protocolString': 'HttpSite', 'location':
    ...     'update.nai.com/Products/CommonUpdater', 'repositoryPort': 80,
    ...     'secureRepositoryPort': 443, 'enabled': True})
    <Repository Trellix HTTPS (fallback, HTTP): update.nai.com/Products/CommonUpdater>
    """

    # protocolString of repository.find -> protocol of the console.
    PROTOCOLS = {'HttpSite': 'HTTP', 'FtpSite': 'FTP', 'UNCSite': 'UNC', 'SpipeSite': 'SPIPE',
                 'LocalSite': 'Local'}

    def __init__(self, name, kind='', protocol='', location='', port=None, secure_port=None,
                 enabled=True, user='', domain='', include_all_software=True,
                 inclusions=(), exclusions=(), raw=None):
        """
        :param: name: The repository name (repositoryName, the sourceRepository
                      of repository.pull for a source site).
        :param: kind: mirror (source site), fallback, master (Main
                      Repository) or the kind of a distributed repository
                      (repositoryTypeString).
        :param: protocol: HTTP, FTP, UNC, SPIPE... (see PROTOCOLS).
        :param: location: The server and path, or the UNC path.
        :param: port: The port (repositoryPort).
        :param: secure_port: The HTTPS port (secureRepositoryPort, 0 when none).
        :param: enabled: The repository is enabled.
        :param: user: The download user name.
        :param: domain: The domain of the download user.
        :param: include_all_software: All the packages are replicated.
        :param: inclusions: The packages replicated when not all.
        :param: exclusions: The packages not replicated.
        :param: raw: The JSON of repository.find, for the other fields.
        """
        self.name = name
        self.kind = kind
        self.protocol = protocol
        self.location = location
        self.port = port
        self.secure_port = secure_port
        self.enabled = enabled
        self.user = user
        self.domain = domain
        self.include_all_software = include_all_software
        self.inclusions = list(inclusions)
        self.exclusions = list(exclusions)
        self.raw = raw or {}

    @classmethod
    def from_json(cls, data):
        """
        Returns the repository of a line of repository.find.
        """
        protocol = data.get('protocolString') or ''
        return cls(data.get('repositoryName') or data.get('repositoryId') or '',
                   data.get('repositoryTypeString') or '',
                   cls.PROTOCOLS.get(protocol, protocol), data.get('location') or '',
                   data.get('repositoryPort'), data.get('secureRepositoryPort'),
                   bool(data.get('enabled')), data.get('downloadCredUsername') or '',
                   data.get('downloadCredDomain') or '',
                   data.get('includeAllSoftware') is not False,
                   data.get('softwareInclusionList') or (),
                   data.get('softwareExclusionList') or (), data)

    def __repr__(self):
        """
        Shows the name, the kind, the protocol and the location.
        """
        return '<Repository {} ({}, {}): {}>'.format(self.name, self.kind, self.protocol,
                                                     self.location)
