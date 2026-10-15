# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class TAPolicyRepository and RepositoryList.
"""

import xml.etree.ElementTree as et
from ..policies import Policy
from .markdown import MD_PRODUCT, labelled

class TAPolicyRepository(Policy):
    """
    The TAPolicyRepository class can be used to edit the McAfee Agent policy: Repository.
    """

    def __init__(self, policy_from_mcafeeagentpolicies):
        super(TAPolicyRepository, self).__init__(policy_from_mcafeeagentpolicies)
        if self.get_type() != 'Repository':
            raise ValueError('Wrong McAfee Agent policy. Policy type must be "Repository".')

    def __repr__(self):
        name = self.get_name()
        epo = self.get_epo_server()
        return '<TAPolicyRepository for policy {} from server {}.>'.format(name, epo)

    def get_site_list(self):
        """
        Get a table (list of list) of sites within the Repository policy
        """
        sites = self.get_indexed_list('InetManager', 'SitelistOrderNum', 'SitelistOrder_{}')
        if sites is None:
            return None
        disabled_sites = self.get_indexed_list('InetManager', 'DisabledSiteNum', 'DisabledSites_{}')
        table = []
        for site in sites:
            state = 'Disabled' if disabled_sites and site in disabled_sites else 'Enabled'
            table.append([site, state])
        return table

    def set_site_list(self, table):
        """
        Set a table (list of list) of sites within the Repository policy
        """
        disabled_sites = [row[0] for row in table if row[1] == 'Disabled']
        success = self.set_indexed_list('InetManager', 'DisabledSiteNum',
                                        'DisabledSites_{}', disabled_sites)
        sites = [row[0] for row in table]
        return self.set_indexed_list('InetManager', 'SitelistOrderNum',
                                     'SitelistOrder_{}', sites) and success

    # ------------------------------ Markdown export ------------------------------
    # One section per console tab (Repositories, Proxy), with the labels of
    # the ePO 5.10 console (Trellix Agent > Repository). See Policy.to_markdown().
    MD_PRODUCT = MD_PRODUCT
    MD_CATEGORY = 'Repository'
    LIST_SELECTION = {'1': 'Use this repository list', '0': 'Use other repository list'}
    SELECT_BY = {'0': 'Ping time', '1': 'Subnet distance', '2': 'Use order in repository list'}
    PROXY_TYPES = {'0': 'Do not use a proxy',
                   '1': 'Use Internet Explorer settings (For Windows) / System Preferences '
                        'settings (For Mac OSX) / System environment variables (For Linux)',
                   '2': 'Manually configure the proxy settings'}

    def __md(self, setting, section='ProxySettings'):
        return self.get_setting_value(section, setting)

    def __md_repositories(self):
        method = self.__md('uiFindNearestMethod', 'Advanced')
        text = '### Repository list selection\n\n' + self.md_settings([
            ['Repository list selection',
             labelled(self.__md('OverwriteClientSites', 'Advanced'), self.LIST_SELECTION)]])
        rows = [['Select repository by', labelled(method, self.SELECT_BY)]]
        if method == '0':
            rows.append(['Ping timeout (seconds)', self.__md('nMaxPingTimeout', 'Advanced')])
        elif method == '1':
            rows.append(['Maximum number of hops', self.__md('nMaxHopLimit', 'Advanced')])
        text += '\n### Select repository by\n\n' + self.md_settings(rows)
        # The Type column of the console (Global, Fallback...) comes from the
        # ePO server, not from the policy.
        text += '\n### Repository list\n\n' + self.md_settings([
            ['Automatically allow clients to access newly-added repositories',
             self.md_check(self.__md('includeReposByDefault', 'InetManager'))]])
        text += '\n' + self.md_table(['Name', 'State'], self.get_site_list() or [],
                                     numbered=True)
        return text

    def __md_proxy(self):
        proxy_type = self.__md('uiUseProxyType')
        rows = [['Proxy settings', labelled(proxy_type, self.PROXY_TYPES)]]
        if proxy_type == '1':
            rows.append(['Allow user to configure proxy settings',
                         self.md_check(self.__md('bAllowUserToConfigureProxy'))])
        if proxy_type == '2':
            single = self.__md('bUseSingleProxySettings')
            rows += [['HTTP address', self.__md('szHttpProxyServer')],
                     ['HTTP port', self.__md('uiHttpProxyPort')],
                     ['Use these settings for all proxy types', self.md_check(single)]]
            if single != '1':
                rows += [['FTP address', self.__md('szFtpProxyServer')],
                         ['FTP port', self.__md('uiFtpProxyPort')]]
            exceptions = [value for name, value in self.__settings('ProxySettings')
                          if 'Exception' in name and name != 'uiNumExceptions' and value]
            rows += [['Specify exceptions', self.md_check(self.__md('bBypassLocalAddress'))],
                     ['Exceptions', '; '.join(exceptions)]]
        # The passwords are never written: only whether one is set.
        for kind in ['Http', 'Ftp']:
            label = 'HTTP' if kind == 'Http' else 'FTP'
            enabled = self.__md('bUse{}Authentication'.format(kind))
            rows.append(['Use {} proxy authentication'.format(label), self.md_check(enabled)])
            if enabled == '1':
                password = self.__md('sz{}ProxyPassword'.format(kind)) or \
                    self.__md('256_sz{}ProxyPassword'.format(kind))
                rows += [['{} user name'.format(label), self.__md('sz{}ProxyUser'.format(kind))],
                         ['{} password'.format(label), 'Set' if password else 'Not set']]
        return '### Proxy settings\n\n' + self.md_settings(rows)

    def __settings(self, section):
        section_obj = self.root.find('.//Section[@name="{}"]'.format(section))
        if section_obj is None:
            return []
        return [(setting.get('name'), setting.get('value')) for setting in section_obj]

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        return [('Repositories', self.__md_repositories()), ('Proxy', self.__md_proxy())]


class RepositoryList():
    """
    The RepositoryList class can be used to edit the repository list from the policy.
    """

    def __init__(self, repository_list=None):
        if repository_list is None:
            self.repo_list = []
        else:
            self.repo_list = repository_list
        self.__update_index__()

    def __repr__(self):
        return '<RepositoryList which contains {} site(s)>'.format(len(self.repo_list))

    def __str__(self):
        txt = '| {0:5} | {1:25}| {2:9}|\n'.format('Order', 'Name', 'State')
        txt += '|------:|:-------------------------|:---------|'
        for index, row in enumerate(self.repo_list):
            txt += '\n| {0:5} | {1:25}| {2:9}|'.format(index, row[0], row[1])
        return txt

    def __update_index__(self):
        self.repo_index = [r[0] for r in self.repo_list]
    
    def is_empty(self):
        """
        Return True if the RepositoryList is empty.
        """
        return self.repo_list.count(0) == 0

    def add(self, site_name, state='Disabled'):
        """
        Add a site with its state to the RepositoryList
        """
        self.repo_list.append([site_name, state])
        self.__update_index__()

    def remove(self, site_name):
        """
        Remove a site with its state to the RepositoryList
        """
        row_index = self.repo_index.index(site_name)
        self.repo_list.pop(row_index)
        self.__update_index__()

    def index(self, site_name):
        """
        Return the current index of the site within the RepositoryList
        """
        try:
            return self.repo_index.index(site_name)
        except ValueError:
            return -1

    def contain(self, site_name):
        """
        Return True if the RepositoryList contains the site
        """
        index = self.repo_index.index(site_name)
        return index > -1

    def state(self, site_name):
        """
        Return the current state of the site
        """
        return self.repo_list[self.repo_index.index(site_name)][1]

    def set_repo_list(self, table):
        """
        Set the list of repositories
        """
        self.repo_list = table
        self.__update_index__()

    def get_repo_list(self):
        """
        Get the list of repositories
        """
        return self.repo_list

    def enable(self, site_name):
        """
        Enable a repository site based on his name
        """
        self.repo_list[self.repo_index.index(site_name)][1] = 'Enabled'

    def disable(self, site_name):
        """
        Disable a repository site based on his name
        """
        self.repo_list[self.repo_index.index(site_name)][1] = 'Disabled'

    def move_at(self, site_name, new_index):
        """
        Move a site to a soecific index
        """
        row_index = self.repo_index.index(site_name)
        if new_index in range(len(self.repo_list)+1):
            self.repo_list.insert(new_index, self.repo_list.pop(row_index))
            self.__update_index__()

    def move_up(self, site_name):
        """
        Move Up a site
        """
        row_index = self.repo_index.index(site_name)
        if row_index in range(1, len(self.repo_list)+1):
            self.repo_list.insert(row_index-1, self.repo_list.pop(row_index))
            self.__update_index__()

    def move_down(self, site_name):
        """
        Move Down a site
        """
        row_index = self.repo_index.index(site_name)
        if row_index in range(len(self.repo_list)):
            self.repo_list.insert(row_index+1, self.repo_list.pop(row_index))
            self.__update_index__()

    def move_top(self, site_name):
        """
        Move at the top a repository site based on his name
        """
        self.move_at(site_name, 0)

    def move_bottom(self, site_name):
        """
        Move at the bottom a repository site based on his name
        """
        self.move_at(site_name, len(self.repo_list))
