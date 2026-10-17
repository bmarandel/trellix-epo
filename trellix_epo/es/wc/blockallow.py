# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes ESWCPolicyBlockAllowList (Endpoint Security
Web Control: Block and Allow List) and WCSite.

Storage learnt from a test policy changed in the ePO 5.10 console: section
BlockAndAllowList, uiSiteCount and for each site szSite<n> and
szUnicodeSite<n> (both the pattern as typed, internationalized domain names
included), Action<n> ('0' Allow, '1' Block) and szNote<n>; uiSiteResourceFileDownload holds the rating actions of the file
downloads from allowed sites (see RatingActions).
"""

import re

from .common import ESWCPolicy
from ...validators import check_length, is_wc_site_pattern


class WCSite():
    """
    A site of the Block and Allow List.

    :param: pattern: Site pattern (at least 3 characters, no *, \\, <, >,
                     space or comma, see is_wc_site_pattern), e.g.
                     'example.com' or 'www.example.com/path'. Surrounding
                     white spaces are removed, as the server does.
    :param: action: WCSite.ALLOW ('0') or WCSite.BLOCK ('1').
    :param: note: Notes (50 characters max, trimmed as by the server).
    """
    ALLOW, BLOCK = '0', '1'
    ACTIONS = {ALLOW: 'Allow', BLOCK: 'Block'}

    def __init__(self, pattern, action=ALLOW, note=''):
        self.pattern = str(pattern).strip()
        self.action = str(action)
        self.note = str(note or '').strip()

    def __repr__(self):
        return 'WCSite({!r}, {!r}, {!r})'.format(self.pattern, self.action, self.note)

    def __eq__(self, other):
        return isinstance(other, WCSite) and (self.pattern, self.action, self.note) == \
            (other.pattern, other.action, other.note)

    def check(self):
        """
        Raise ValueError if the console would refuse the site (validatePattern
        of the dialogs, checked on the lab).
        """
        if len(self.pattern) < 3:
            raise ValueError('Site patterns must be at least 3 characters: {!r}'.format(
                self.pattern))
        if not is_wc_site_pattern(self.pattern):
            raise ValueError('Site pattern cannot contain the characters: *, \\, <, >, comma '
                             'or space: {!r}'.format(self.pattern))
        if self.action not in self.ACTIONS:
            raise ValueError('The action must be "0" (Allow) or "1" (Block).')
        check_length('Notes', self.note, 50)


class ESWCPolicyBlockAllowList(ESWCPolicy):
    """
    The ESWCPolicyBlockAllowList class can be used to edit the Endpoint
    Security Web Control policy: Block and Allow List.
    """
    TYPE = 'EWC_BlockAndAllowList'
    MD_CATEGORY = 'Block and Allow List'
    SECTION = 'BlockAndAllowList'

    # ------------------------------ Block and Allow List ------------------------------
    def _info_counts(self):
        """
        The counts of get_info() and of the representation: the sites.
        """
        return {'sites': len(self.get_sites())}

    def get_sites(self):
        """
        Get the sites (list of WCSite) in the policy order (the console sorts
        them by site, descending).
        """
        value = lambda setting: self._get(self.SECTION, setting) or ''
        return [WCSite(value('szSite{}'.format(row)),
                       value('Action{}'.format(row)) or WCSite.ALLOW,
                       value('szNote{}'.format(row)))
                for row in range(int(value('uiSiteCount') or 0))]

    def set_sites(self, sites):
        """
        Set the sites (list of WCSite).
        """
        patterns = set()
        for site in sites:
            site.check()
            if site.pattern.lower() in patterns:
                raise ValueError('The site pattern {!r} is already in the list.'.format(
                    site.pattern))
            patterns.add(site.pattern.lower())
        section = self._section(self.SECTION)
        pattern = re.compile(r'^(szSite|szUnicodeSite|Action|szNote)\d+$')
        for setting_obj in section.findall('Setting'):
            if pattern.match(setting_obj.get('name')):
                section.remove(setting_obj)
        for row, site in enumerate(sites):
            for setting, value in [('Action', site.action), ('szNote', site.note),
                                   ('szSite', site.pattern),
                                   ('szUnicodeSite', site.pattern)]:
                self.set_setting_value(self.SECTION, '{}{}'.format(setting, row), value, True)
        return self._set(self.SECTION, 'uiSiteCount', len(sites))

    sites = property(get_sites, set_sites)

    def add_site(self, site):
        """
        Add a site (WCSite). A pattern already in the list (case ignored, as
        the server does) is replaced.
        """
        site.check()
        sites = [known for known in self.get_sites()
                 if known.pattern.lower() != site.pattern.lower()]
        return self.set_sites(sites + [site])

    def remove_site(self, pattern):
        """
        Remove a site given by its pattern.
        """
        sites = self.get_sites()
        kept = [site for site in sites if site.pattern != pattern]
        if len(kept) == len(sites):
            return False
        return self.set_sites(kept)

    # ------------------------------ Advanced Settings ------------------------------
    def get_enforce_download_ratings(self):
        """
        Get state of Enforce actions for file downloads based on their rating
        (allowed sites) ('1' or '0').
        """
        return self._get(self.SECTION, 'bTrack')

    def set_enforce_download_ratings(self, mode):
        """
        Set state of Enforce actions for file downloads based on their rating
        (allowed sites) ('1' or '0').
        """
        return self._set_checkbox(self.SECTION, 'bTrack', mode)

    enforce_download_ratings = property(get_enforce_download_ratings,
                                        set_enforce_download_ratings)

    def get_download_actions(self):
        """
        Get the actions for file downloads from allowed sites (RatingActions).
        """
        return self._get_rating(self.SECTION, 'uiSiteResourceFileDownload')

    def set_download_actions(self, actions):
        """
        Set the actions for file downloads from allowed sites (RatingActions).
        """
        return self._set_rating(self.SECTION, 'uiSiteResourceFileDownload', actions)

    download_actions = property(get_download_actions, set_download_actions)

    def get_allowed_precedence(self):
        """
        Get state of Enable allowed sites to take precedence over blocked
        sites ('1' or '0').
        """
        return self._get(self.SECTION, 'bPrecedenceOverProhibitLists')

    def set_allowed_precedence(self, mode):
        """
        Set state of Enable allowed sites to take precedence over blocked
        sites ('1' or '0').
        """
        return self._set_checkbox(self.SECTION, 'bPrecedenceOverProhibitLists', mode)

    allowed_precedence = property(get_allowed_precedence, set_allowed_precedence)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        sites = self.md_table(['Site', 'Action', 'Notes'], [
            [site.pattern, WCSite.ACTIONS.get(site.action, site.action), site.note]
            for site in self.get_sites()], numbered=True)
        text = '### Allowed Site Options\n\n' + self.md_settings([
            ['Enforce actions for file downloads based on their rating (Windows only)',
             self.md_check(self.get_enforce_download_ratings())]])
        if self.get_enforce_download_ratings() == '1':
            text += '\n' + self._md_rating(self.get_download_actions())
        text += '\n### Action Precedence\n\n' + self.md_settings([
            ['Enable allowed sites to take precedence over blocked sites',
             self.md_check(self.get_allowed_precedence())]])
        return [('Block and Allow List', sites), ('Advanced Settings', text)]
