# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESWCPolicyBrowserControl (Endpoint Security
Web Control: Browser Control).

Storage (ePO 5.10): section HardenSettings, three "|" separated lists in the
same order: szBrowserIds (e.g. IE|FF|CHROME...), szBrowserExeNames and
szBrowserBlocks ('1' = Block use of the browser).
"""

from .common import ESWCPolicy


class ESWCPolicyBrowserControl(ESWCPolicy):
    """
    The ESWCPolicyBrowserControl class can be used to edit the Endpoint
    Security Web Control policy: Browser Control. Browsers are given by
    their ID (see UNSUPPORTED and SUPPORTED).
    """
    TYPE = 'EWC_BrowserControl'
    MD_CATEGORY = 'Browser Control'
    SECTION = 'HardenSettings'

    # Browser ID -> console label, in the console order.
    UNSUPPORTED = {'OPERA': 'Opera', 'SAFARI': 'Safari for Windows', 'NETSCAPE': 'Netscape',
                   'MAXTHON': 'Maxthon', 'FLOCK': 'Flock', 'AVANT': 'Avant Browser',
                   'DEEPNET': 'Deepnet Explorer', 'PHASEOUT': 'PhaseOut'}
    SUPPORTED = {'IE': 'Internet Explorer', 'FF': 'Firefox', 'CHROME': 'Chrome',
                 'EDGE': 'Edge', 'CEDGE': 'Chromium Edge'}

    def __lists(self):
        ids = (self._get(self.SECTION, 'szBrowserIds') or '').split('|')
        blocks = (self._get(self.SECTION, 'szBrowserBlocks') or '').split('|')
        return ids, blocks + ['0'] * (len(ids) - len(blocks))

    def get_browsers(self):
        """
        Get the browsers: a dict {browser ID: '1' (blocked) or '0'}.
        """
        ids, blocks = self.__lists()
        return dict(zip(ids, blocks))

    def get_block(self, browser):
        """
        Get state of Block use of a browser ('1' or '0'), e.g. get_block('OPERA').
        """
        browsers = self.get_browsers()
        if browser not in browsers:
            raise ValueError('Unknown browser: {}'.format(browser))
        return browsers[browser]

    def set_block(self, browser, mode):
        """
        Set state of Block use of a browser ('1' or '0'), e.g. set_block('OPERA', '1').
        """
        if str(mode) not in ['0', '1']:
            raise ValueError('The state must be "1" or "0".')
        ids, blocks = self.__lists()
        if browser not in ids:
            raise ValueError('Unknown browser: {}'.format(browser))
        blocks[ids.index(browser)] = str(mode)
        return self._set(self.SECTION, 'szBrowserBlocks', '|'.join(blocks))

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        browsers = self.get_browsers()
        text = ''
        for title, labels in [('Block use of the following unsupported browsers',
                               self.UNSUPPORTED),
                              ('Block use of the following supported browsers', self.SUPPORTED)]:
            text += '### {}\n\n'.format(title)
            text += self.md_settings([[label, self.md_check(browsers.get(browser))]
                                      for browser, label in labels.items()]) + '\n'
        return [('Browser Control', text)]
