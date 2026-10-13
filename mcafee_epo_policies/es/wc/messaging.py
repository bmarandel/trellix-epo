# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESWCPolicyMessaging (Endpoint Security Web
Control: Enforcement Messaging).

Storage (ePO 5.10): section EnforcementMessaging, one setting per message
and language, "<message>_<language>" (e.g. szBlock_en, szBlock_fr), for the
15 languages of the console "Settings for" selection.
"""

from .common import ESWCPolicy
from ...validators import check_length


class ESWCPolicyMessaging(ESWCPolicy):
    """
    The ESWCPolicyMessaging class can be used to edit the Endpoint Security
    Web Control policy: Enforcement Messaging. Messages are given by their
    setting name (see MESSAGES) and language (see LANGUAGES).
    """
    TYPE = 'EWC_EnforcementMessaging'
    MD_CATEGORY = 'Enforcement Messaging'

    LANGUAGES = {'en': 'English', 'es': 'Spanish', 'iw': 'Hebrew', 'fr': 'French',
                 'de': 'German', 'zh_CN': 'Chinese (Simplified)',
                 'zh_TW': 'Chinese (Traditional)', 'ja': 'Japanese', 'ru': 'Russian',
                 'ko': 'Korean', 'it': 'Italian', 'pt_BR': 'Brazilian-Portuguese',
                 'nl': 'Dutch', 'pl': 'Polish', 'sv': 'Swedish'}
    # Console groups: (group, [(box title, [(setting, label, max length)])]).
    GROUPS = [
        ('Site', [
            ('Explanation for sites blocked by Web Category Blocking (1000 characters, HTML OK)',
             [('szBlockContentDetail', 'Block explanation', 1000)]),
            ('Messages for sites blocked by Rating Actions',
             [('szBlock', 'Block message', 100), ('szWarn', 'Warn message', 100)]),
            ('Explanations for sites blocked by Rating Actions (1000 characters, HTML OK)',
             [('szBlockDetail', 'Block explanation', 1000),
              ('szWarnDetail', 'Warn explanation', 1000)])]),
        ('Site Downloads', [
            ('Messages for site download blocked by Rating Actions',
             [('szSiteResourceFileDownloadBlock', 'Block message', 100),
              ('szSiteResourceFileDownloadWarn', 'Warn message', 100)]),
            ('Message for sites blocked by Phishing Pages',
             [('szSiteResourcePageBlock', 'Block message', 100)])]),
        ('Block List', [
            ('Message for sites on the Block List',
             [('szListOnProhibited', 'Block message', 100)]),
            ('Explanation for sites on the Block List (1000 characters, HTML OK)',
             [('szListOnProhibitedDetail', 'Block explanation', 1000)])]),
        ('Trellix GTI Unreachable', [
            ('Message for sites blocked when Trellix GTI ratings server is not reachable',
             [('szBlockGTIFailClose', 'Block message', 100)]),
            ('Explanation for sites blocked when Trellix GTI ratings server is not reachable '
             '(1000 characters, HTML OK)',
             [('szBlockGTIFailCloseDetail', 'Block explanation', 1000)])]),
        ('Unverified Site Protection', [
            ('Messages for sites not yet verified by Trellix GTI',
             [('szBlockZeroDay', 'Block message', 100), ('szWarnZeroDay', 'Warn message', 100)]),
            ('Explanations for sites not yet verified by Trellix GTI (1000 characters, HTML OK)',
             [('szBlockDetailZeroDay', 'Block explanation', 1000),
              ('szWarnDetailZeroDay', 'Warn explanation', 1000)])]),
        ('Unverified File Download Protection', [
            ('Messages for files not yet verified by Trellix GTI',
             [('szBlockFileMessage', 'Block message', 100),
              ('szWarnFileMessage', 'Warn message', 100)])]),
        ('Image for Warn and Block Pages', [
            ('Specify image URL to display for Warn and Block pages (suggested image formats: '
             'GIF, JPG, PNG)', [('szLogoUrl', 'URL', 254)])]),
    ]
    MESSAGES = {setting: (label, length) for _, boxes in GROUPS for _, messages in boxes
                for setting, label, length in messages}

    def __init__(self, policy_from_eswcpolicies=None):
        super(ESWCPolicyMessaging, self).__init__(policy_from_eswcpolicies)
        # Languages documented by to_markdown() (console "Settings for").
        self.md_languages = ['en']

    def __check(self, message, language):
        if message not in self.MESSAGES:
            raise ValueError('Unknown message: {} (see ESWCPolicyMessaging.MESSAGES)'.format(
                message))
        if language not in self.LANGUAGES:
            raise ValueError('Unknown language: {} (see ESWCPolicyMessaging.LANGUAGES)'.format(
                language))

    def get_message(self, message, language='en'):
        """
        Get a message, e.g. get_message('szBlock', 'fr').
        """
        self.__check(message, language)
        return self._get('EnforcementMessaging', '{}_{}'.format(message, language))

    def set_message(self, message, text, language='en'):
        """
        Set a message, e.g. set_message('szBlock', 'Site interdit.', 'fr').
        Messages are required and limited to 100 characters, explanations
        (HTML OK, a line break counts for one and is stored as \n) to 1000
        and the image URL to 254.
        """
        self.__check(message, language)
        label, limit = self.MESSAGES[message]
        text = str(text).replace('\r\n', '\n')
        check_length('{} ({})'.format(label, message), text, limit, required=limit == 100)
        return self._set('EnforcementMessaging', '{}_{}'.format(message, language), text, True)

    def set_message_all_languages(self, message, text):
        """
        Set a message for all the languages (e.g. the image URL).
        """
        for language in self.LANGUAGES:
            self.set_message(message, text, language)
        return True

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown). The
        languages written are those of the md_languages attribute (default
        ['en']).
        """
        languages = [language for language in self.md_languages if language in self.LANGUAGES]
        sections = []
        for group, boxes in self.GROUPS:
            text = ''
            for title, messages in boxes:
                text += '### {}\n\n'.format(self.md_heading(title))
                if len(languages) == 1:
                    text += self.md_table(['Message', 'Text'], [
                        [label, self.get_message(setting, languages[0])]
                        for setting, label, _ in messages])
                else:
                    text += self.md_table(['Message', 'Language', 'Text'], [
                        [label, self.LANGUAGES[language], self.get_message(setting, language)]
                        for setting, label, _ in messages for language in languages])
                text += '\n'
            sections.append((group, text))
        if languages:
            sections[0] = (sections[0][0], 'Settings for: {}\n\n'.format(', '.join(
                self.LANGUAGES[language] for language in languages)) + sections[0][1])
        return sections
