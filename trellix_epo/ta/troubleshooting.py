# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class TAPolicyTroubleshooting.
"""

from ..policies import Policy
from .markdown import MD_PRODUCT, labelled

class TAPolicyTroubleshooting(Policy):
    """
    The TAPolicyTroubleshooting class can be used to edit the McAfee Agent
    policy: Troubleshooting.

    Note: ServerId (a per-installation ePO server GUID) is intentionally not
    exposed here - it is internal to the ePO server and not a user setting.
    """

    def __init__(self, policy_from_tapolicies=None):
        super(TAPolicyTroubleshooting, self).__init__(policy_from_tapolicies)
        if policy_from_tapolicies is not None and self.get_type() != 'Troubleshooting':
            raise ValueError('Wrong Trellix Agent policy. Policy type must be "Troubleshooting".')

    # ------------------------------ GENERAL TAB ------------------------------
    # Language Options:
    #   Select language used by agent
    def get_enable_agent_language_selection(self):
        """
        Get state of Select language used by agent
        """
        value = self.get_setting_value('LanguageOptions', 'bEnableAgentLangSelection')
        return value if value is not None else self.get_setting_value(
            'General', 'bEnableAgentLangSelection')

    def set_enable_agent_language_selection(self, mode):
        """
        Set state of Select language used by agent
        """
        self.set_setting_value('LanguageOptions', 'bEnableAgentLangSelection', mode)
        return self.set_setting_value('General', 'bEnableAgentLangSelection', mode)

    enable_agent_language_selection = property(get_enable_agent_language_selection,
                                               set_enable_agent_language_selection)

    #   Language dropdown, available once "Select language used by agent" is checked.
    #   Value is a Windows LCID hex code (use the Language class from constants,
    #   e.g. Language.FRENCH, instead of remembering the raw code).
    def get_agent_language(self):
        """
        Get the selected agent language (Use Language class from constants)
        """
        value = self.get_setting_value('LanguageOptions', 'AgentLanguage')
        return value if value is not None else self.get_setting_value('General', 'AgentLanguage')

    def set_agent_language(self, language_code):
        """
        Set the selected agent language (Use Language class from constants)
        """
        self.set_setting_value('LanguageOptions', 'AgentLanguage', language_code)
        return self.set_setting_value('General', 'AgentLanguage', language_code)

    agent_language = property(get_agent_language, set_agent_language)

    # ------------------------------ GENERAL TAB ------------------------------
    #   Console label not confirmed - kept for completeness.
    def get_health_check(self):
        """
        Get state of a General tab option (console label not confirmed)
        """
        return self.get_setting_value('General', 'IsHealthcheckEnabled')

    def set_health_check(self, mode):
        """
        Set state of a General tab option (console label not confirmed)
        """
        return self.set_setting_value('General', 'IsHealthcheckEnabled', mode)

    health_check = property(get_health_check, set_health_check)

    # ------------------------------ Markdown export ------------------------------
    # Console: Trellix Agent > Troubleshooting, tab General (ePO 5.10).
    MD_PRODUCT = MD_PRODUCT
    MD_CATEGORY = 'Troubleshooting'
    LANGUAGES = {'0000': 'UI Default Language', '0804': 'Chinese (Simplified)',
                 '0404': 'Chinese (Traditional)', '0405': 'Czech', '0406': 'Danish',
                 '0413': 'Dutch', '0409': 'English', '040b': 'Finnish', '040c': 'French',
                 '0407': 'German', '0410': 'Italian', '0411': 'Japanese', '0412': 'Korean',
                 '0414': 'Norwegian', '0415': 'Polish', '0816': 'Portuguese',
                 '0416': 'Portuguese (Brazilian)', '0419': 'Russian', '040a': 'Spanish',
                 '041d': 'Swedish', '041f': 'Turkish'}

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples
        (see Policy.to_markdown).
        """
        enabled = self.get_enable_agent_language_selection()
        rows = [['Select language used by agent (Windows, Mac OSX and EWS agents only)',
                 self.md_check(enabled)]]
        if enabled == '1':
            rows.append(['Language', labelled(self.get_agent_language(), self.LANGUAGES)])
        return [('General', '### Language options\n\n' + self.md_settings(rows))]
