# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class TAPolicyCustomProps.
"""

from ..policies import Policy
from .markdown import MD_PRODUCT

class TAPolicyCustomProps(Policy):
    """
    The TAPolicyCustomProps class can be used to edit the McAfee Agent
    policy: Custom Properties.
    """

    def __init__(self, policy_from_mcafeeagentpolicies):
        super(TAPolicyCustomProps, self).__init__(policy_from_mcafeeagentpolicies)
        if self.get_type() != 'CustomProps':
            raise ValueError('Wrong McAfee Agent policy. Policy type must be "CustomProps".')

    def __repr__(self):
        name = self.get_name()
        epo = self.get_epo_server()
        return '<TAPolicyCustomProps for policy {} from server {}.>'.format(name, epo)

    # ------------------------------ Custom Properties ------------------------------
    # The Custom Properties table lists Property 1 through Property 8, each with
    # an "allow client to edit" and a "visible to client" style toggle.
    # Exact column wording not independently confirmed against the ePO console.
    def get_custom_properties(self):
        """
        Get the Custom Properties table (Property 1 through Property 8).
        Returns a list of 8 dicts with keys 'AllowClientEditing' and 'Visibility'.
        """
        return self.get_indexed_table('CustomProps', 'NumberOfCustomProps',
                                      ['AllowClientEditing', 'Visibility'], start=1)

    def set_custom_properties(self, table):
        """
        Set the Custom Properties table (Property 1 through Property 8).
        Use a list of dicts with keys 'AllowClientEditing' and 'Visibility'.
        """
        return self.set_indexed_table('CustomProps', 'NumberOfCustomProps',
                                      ['AllowClientEditing', 'Visibility'], table, start=1)

    custom_properties = property(get_custom_properties, set_custom_properties)

    #   Overwrite blank client-side values with the server value
    #   (exact console label not independently confirmed)
    def get_overwrite_blanks(self):
        """
        Get state of Overwrite blank client-side values with the server value
        """
        return self.get_setting_value('CustomProps', 'OverwriteBlanks')

    def set_overwrite_blanks(self, mode):
        """
        Set state of Overwrite blank client-side values with the server value
        """
        return self.set_setting_value('CustomProps', 'OverwriteBlanks', mode)

    overwrite_blanks = property(get_overwrite_blanks, set_overwrite_blanks)

    # ------------------------------ Markdown export ------------------------------
    # Console: Trellix Agent > Custom Properties (ePO 5.10): one row per
    # custom property with the "Allow view" and "Allow edit" checkboxes.
    MD_PRODUCT = MD_PRODUCT
    MD_CATEGORY = 'Custom Properties'

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples
        (see Policy.to_markdown).
        """
        rows = [['Custom Property {}'.format(index), self.md_check(prop.get('Visibility')),
                 self.md_check(prop.get('AllowClientEditing'))]
                for index, prop in enumerate(self.get_custom_properties() or [], 1)]
        return [('Custom Properties', '### End user access to Custom Properties\n\n' +
                 self.md_table(['Custom Property', 'Allow view', 'Allow edit'], rows))]
