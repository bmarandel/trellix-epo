# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class TAPolicyTelemetry.
"""

from ..policies import Policy
from .markdown import MD_PRODUCT

class TAPolicyTelemetry(Policy):
    """
    The TAPolicyTelemetry class can be used to edit the McAfee Agent
    policy: Product Improvement Program.

    Note: branch, maxTelemetrySize, serverLevelInstallFlag and timer are
    confirmed internal (not shown in the ePO console) and are only exposed as
    private, read-only "hidden setting" accessors.
    """

    def __init__(self, policy_from_mcafeeagentpolicies):
        super(TAPolicyTelemetry, self).__init__(policy_from_mcafeeagentpolicies)
        if self.get_type() != 'Telemetry':
            raise ValueError('Wrong McAfee Agent policy. Policy type must be "Telemetry".')

    def __repr__(self):
        name = self.get_name()
        epo = self.get_epo_server()
        return '<TAPolicyTelemetry for policy {} from server {}.>'.format(name, epo)

    # ------------------------------ Product Improvement Program ------------------------------
    #   Enable Product Improvement Program
    #   Note: raw values are the strings 'true'/'false', not '1'/'0' like the
    #   rest of this package.
    def get_product_improvement_program(self):
        """
        Get state of Enable Product Improvement Program ('true' or 'false')
        """
        return self.get_setting_value('Telemetry', 'optIn')

    def set_product_improvement_program(self, mode):
        """
        Set state of Enable Product Improvement Program ('true' or 'false')
        """
        return self.set_setting_value('Telemetry', 'optIn', mode)

    product_improvement_program = property(get_product_improvement_program,
                                           set_product_improvement_program)

    # Hidden settings (confirmed not shown in the ePO console):
    def __get_branch(self):
        """
        Get Hidden setting - Telemetry update branch
        """
        return self.get_setting_value('Telemetry', 'branch')

    def __get_max_telemetry_size(self):
        """
        Get Hidden setting - Maximum telemetry payload size
        """
        return self.get_setting_value('Telemetry', 'maxTelemetrySize')

    def __get_server_level_install_flag(self):
        """
        Get Hidden setting - Server level install flag
        """
        return self.get_setting_value('Telemetry', 'serverLevelInstallFlag')

    def __get_timer(self):
        """
        Get Hidden setting - Telemetry upload timer (milliseconds)
        """
        return self.get_setting_value('Telemetry', 'timer')

    # ------------------------------ Markdown export ------------------------------
    # Console: Trellix Agent > Product Improvement Program (ePO 5.10).
    MD_PRODUCT = MD_PRODUCT
    MD_CATEGORY = 'Product Improvement Program'

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples
        (see Policy.to_markdown).
        """
        opt_in = self.get_product_improvement_program()
        value = None if opt_in is None else ('Yes' if opt_in == 'true' else 'No')
        return [('Product Improvement Program', '### Options\n\n' + self.md_settings(
            [['Allow Trellix to collect usage, threat and diagnostic data', value]]))]
