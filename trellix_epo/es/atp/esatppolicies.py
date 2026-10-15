# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines one Class object: ESATPPolicies.
This class can be used to store Endpoint Security Adaptive Threat Protection
(ENS ATP) policies exported from ePolicy Orchestrator manually or through the
API (policy.export productId=TIEClientMETA).
"""

from ...policies import Policies

class ESATPPolicies(Policies):
    """
    ESATPPolicies is a class object containing the policies returned by the ePO API.
    """

    def __init__(self, xml_policies=None):
        super(ESATPPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if self.get_product() != 'TIEClientMETA':
                raise ValueError('Wrong McAfee Product. Policies must come from "TIEClientMETA".')
