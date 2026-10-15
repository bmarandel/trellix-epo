# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines one Class object: ESCommonPolicies.
This class can be used to store Endpoint Security Common (ENS Common)
policies exported from ePolicy Orchestrator manually or through the API
(policy.export productId=ENDP_GS_1000).
"""

from ...policies import Policies

class ESCommonPolicies(Policies):
    """
    ESCommonPolicies is a class object containing the policies returned by the ePO API.
    """

    def __init__(self, xml_policies=None):
        super(ESCommonPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if self.get_product() != 'ENDP_GS_1000':
                raise ValueError('Wrong McAfee Product. Policies must come from "ENDP_GS_1000".')
