# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines one Class object: ESSPPolicies.
This class can be used to store Endpoint Security Storage Protection (ENSSP)
policies exported from ePolicy Orchestrator manually or through the API
(policy.export productId=VSESTOMD1300).
"""

from ...policies import Policies

class ESSPPolicies(Policies):
    """
    ESSPPolicies is a class object containing the policies returned by the ePO API.
    """

    def __init__(self, xml_policies=None):
        super(ESSPPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if self.get_product() != 'VSESTOMD1300':
                raise ValueError('Wrong McAfee Product. Policies must come from "VSESTOMD1300".')
