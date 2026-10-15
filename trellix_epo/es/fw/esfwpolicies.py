# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines one Class object: ESFWPolicies.
This class can be used to store ENS Firewall policies exported from
ePolicy Orchestrator manually or through the API.
"""

from ...policies import Policies

class ESFWPolicies(Policies):
    """
    ESFWPolicies is a class object containing the policies returned by the ePO API.
    """

    def __init__(self, xml_policies=None):
        super(ESFWPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if self.get_product() != 'ENDP_FW_META_FW':
                raise ValueError('Wrong McAfee Product. Policies must come from "ENDP_FW_META_FW".')
