# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines one Class object: SIRPolicies.
This class can be used to store System Information Reporter (SIR) policies
exported from ePolicy Orchestrator manually or through the API
(policy.export productId=SIR_____1000).

Both SIR policy categories (Collect Data > General and Set Registry >
Registry General) have the typeid "General": they are told apart by their
featureid, used as the policy type by SIRPolicies (see
SIRPolicies.COLLECT_DATA and SIRPolicies.SET_REGISTRY).
"""

from ..policies import Policies

class SIRPolicies(Policies):
    """
    SIRPolicies is a class object containing the policies returned by the ePO
    API. Its policy types are the feature IDs COLLECT_DATA and SET_REGISTRY.
    """
    TYPE_ATTRIBUTE = 'featureid'
    COLLECT_DATA = 'SIR_____1000_COLLECT_DATA'
    SET_REGISTRY = 'SIR_____1000_SET_REGISTRY'

    def __init__(self, xml_policies=None):
        super(SIRPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if not self.get_product().startswith('SIR_____1000'):
                raise ValueError('Wrong McAfee Product. Policies must come from "SIR_____1000".')
