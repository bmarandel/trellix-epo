# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines one Class object: EDRFPolicies.
This class can be used to store Trellix EDR with Forensics (EDRF) policies
exported from ePolicy Orchestrator manually or through the API
(policy.export productId=XCLIENT_META).
"""

from ..policies import Policies


class EDRFPolicies(Policies):
    """
    EDRFPolicies is a class object containing the policies returned by the
    ePO API. Its policy types (typeid) are the console category names.
    """
    PRODUCT = 'XCLIENT_META'
    GENERAL = 'General'
    PROTECTION = 'Protection'       # not supported by the library
    STREAMING = 'Streaming'
    DETECTION = 'Detection'
    INVESTIGATION = 'Investigation'
    REMEDIATION = 'Remediation'

    def __init__(self, xml_policies=None):
        super(EDRFPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if self.get_product() != self.PRODUCT:
                raise ValueError('Wrong McAfee Product. Policies must come from "XCLIENT_META".')
