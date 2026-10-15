# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines one Class object: TAPolicies.
This class can be used to store McAfee Agent policies exported from
ePolicy Orchestrator manually or through the API.
"""

from ..policies import Policies

class TAPolicies(Policies):
    """
    TAPolicies is a class object containing the policies returned by the ePO API.
    """

    def __init__(self, xml_policies=None):
        super(TAPolicies, self).__init__(xml_policies)
        if xml_policies is not None:
            if self.get_product() != 'EPOAGENTMETA':
                raise ValueError('Wrong McAfee Product. Policies must come from "EPOAGENTMETA".')
