# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

""" McAfee Agent Policies Class """

__all__ = ["tapolicies", "general", "repository", "troubleshooting", "customprops", "telemetry"]

from .tapolicies import TAPolicies
from .general import TAPolicyGeneral
from .repository import TAPolicyRepository, RepositoryList
from .troubleshooting import TAPolicyTroubleshooting
from .customprops import TAPolicyCustomProps
from .telemetry import TAPolicyTelemetry