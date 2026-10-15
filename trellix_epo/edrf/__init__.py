# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
Trellix EDR with Forensics (EDRF, ePO product XCLIENT_META): General,
Streaming, Detection, Investigation and Remediation policies (the
Protection policy of the extension 2.1.2 is not supported; the extension
50.3 removed it).
"""

__all__ = ["edrfpolicies", "policy", "general", "streaming", "detection", "investigation",
           "remediation"]

from .edrfpolicies import EDRFPolicies
from .policy import EDRFPolicy
from .general import EDRFPolicyGeneral
from .streaming import (EDRFPolicyStreaming, EDRFEventLog, EDRFFileEvent, EDRFEventFilter,
                        EDRFFilterCondition, EDRFSyslogServer)
from .detection import EDRFPolicyDetection, EDRFRegistryExclusion
from .investigation import EDRFPolicyInvestigation
from .remediation import EDRFPolicyRemediation, EDRFAllowedIP
