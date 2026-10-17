# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

""" trellix_epo Class """

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("trellix_epo")
except PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = ["constants", "policies", "validators", "ta", "es", "sc", "sir", "edrf", "epo", "tags",
           "tagcatalog", "epotags", "assignmentrules", "clienttasks", "epoclienttasks",
           "repository", "eporepository", "systemtree", "eposystemtree", "policycatalog", "epopolicies", "servertasks",
           "eposervertasks", "squid", "epoqueries", "users",
           "epousers"]

from .constants import State, Priority, Gti, OASState, Severity, Language, SCException, SCReputation
from .policies import Policies, Policy
from .ta.tapolicies import TAPolicies
from .ta.general import TAPolicyGeneral
from .ta.repository import TAPolicyRepository, RepositoryList
from .ta.troubleshooting import TAPolicyTroubleshooting
from .ta.customprops import TAPolicyCustomProps
from .ta.telemetry import TAPolicyTelemetry
from .es.tp.estppolicies import ESTPPolicies
from .es.tp.onaccessscan import ESTPPolicyOnAccessScan, OASProcessList, OASExclusionList, OASURLList
from .es.tp.ondemandscan import ESTPPolicyOnDemandScan, ODSLocationList, ODSExclusionList
from .es.tp.exploitprevention import (ESTPPolicyExploitPrevention, SearchFilter, EPExclusion, EPAppRule,
                                      EPExecutable)
from .es.tp.options import ESTPPolicyOptions
from .es.tp.accessprotection import (ESTPPolicyAccessProtection, APRule, APSubRule, APTarget,
                                     APExecutable, APUserName)
from .es.fw.esfwpolicies import ESFWPolicies
from .es.fw.rules import (ESFWPolicyRules, FWRule, FWGroup, FWNetwork, FWApplication,
                          FWExecutable, FWLocation, FWAddress)
from .es.fw.options import ESFWPolicyOptions
from .es.sp import ESSPPolicies, ESSPPolicy, ESSPPolicyICAP, ESSPPolicyNetApp, SPExclusion
from .es.cm import ESCommonPolicies, ESCommonPolicyOptions, AACExclusion
from .es.atp import ESATPPolicies, ESATPPolicyOptions, ESATPPolicyDAC, DACExclusion
from .es.wc import (ESWCPolicies, ESWCPolicy, RatingActions, ESWCPolicyOptions, ESWCPolicyMessaging,
                    ESWCPolicyBlockAllowList, WCSite, ESWCPolicyContentActions,
                    ESWCPolicyBrowserControl)
from .sc.scpolicies import SCPolicies, SCPolicy
from .sir import SIRPolicies, SIRPolicyCollectData, SIRPolicySetRegistry, SIRRegistryValue
from .edrf import (EDRFPolicies, EDRFPolicy, EDRFPolicyGeneral, EDRFPolicyStreaming,
                   EDRFEventLog, EDRFFileEvent, EDRFEventFilter, EDRFFilterCondition,
                   EDRFSyslogServer, EDRFPolicyDetection, EDRFRegistryExclusion,
                   EDRFPolicyInvestigation, EDRFPolicyRemediation, EDRFAllowedIP)
from .sc.rules import SCRules, SCExclusionRules, SCUpdaterRules
from .sc.gen import SCGENPolicyConfiguration, SCGENPolicyExceptionRules
from .sc.awl import SCAWLPolicyOptions, SCAWLPolicyRules
from .sc.cc import SCCCPolicyRules
from .sc.fim import SCFIMPolicyRules
from .sc.rulegroups import SCRuleGroups, SCRuleGroup, SCAWLRuleGroup, SCCCRuleGroup, SCFIMRuleGroup
from .epo import EPOClient, EPOError
from .tags import Tag, TagCriteria, TagCondition, TagProperty, TagList
from .assignmentrules import (AssignmentRule, AssignmentRuleList, PolicyAssignment,
                              RuleTagCriteria, SystemGroups)
from .clienttasks import (ClientTask, ClientTaskList, DeploymentItem, TADeploymentTask,
                          TAUpdateTask, SIRFileRetrievalTask, SCEnableTask, SCDisableTask,
                          SCBeginUpdateTask, SCEndUpdateTask, SCBeginInventoryTask,
                          SCEndInventoryTask, SCPullInventoryTask, SCDebugInfoTask,
                          SCCLIAccessTask, SCObserveModeTask, SCRunCommandsTask)
from .repository import Package, Repository, packages_to_markdown
from .systemtree import System, Group, systems_to_markdown, groups_to_markdown
from .policycatalog import (PolicyRef, Assignment, AppliedPolicy, policies_to_markdown,
                            assignments_to_markdown, applied_to_markdown)
from .servertasks import (ServerTask, TaskLogEntry, TaskMessage, RunningTask,
                          server_tasks_to_markdown, task_log_to_markdown)
from .squid import Query, SavedQuery, rows_to_markdown, saved_queries_to_markdown
from .users import User, Role, PermissionSet, PermissionSetList, users_to_markdown
