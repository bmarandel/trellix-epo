#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
policy_documentation.py

Example for the mcafee_epo_policies package: write one Markdown document per
policy of an ENS (Common, Threat Prevention, Firewall, Storage Protection,
Adaptive Threat Protection, Web Control), Trellix Agent, System Information Reporter,
Solidcore or Trellix EDR with Forensics export, to keep a
documentation of the enforced security policies (audits, compliance).

Each document has a metadata header, a table of contents, one section per
console tab and a document control section (review/approval sign-off and
change history) to fill in.

Usage:
    python3 policy_documentation.py <export.xml> [output_dir] [author]
"""

import os
import re
import sys

from mcafee_epo_policies import (ESTPPolicies, ESFWPolicies, ESTPPolicyOnAccessScan,
                                 ESTPPolicyOnDemandScan, ESTPPolicyExploitPrevention,
                                 ESTPPolicyOptions, ESTPPolicyAccessProtection, ESFWPolicyRules,
                                 ESFWPolicyOptions, McAfeeAgentPolicies, McAfeeAgentPolicyGeneral,
                                 McAfeeAgentPolicyRepository, McAfeeAgentPolicyTroubleshooting,
                                 McAfeeAgentPolicyCustomProps, McAfeeAgentPolicyTelemetry,
                                 ESSPPolicies, ESSPPolicyICAP, ESSPPolicyNetApp, SCPolicies,
                                 SCGENPolicyConfiguration, SCGENPolicyExceptionRules,
                                 SCAWLPolicyOptions, SCAWLPolicyRules, SCCCPolicyRules,
                                 SCFIMPolicyRules, ESATPPolicies, ESATPPolicyOptions,
                                 ESATPPolicyDAC, ESWCPolicies, ESWCPolicyOptions,
                                 ESWCPolicyMessaging, ESWCPolicyBlockAllowList,
                                 ESWCPolicyContentActions, ESWCPolicyBrowserControl,
                                 SIRPolicies, SIRPolicyCollectData, SIRPolicySetRegistry,
                                 ESCommonPolicies, ESCommonPolicyOptions, EDRFPolicies,
                                 EDRFPolicyGeneral, EDRFPolicyStreaming, EDRFPolicyDetection,
                                 EDRFPolicyInvestigation, EDRFPolicyRemediation)

# Policy types with a Markdown export, per product of the export.
PRODUCTS = {
    'ENDP_AM_1000': (ESTPPolicies, {
        'EAM_General_Policies': ESTPPolicyOnAccessScan,
        'EAM_OnDemandScan_Policies': ESTPPolicyOnDemandScan,
        'EAM_BufferOverflow_Policies': ESTPPolicyExploitPrevention,
        'EAM_CommonScan_Policies': ESTPPolicyOptions,
        'EAM_BehaviorBlock_Policies': ESTPPolicyAccessProtection}),
    'ENDP_FW_META_FW': (ESFWPolicies, {
        'FireCore_FW_Rules': ESFWPolicyRules,
        'FW_StatusMode': ESFWPolicyOptions}),
    'EPOAGENTMETA': (McAfeeAgentPolicies, {
        'General': McAfeeAgentPolicyGeneral,
        'Repository': McAfeeAgentPolicyRepository,
        'Troubleshooting': McAfeeAgentPolicyTroubleshooting,
        'CustomProps': McAfeeAgentPolicyCustomProps,
        'Telemetry': McAfeeAgentPolicyTelemetry}),
    'VSESTOMD1300': (ESSPPolicies, {
        'VSES1000_Icap_Policies': ESSPPolicyICAP,
        'VSES1000_Netapp_Policies': ESSPPolicyNetApp}),
    'ENDP_GS_1000': (ESCommonPolicies, {
        'EGS_Product_Configuration_Policies': ESCommonPolicyOptions}),
    'TIEClientMETA': (ESATPPolicies, {
        'General': ESATPPolicyOptions,
        'TIE_DynamicApplicationContainment_Policies': ESATPPolicyDAC}),
    'ENDP_WP_1000': (ESWCPolicies, {
        'EWC_General': ESWCPolicyOptions,
        'EWC_EnforcementMessaging': ESWCPolicyMessaging,
        'EWC_BlockAndAllowList': ESWCPolicyBlockAllowList,
        'EWC_ContentFiltering': ESWCPolicyContentActions,
        'EWC_BrowserControl': ESWCPolicyBrowserControl}),
    # SIR policy types are the feature IDs (both categories have the typeid "General").
    'SIR': (SIRPolicies, {
        SIRPolicies.COLLECT_DATA: SIRPolicyCollectData,
        SIRPolicies.SET_REGISTRY: SIRPolicySetRegistry}),
    # Trellix EDR with Forensics (the Protection policies are skipped).
    'XCLIENT_META': (EDRFPolicies, {
        EDRFPolicies.GENERAL: EDRFPolicyGeneral,
        EDRFPolicies.STREAMING: EDRFPolicyStreaming,
        EDRFPolicies.DETECTION: EDRFPolicyDetection,
        EDRFPolicies.INVESTIGATION: EDRFPolicyInvestigation,
        EDRFPolicies.REMEDIATION: EDRFPolicyRemediation}),
    # Solidcore exports hold several features (SCOR_GEN, SCOR_AWL, SCOR_CC, SCOR_FIM).
    'SCOR': (SCPolicies, {
        'Lockdown Rules': SCGENPolicyConfiguration,
        'Attr Rules (Windows)': SCGENPolicyExceptionRules,
        'Attr Rules (Unix)': SCGENPolicyExceptionRules,
        'AWL Options (Windows)': SCAWLPolicyOptions,
        'AWL Options (Unix)': SCAWLPolicyOptions,
        'AWL Rules (Windows)': SCAWLPolicyRules,
        'AWL Rules (Unix)': SCAWLPolicyRules,
        'CC Rules (Windows)': SCCCPolicyRules,
        'CC Rules (Unix)': SCCCPolicyRules,
        'Mon Rules (Windows)': SCFIMPolicyRules,
        'Mon Rules (Unix)': SCFIMPolicyRules}),
}


def main():
    if len(sys.argv) not in (2, 3, 4):
        print('Usage: python3 policy_documentation.py <export.xml> [output_dir] [author]',
              file=sys.stderr)
        return 1
    output_dir = sys.argv[2] if len(sys.argv) >= 3 else '.'
    author = sys.argv[3] if len(sys.argv) == 4 else ''
    os.makedirs(output_dir, exist_ok=True)

    with open(sys.argv[1], 'rb') as export_file:
        xml_data = export_file.read()
    product = re.search(rb'featureid="([^"]+)"', xml_data)
    product = product.group(1).decode() if product else ''
    if product.startswith('SCOR_'):
        product = 'SCOR'
    if product.startswith('SIR_____1000'):
        product = 'SIR'
    if product not in PRODUCTS:
        print('Unsupported product "{}": use an ENS Common, ENS Threat Prevention, ENS Firewall, ENS '
              'Storage Protection, ENS Adaptive Threat Protection, ENS Web Control, '
              'Trellix Agent, System Information Reporter, Solidcore or '
              'Trellix EDR with Forensics export.'
              .format(product), file=sys.stderr)
        return 1
    container, classes = PRODUCTS[product]
    policies = container(xml_data)

    for item in policies.list():
        policy_class = classes.get(item['typeid'])
        if policy_class is None:
            print('Skipped (no Markdown export yet): {} - {}'.format(item['typeid'],
                                                                      item['name']))
            continue
        policy = policy_class(policies.get_policy(item['typeid'], item['name']))
        # e.g. "ENS Firewall - Options - My Default.md" (both TP and FW have Options).
        file_name = '{} - {} - {}.md'.format(
            policy.MD_PRODUCT.replace('Endpoint Security', 'ENS'), policy.MD_CATEGORY,
            re.sub(r'[\\/:*?"<>|]', '_', item['name']))
        policy.save_markdown(os.path.join(output_dir, file_name), author=author)
        print('Written: {}'.format(file_name))
    return 0


if __name__ == '__main__':
    sys.exit(main())
