# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes for the Solidcore "Application Control" policies
(SCOR_AWL): SCAWLPolicyOptions and SCAWLPolicyRules.
"""

import re
import uuid
from ..policies import Policy
from .scpolicies import SCPolicy
from ..validators import (check_int, check_length, is_sc_email_list, is_sc_website,
                          is_sc_directory, is_sc_execution_path, is_sc_file_name)
from .rules import SCExclusionRules, SCUpdaterRules

class SCAWLPolicyOptions(SCPolicy):
    """
    The SCAWLPolicyOptions class can be used to edit the Solidcore policies:
    Application Control > Application Control Options (Windows) and (Unix).

    Note: ePO stores these policies under the internal types "AWL Options (Windows)"
    and "AWL Options (Unix)". The Unix policy only has the Reputation tab, and
    without the TIE and ATD settings.
    """

    TYPE_IDS = ('AWL Options (Windows)', 'AWL Options (Unix)')

    # The two rules added by "Hide Windows OS Files" (Inventory tab), as created by ePO.
    __HIDE_OS_FILES_RULES = (
        {'type': 'advanced-inv-exclusion', 'action': 'exclude',
         'condition-type_0': 'File', 'match-type_0': 'begins', 'pattern_0': '%WINDIR%\\',
         'condition-type_1': 'Mrsf', 'match-type_1': 'equals', 'pattern_1': 'yes',
         'rule-uuid': '4feeed2d-5de8-47e5-8199-35a75d121b7b'},
        {'type': 'advanced-inv-exclusion', 'action': 'exclude',
         'condition-type_0': 'File', 'match-type_0': 'begins', 'pattern_0': '%WINDIR%\\winsxs\\',
         'rule-uuid': '718a4d26-b107-4a1d-9d67-1eeeddd2f30f'},
    )

    # Features shown in the Features tab (set to enforced by "Enforce feature
    # control"). Checked on the ePO 5.10 lab: the console leaves the hidden
    # 'mp-vasr' feature unenforced, and drops the obsolete hidden 'activex'
    # feature at any save of the policy (whatever the change, even with
    # "Enforce feature control" left as is); the library keeps 'activex', like
    # a policy never saved in the console (e.g. "My Default").
    FEATURES = ('execution-control', 'mp', 'mp-casp', 'mp-nx', 'ob-logging', 'pkg-ctrl',
                'pkg-ctrl-bypass', 'pkg-ctrl-allow-uninstall', 'sau')

    # ------------------------------ SELF-APPROVAL TAB ------------------------------
    #   Enable Self-Approval (State.ENABLED / State.DISABLED)
    def get_self_approval(self):
        """
        Get state of Enable Self-Approval
        """
        return self.get_feature('self-approval')

    def set_self_approval(self, value):
        """
        Set state of Enable Self-Approval
        """
        return self.set_feature('self-approval', value)

    self_approval = property(get_self_approval, set_self_approval)

    #   Self-Approval Text (banner text of the Self-Approval dialog box)
    def get_self_approval_text(self):
        """
        Get the Self-Approval Text
        """
        return self._get_rule_value('sadlg', 'banner_msg')

    def set_self_approval_text(self, value):
        """
        Set the Self-Approval Text
        """
        value = check_length('Self-Approval Text', str(value).replace('\r\n', '\n'), 1500)
        return self.update_rules('sadlg', None, {'banner_msg': value}) > 0

    self_approval_text = property(get_self_approval_text, set_self_approval_text)

    #   Dialog Timeout (secs, the console doesn't accept more than 180)
    def get_self_approval_timeout(self):
        """
        Get the Self-Approval Dialog Timeout (seconds)
        """
        return self._get_rule_value('sadlg', 'timeout')

    def set_self_approval_timeout(self, value):
        """
        Set the Self-Approval Dialog Timeout (seconds, 1-180)
        """
        value = check_int('Dialog Timeout (secs)', value, 1, 180)
        return self.update_rules('sadlg', None, {'timeout': str(value)}) > 0

    self_approval_timeout = property(get_self_approval_timeout, set_self_approval_timeout)

    #   Justification Message: '0' = Mandatory, '1' = Optional
    def get_justification_optional(self):
        """
        Get the Justification Message mode ('0' = Mandatory, '1' = Optional)
        """
        return self.get_config('SaDlgConfig')

    def set_justification_optional(self, value):
        """
        Set the Justification Message mode ('0' = Mandatory, '1' = Optional)
        """
        return self.set_config('SaDlgConfig', value)

    justification_optional = property(get_justification_optional, set_justification_optional)

    #   Advanced Options: allow execution and update of files not included in the
    #   allow list at boot time ('1' or '0')
    def get_self_approval_at_boot(self):
        """
        Get state of Advanced Options (allow execution and update of files not
        included in the allow list at boot time)
        """
        return self.get_config('SelfApprovalOptions')

    def set_self_approval_at_boot(self, value):
        """
        Set state of Advanced Options (allow execution and update of files not
        included in the allow list at boot time)
        """
        return self.set_config('SelfApprovalOptions', value)

    self_approval_at_boot = property(get_self_approval_at_boot, set_self_approval_at_boot)

    # ------------------------------ END USER NOTIFICATIONS TAB ------------------------------
    #   ePO stores the User Message and Helpdesk Information settings in every
    #   message ('event-cust-msg' rule): getters read the first one, setters
    #   update all of them, as the console does.
    def __get_message_setting(self, key):
        rules = self.get_rules('event-cust-msg')
        return rules[0].get(key) if rules else None

    def __set_message_setting(self, key, value):
        return self.update_rules('event-cust-msg', None, {key: value}) > 0

    #   User Message: Show the messages dialog box when an event is detected and
    #   display the specified text in the message ('true' or 'false')
    def get_user_message(self):
        """
        Get state of User Message ('true' or 'false')
        """
        return self.__get_message_setting('raise_immediately')

    def set_user_message(self, value):
        """
        Set state of User Message ('true' or 'false')
        """
        return self.__set_message_setting('raise_immediately', value)

    user_message = property(get_user_message, set_user_message)

    # Helpdesk Information:
    #   Mail to (use semicolon as a separator for multiple email addresses)
    def get_helpdesk_mail_to(self):
        """
        Get Helpdesk Information - Mail to
        """
        return self.__get_message_setting('mailto')

    def set_helpdesk_mail_to(self, value):
        """
        Set Helpdesk Information - Mail to
        """
        check_length('Mail to', value, 100, required=True)
        if not is_sc_email_list(value):
            raise ValueError('Invalid Mail to (see is_sc_email_list): {!r}'.format(value))
        return self.__set_message_setting('mailto', value)

    helpdesk_mail_to = property(get_helpdesk_mail_to, set_helpdesk_mail_to)

    #   Mail Subject
    def get_helpdesk_mail_subject(self):
        """
        Get Helpdesk Information - Mail Subject
        """
        return self.__get_message_setting('subject')

    def set_helpdesk_mail_subject(self, value):
        """
        Set Helpdesk Information - Mail Subject
        """
        check_length('Mail Subject', value, 100, required=True)
        return self.__set_message_setting('subject', value)

    helpdesk_mail_subject = property(get_helpdesk_mail_subject, set_helpdesk_mail_subject)

    #   Link to Website
    def get_helpdesk_website(self):
        """
        Get Helpdesk Information - Link to Website
        """
        return self.__get_message_setting('website')

    def set_helpdesk_website(self, value):
        """
        Set Helpdesk Information - Link to Website
        """
        check_length('Link to Website', value, 100, required=True)
        if not is_sc_website(value):
            raise ValueError('Invalid Link to Website (see is_sc_website): {!r}'.format(value))
        return self.__set_message_setting('website', value)

    helpdesk_website = property(get_helpdesk_website, set_helpdesk_website)

    #   Trellix ePO IP Address and Port (e.g. '{replace_epo_ip}:8443'). ePO stores
    #   it inside a full URL (epo_url), only the host:port part is shown.
    def get_helpdesk_epo_address(self):
        """
        Get Helpdesk Information - Trellix ePO IP Address and Port
        """
        epo_url = self.__get_message_setting('epo_url')
        match = re.match(r'^https://([^/]*)/', epo_url) if epo_url else None
        return match.group(1) if match else None

    def set_helpdesk_epo_address(self, value):
        """
        Set Helpdesk Information - Trellix ePO IP Address and Port
        """
        check_length('Trellix ePO IP Address and Port', value, 100, required=True)
        success = False
        for rule in self.get_rules('event-cust-msg'):
            epo_url = re.sub(r'^https://[^/]*/', 'https://{}/'.format(value), rule['epo_url'])
            self.update_rules('event-cust-msg', {'event_name': rule['event_name']},
                              {'epo_url': epo_url})
            success = True
        return success

    helpdesk_epo_address = property(get_helpdesk_epo_address, set_helpdesk_epo_address)

    # Messages: one message per event (e.g. 'EXECUTION_DENIED', 'WRITE_DENIED'),
    # with its text and its "Show Event in Dialog" checkbox. Variables like
    # {file_name}, {process_name}, {process_id} or {user_name} can be used.
    def get_message_events(self):
        """
        Get the list of event names which have a message.
        """
        return [rule['event_name'] for rule in self.get_rules('event-cust-msg')]

    def get_message(self, event_name):
        """
        Get the message text of an event, or None.
        """
        rule = self.get_rule('event-cust-msg', {'event_name': event_name})
        return rule.get('event_msg') if rule is not None else None

    def set_message(self, event_name, text):
        """
        Set the message text of an event.
        """
        return self.update_rules('event-cust-msg', {'event_name': event_name},
                                 {'event_msg': text}) > 0

    def get_message_show_in_dialog(self, event_name):
        """
        Get state of "Show Event in Dialog" for an event ('true' or 'false').
        """
        rule = self.get_rule('event-cust-msg', {'event_name': event_name})
        return rule.get('show_in_popup') if rule is not None else None

    def set_message_show_in_dialog(self, event_name, value):
        """
        Set state of "Show Event in Dialog" for an event ('true' or 'false').
        """
        return self.update_rules('event-cust-msg', {'event_name': event_name},
                                 {'show_in_popup': value}) > 0

    # ------------------------------ FEATURES TAB ------------------------------
    #   Enforce feature control from Trellix ePO ('true' or 'false'). The state of
    #   each feature below is only applied on the endpoints when it is 'true'.
    def get_enforce_feature_control(self):
        """
        Get state of Enforce feature control from Trellix ePO ('true' or 'false')
        """
        return self.get_meta('enforce-features-from-policy')

    def set_enforce_feature_control(self, value):
        """
        Set state of Enforce feature control from Trellix ePO ('true' or 'false')
        """
        for name in self.FEATURES:
            self.update_rules('features', {'name': name}, {'enforce': value})
        return self.set_meta('enforce-features-from-policy', value)

    enforce_feature_control = property(get_enforce_feature_control,
                                       set_enforce_feature_control)

    #   Feature Control (State.ENABLED / State.DISABLED):
    #   Execution Control
    def get_execution_control(self):
        """
        Get state of Feature Control - Execution Control
        """
        return self.get_feature('execution-control')

    def set_execution_control(self, value):
        """
        Set state of Feature Control - Execution Control
        """
        return self.set_feature('execution-control', value)

    execution_control = property(get_execution_control, set_execution_control)

    #   Memory Protection (reboot required)
    def get_memory_protection(self):
        """
        Get state of Feature Control - Memory Protection
        """
        return self.get_feature('mp')

    def set_memory_protection(self, value):
        """
        Set state of Feature Control - Memory Protection
        """
        return self.set_feature('mp', value)

    memory_protection = property(get_memory_protection, set_memory_protection)

    #     CASP (reboot required)
    def get_memory_protection_casp(self):
        """
        Get state of Feature Control - Memory Protection - CASP
        """
        return self.get_feature('mp-casp')

    def set_memory_protection_casp(self, value):
        """
        Set state of Feature Control - Memory Protection - CASP
        """
        return self.set_feature('mp-casp', value)

    memory_protection_casp = property(get_memory_protection_casp, set_memory_protection_casp)

    #     NX (64-Bit) (reboot required)
    def get_memory_protection_nx(self):
        """
        Get state of Feature Control - Memory Protection - NX (64-Bit)
        """
        return self.get_feature('mp-nx')

    def set_memory_protection_nx(self, value):
        """
        Set state of Feature Control - Memory Protection - NX (64-Bit)
        """
        return self.set_feature('mp-nx', value)

    memory_protection_nx = property(get_memory_protection_nx, set_memory_protection_nx)

    #   Generate Observations
    def get_generate_observations(self):
        """
        Get state of Feature Control - Generate Observations
        """
        return self.get_feature('ob-logging')

    def set_generate_observations(self, value):
        """
        Set state of Feature Control - Generate Observations
        """
        return self.set_feature('ob-logging', value)

    generate_observations = property(get_generate_observations, set_generate_observations)

    #   Package Control
    def get_package_control(self):
        """
        Get state of Feature Control - Package Control
        """
        return self.get_feature('pkg-ctrl')

    def set_package_control(self, value):
        """
        Set state of Feature Control - Package Control
        """
        return self.set_feature('pkg-ctrl', value)

    package_control = property(get_package_control, set_package_control)

    #     Bypass Package Control
    def get_bypass_package_control(self):
        """
        Get state of Feature Control - Package Control - Bypass Package Control
        """
        return self.get_feature('pkg-ctrl-bypass')

    def set_bypass_package_control(self, value):
        """
        Set state of Feature Control - Package Control - Bypass Package Control
        """
        return self.set_feature('pkg-ctrl-bypass', value)

    bypass_package_control = property(get_bypass_package_control, set_bypass_package_control)

    #     Allow Uninstallation
    def get_allow_uninstallation(self):
        """
        Get state of Feature Control - Package Control - Allow Uninstallation
        """
        return self.get_feature('pkg-ctrl-allow-uninstall')

    def set_allow_uninstallation(self, value):
        """
        Set state of Feature Control - Package Control - Allow Uninstallation
        """
        return self.set_feature('pkg-ctrl-allow-uninstall', value)

    allow_uninstallation = property(get_allow_uninstallation, set_allow_uninstallation)

    #   Script as Updater (SAU) (reboot required)
    def get_script_as_updater(self):
        """
        Get state of Feature Control - Script as Updater (SAU)
        """
        return self.get_feature('sau')

    def set_script_as_updater(self, value):
        """
        Set state of Feature Control - Script as Updater (SAU)
        """
        return self.set_feature('sau', value)

    script_as_updater = property(get_script_as_updater, set_script_as_updater)

    # ------------------------------ INVENTORY TAB ------------------------------
    #   Hide Windows OS Files: Inventory items signed with Microsoft certificates
    #   will not be sent to Trellix ePO ('true' or 'false'). ePO also adds (or
    #   removes) two inventory exclusion rules for %WINDIR%.
    def get_hide_windows_os_files(self):
        """
        Get state of Hide Windows OS Files ('true' or 'false')
        """
        rule = self.get_rule('scor-extn-internal-setting', {'name': 'inv-exclude-base-os-files'})
        return rule.get('value') if rule is not None else None

    def set_hide_windows_os_files(self, value):
        """
        Set state of Hide Windows OS Files ('true' or 'false')
        """
        if self.update_rules('scor-extn-internal-setting', {'name': 'inv-exclude-base-os-files'},
                             {'value': value}) == 0:
            self.add_rule({'type': 'scor-extn-internal-setting',
                           'name': 'inv-exclude-base-os-files', 'value': value})
        for rule in self.__HIDE_OS_FILES_RULES:
            match = {'rule-uuid': rule['rule-uuid']}
            if value == 'true':
                if not self.get_rules('advanced-inv-exclusion', match):
                    self.add_rule(rule)
            else:
                self.remove_rules('advanced-inv-exclusion', match)
        return True

    hide_windows_os_files = property(get_hide_windows_os_files, set_hide_windows_os_files)

    #   Pull Complete Inventory Interval: <n> days between consecutive inventory
    #   pulls (stored in seconds by ePO)
    def get_pull_inventory_interval(self):
        """
        Get Pull Complete Inventory Interval (days)
        """
        value = self.get_config('PullInvTimeout')
        return str(int(value) // 86400) if value is not None else None

    def set_pull_inventory_interval(self, days):
        """
        Set Pull Complete Inventory Interval (days)
        """
        days = check_int('Pull Complete Inventory Interval (days)', days, 1, 180)
        return self.set_config('PullInvTimeout', str(days * 86400))

    pull_inventory_interval = property(get_pull_inventory_interval, set_pull_inventory_interval)

    #   Receive Inventory Updates Interval: <n> hours (stored in seconds by ePO)
    def get_inventory_updates_interval(self):
        """
        Get Receive Inventory Updates Interval (hours)
        """
        value = self.get_config('InvDiffTimeout')
        return str(int(value) // 3600) if value is not None else None

    def set_inventory_updates_interval(self, hours):
        """
        Set Receive Inventory Updates Interval (hours)
        """
        hours = check_int('Receive Inventory Updates Interval (hours)', hours, 1, 180)
        return self.set_config('InvDiffTimeout', str(hours * 3600))

    inventory_updates_interval = property(get_inventory_updates_interval,
                                          set_inventory_updates_interval)

    # ------------------------------ REPUTATION TAB ------------------------------
    #   Reputation:
    #     Use Trellix Threat Intelligence Exchange (TIE) server (Windows only)
    def get_tie_reputation(self):
        """
        Get state of Use Trellix Threat Intelligence Exchange (TIE) server
        """
        return self.get_feature('tie-reputation')

    def set_tie_reputation(self, value):
        """
        Set state of Use Trellix Threat Intelligence Exchange (TIE) server
        """
        return self.set_feature('tie-reputation', value)

    tie_reputation = property(get_tie_reputation, set_tie_reputation)

    #       TIE Enterprise Trust Level (Windows only, '1' or '0')
    def get_tie_enterprise_trust_level(self):
        """
        Get state of TIE Enterprise Trust Level
        """
        return self.get_config('TieEnterpriseLevelTrustEnable')

    def set_tie_enterprise_trust_level(self, value):
        """
        Set state of TIE Enterprise Trust Level
        """
        return self.set_config('TieEnterpriseLevelTrustEnable', value)

    tie_enterprise_trust_level = property(get_tie_enterprise_trust_level, set_tie_enterprise_trust_level)

    #     Use Trellix Global Threat Intelligence (Trellix GTI)
    def get_gti_reputation(self):
        """
        Get state of Use Trellix Global Threat Intelligence (Trellix GTI)
        """
        return self.get_feature('gti-reputation')

    def set_gti_reputation(self, value):
        """
        Set state of Use Trellix Global Threat Intelligence (Trellix GTI)
        """
        return self.set_feature('gti-reputation', value)

    gti_reputation = property(get_gti_reputation, set_gti_reputation)

    #   Reputation-Based Execution Settings:
    #     Allow files with <level> and above ('1' or '0')
    def get_allow_by_reputation(self):
        """
        Get state of Allow files with <level> and above
        """
        return self.get_config('AllowBinariesByReputation')

    def set_allow_by_reputation(self, value):
        """
        Set state of Allow files with <level> and above
        """
        return self.set_config('AllowBinariesByReputation', value)

    allow_by_reputation = property(get_allow_by_reputation, set_allow_by_reputation)

    #       <level> (Use SCReputation class from constants)
    def get_allow_reputation_level(self):
        """
        Get the reputation level of Allow files with <level> and above
        """
        return self.get_config('AllowReputationLevel')

    def set_allow_reputation_level(self, value):
        """
        Set the reputation level of Allow files with <level> and above
        """
        return self.set_config('AllowReputationLevel', value)

    allow_reputation_level = property(get_allow_reputation_level, set_allow_reputation_level)

    #     Ban files with <level> and below ('1' or '0')
    def get_ban_by_reputation(self):
        """
        Get state of Ban files with <level> and below
        """
        return self.get_config('BlockBinariesByReputation')

    def set_ban_by_reputation(self, value):
        """
        Set state of Ban files with <level> and below
        """
        return self.set_config('BlockBinariesByReputation', value)

    ban_by_reputation = property(get_ban_by_reputation, set_ban_by_reputation)

    #       <level> (Use SCReputation class from constants)
    def get_ban_reputation_level(self):
        """
        Get the reputation level of Ban files with <level> and below
        """
        return self.get_config('BlockReputationLevel')

    def set_ban_reputation_level(self, value):
        """
        Set the reputation level of Ban files with <level> and below
        """
        return self.set_config('BlockReputationLevel', value)

    ban_reputation_level = property(get_ban_reputation_level, set_ban_reputation_level)

    #   Advanced Threat Defense (ATD) Settings (Windows only):
    #     Send files with <level> and below reputation for analysis ('1' or '0')
    def get_atd_submission(self):
        """
        Get state of Send files to ATD for analysis
        """
        return self.get_config('IsATDSubmissionAllowed')

    def set_atd_submission(self, value):
        """
        Set state of Send files to ATD for analysis
        """
        return self.set_config('IsATDSubmissionAllowed', value)

    atd_submission = property(get_atd_submission, set_atd_submission)

    #       <level> (Use SCReputation class from constants)
    def get_atd_reputation_level(self):
        """
        Get the reputation level of files sent to ATD for analysis
        """
        return self.get_config('ATDReputationLevel')

    def set_atd_reputation_level(self, value):
        """
        Set the reputation level of files sent to ATD for analysis
        """
        return self.set_config('ATDReputationLevel', value)

    atd_reputation_level = property(get_atd_reputation_level, set_atd_reputation_level)

    #     Limit file size to <n> (1 - 10) MB
    def get_atd_file_size_limit(self):
        """
        Get the size limit (MB) of files sent to ATD
        """
        return self.get_config('ATDFileSizeLimit')

    def set_atd_file_size_limit(self, value):
        """
        Set the size limit (MB) of files sent to ATD (1-10)
        """
        return self.set_config('ATDFileSizeLimit',
                               str(check_int('ATD file size limit (MB)', value, 1, 10)))

    atd_file_size_limit = property(get_atd_file_size_limit, set_atd_file_size_limit)

    # Hidden settings (confirmed not shown in the ePO console):
    def __get_critical_process_list(self):
        """
        Get Hidden setting - CriticalProcList (comma-separated process names)
        """
        return self.get_config('CriticalProcList')

    def __get_gti_target_url(self):
        """
        Get Hidden setting - GtiTargetURL
        """
        return self.get_config('GtiTargetURL')


    # ------------------------------ Markdown export ------------------------------
    # One section per console tab (Solidcore > Application Control >
    # Application Control Options, ePO 5.10 console labels). The Unix policy
    # only has the Reputation tab, without TIE and ATD. See Policy.to_markdown().
    REPUTATIONS = {'99': 'Known Trusted', '85': 'Most Likely Trusted', '70': 'Might be Trusted',
                   '50': 'Unknown', '30': 'Might be Malicious', '15': 'Most Likely Malicious',
                   '1': 'Known Malicious'}
    # Messages of the End User Notifications tab, in the console order.
    MESSAGE_EVENTS = [('ACTX_INSTALL_PREVENTED', 'ActiveX Installation Prevented'),
                      ('BLOCKED_PROCESS_INTERACTIVE_MODE', 'Blocked Interactive Mode of Process'),
                      ('EXECUTION_DENIED', 'Execution Denied'),
                      ('NX_VIOLATION_DETECTED', 'Nx Violation Detected'),
                      ('PKG_MODIFICATION_PREVENTED', 'Installation Denied'),
                      ('PREVENTED_FILE_EXECUTION', 'Prevented File Execution'),
                      ('PROCESS_HIJACKED', 'Process Hijack Attempted'),
                      ('READ_DENIED', 'File Read Denied'),
                      ('VASR_VIOLATION_DETECTED', 'VASR Violation Detected'),
                      ('WRITE_DENIED', 'File Write Denied')]

    @property
    def MD_CATEGORY(self):
        return 'Application Control Options ({})'.format('Unix' if self.is_unix() else 'Windows')

    def __md_level(self, value):
        return None if value is None else self.REPUTATIONS.get(value, value)

    def __md_reputation(self):
        flag = self.md_flag
        rows = []
        if not self.is_unix():
            rows += [['Use Trellix Threat Intelligence Exchange (TIE) server',
                      flag(self.get_tie_reputation())],
                     ['TIE Enterprise Trust Level', flag(self.get_tie_enterprise_trust_level())]]
        rows.append(['Use Trellix Global Threat Intelligence (Trellix GTI)',
                     flag(self.get_gti_reputation())])
        text = self.md_group('Reputation', rows)
        level = lambda enabled, value, suffix: None if enabled is None else (
            '{} {}'.format(self.__md_level(value), suffix) if enabled == '1' else 'No')
        text += '\n' + self.md_group('Reputation-Based Execution Settings', [
            ['Allow files with', level(self.get_allow_by_reputation(),
                                       self.get_allow_reputation_level(), 'and above')],
            ['Ban files with', level(self.get_ban_by_reputation(),
                                     self.get_ban_reputation_level(), 'and below')]])
        if not self.is_unix():
            rows = [['Send files with', level(self.get_atd_submission(),
                                              self.get_atd_reputation_level(),
                                              'and below reputation for analysis')]]
            if self.get_atd_submission() == '1':
                rows.append(['Limit file size to (1 - 10) MB', self.get_atd_file_size_limit()])
            text += '\n' + self.md_group('Advanced Threat Defense (ATD) Settings', rows)
        return text

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        if self.is_unix():
            return [('Reputation', self.__md_reputation())]
        flag = self.md_flag
        enabled = self.get_self_approval()
        rows = [['Enable Self-Approval', flag(enabled)]]
        if enabled == '1':
            optional = self.get_justification_optional()
            rows += [['Self-Approval Text', self.get_self_approval_text()],
                     ['Dialog Timeout (secs)', self.get_self_approval_timeout()],
                     ['Justification Message', None if optional is None else
                      ('Optional' if optional == '1' else 'Mandatory')],
                     ['Advanced Options: allow execution and update of files not included in '
                      'the allow list at boot time', flag(self.get_self_approval_at_boot())]]
        self_approval = self.md_settings(rows)
        notifications = 'Notify local users when detections occur and specify what actions ' \
                        'can be taken.\n\n' + self.md_settings([
                            ['User Message: Show the messages dialog box when an event is '
                             'detected and display the specified text in the message.',
                             flag(self.get_user_message())]])
        notifications += '\n' + self.md_group('Helpdesk Information', [
            ['Mail to', self.get_helpdesk_mail_to()],
            ['Mail Subject', self.get_helpdesk_mail_subject()],
            ['Link to Website', self.get_helpdesk_website()],
            ['Trellix ePO IP Address and Port', self.get_helpdesk_epo_address()]])
        events = self.get_message_events()
        known = [name for name, _ in self.MESSAGE_EVENTS]
        rows = [[label, self.get_message(name), flag(self.get_message_show_in_dialog(name))]
                for name, label in self.MESSAGE_EVENTS if name in events]
        rows += [[name, self.get_message(name), flag(self.get_message_show_in_dialog(name))]
                 for name in events if name not in known]
        notifications += '\n### Messages\n\n' + self.md_table(
            ['Event', 'Message', 'Show Event in Dialog'], rows)
        features = self.md_group('Feature Control', [
            ['Enforce feature control from Trellix ePO', flag(self.get_enforce_feature_control())],
            ['Execution Control', flag(self.get_execution_control())],
            ['Memory Protection (reboot required)', flag(self.get_memory_protection())],
            ['CASP (reboot required)', flag(self.get_memory_protection_casp())],
            ['NX (64-Bit) (reboot required)', flag(self.get_memory_protection_nx())],
            ['Generate Observations', flag(self.get_generate_observations())],
            ['Package Control', flag(self.get_package_control())],
            ['Bypass Package Control', flag(self.get_bypass_package_control())],
            ['Allow Uninstallation', flag(self.get_allow_uninstallation())],
            ['Script as Updater (SAU) (reboot required)', flag(self.get_script_as_updater())]])
        inventory = self.md_settings([
            ['Hide Windows OS Files (inventory items signed with Microsoft certificates will '
             'not be sent to Trellix ePO)', flag(self.get_hide_windows_os_files())],
            ['Pull Complete Inventory Interval (days between consecutive inventory pulls)',
             self.get_pull_inventory_interval()],
            ['Receive Inventory Updates Interval (hours)', self.get_inventory_updates_interval()]])
        return [('Self-Approval', self_approval), ('End User Notifications', notifications),
                ('Features', features), ('Inventory', inventory),
                ('Reputation', self.__md_reputation())]


class SCAWLRules(SCExclusionRules, SCUpdaterRules):
    """
    SCAWLRules gives the methods of the Application Control Rules tabs of the ePO
    console, for Application Control Rules policies (SCAWLPolicyRules) and
    Application Control Rule Groups (SCAWLRuleGroup). Each tab is a list of
    rules, returned as raw rule dicts by the get_* methods (see SCRules).
    """

    # ------------------------------ CERTIFICATES TAB ------------------------------
    #   Columns: Issued To, Issued By, Expiration Date, Friendly Name, Updater,
    #   Updater Label. ePO stores the PEM certificate split in 2048 characters
    #   chunks (pem_1, pem_2...); the console extracts the other columns from it.
    #   Friendly Name is a Windows certificate store label, not part of the PEM:
    #   the console always shows it empty (24 certificates checked on the ePO
    #   5.10 lab), so the Markdown export leaves it out.
    __PEM_CHUNK = 2048

    def get_certificates(self):
        """
        Get the list of certificates, as dicts {'id', 'pem', 'label', 'updater'}
        ('updater' is 'Yes', 'No' or None).
        """
        certificates = []
        for rule in self.get_rules('cert'):
            chunks = []
            index = 1
            while 'pem_{}'.format(index) in rule:
                chunks.append(rule['pem_{}'.format(index)])
                index += 1
            certificates.append({'id': rule.get('id'), 'pem': ''.join(chunks),
                                 'label': rule.get('tag'), 'updater': rule.get('updater')})
        return certificates

    def add_certificate(self, pem, label=None, updater=False):
        """
        Add a certificate (PEM text). If updater is True, the certificate is also
        used as an updater, with the Updater Label label.
        """
        ids = [int(r['id']) for r in self.get_rules('cert') if r.get('id', '').isdigit()]
        rule = {'type': 'cert', 'id': str(max(ids) + 1 if ids else 1), 'pem_length': str(len(pem))}
        for index in range(0, len(pem), self.__PEM_CHUNK):
            rule['pem_{}'.format(index // self.__PEM_CHUNK + 1)] = pem[index:index + self.__PEM_CHUNK]
        if updater:
            rule['updater'] = 'Yes'
            rule['tag'] = label if label else ''
        return self.add_rule(rule)

    def remove_certificate(self, cert_id):
        """
        Remove a certificate by its id (as returned by get_certificates()).
        """
        return self.remove_rules('cert', {'id': str(cert_id)}) > 0

    # ------------------------------ INSTALLERS TAB ------------------------------
    #   Columns: Installer Name, Type, SHA-1/SHA-256, Version, Vendor, Installer Label.
    #   ePO stores Installer Name and Version together as "<name>\<version>".
    def get_installers(self):
        """
        Get the list of installers ('installer' rules not shown as updaters).
        """
        return [r for r in self.get_rules('installer') if r.get('showas') != 'updater']

    def add_installer(self, checksum, label, name='', version='', vendor=''):
        """
        Add an installer by its SHA-1 or SHA-256 checksum. The label takes
        1024 characters (server check).
        """
        key = self._checksum_key(checksum)
        label = check_length('Installer Label', str(label).strip(), 1024, required=True)
        return self.add_rule({'type': 'installer', key: checksum.lower(), 'tag': label,
                              'ruletype': 'checksum', 'vendor': vendor,
                              'version': '{}\\{}'.format(name, version)})

    def remove_installer(self, label):
        """
        Remove the installer(s) with an Installer Label.
        """
        return sum(self.remove_rules('installer', r) for r in self.get_installers()
                   if r.get('tag') == label)

    # ------------------------------ DIRECTORIES TAB ------------------------------
    #   Columns: Path, Action (Include/Exclude), Updater (trusted directories).
    def get_trusted_directories(self):
        """
        Get the list of trusted directories ('trusted' rules).
        """
        return self.get_rules('trusted')

    def add_trusted_directory(self, path, include=True, updater=False):
        """
        Add a trusted directory (Action Include or Exclude, Updater or not).
        As in the console, the path is required and trimmed, 255 characters
        (server check), checked on Windows by is_sc_directory.
        """
        path = check_length('Path', str(path).strip(), 255, required=True)
        if not is_sc_directory(path, 'UNIX' if self.is_unix() else 'WIN'):
            raise ValueError('Invalid trusted directory (see is_sc_directory): {!r}'.format(path))
        return self.add_rule({'type': 'trusted', 'path': path,
                              'action': 'Include' if include else 'Exclude',
                              'updater': self._bool(updater)})

    def remove_trusted_directory(self, path):
        """
        Remove a trusted directory.
        """
        return self.remove_rules('trusted', {'path': path}) > 0

    # ------------------------------ UPDATER PROCESSES AND USERS TABS ------------------------------
    #   See SCUpdaterRules (get_updaters, add_updater, add_updater_by_checksum,
    #   remove_updater, get_trusted_users, add_trusted_user, remove_trusted_user).

    # ------------------------------ EXECUTABLE FILES TAB ------------------------------
    #   Columns: Rule Name, Allow/Ban, Type (File Name/SHA-1/SHA-256), Value.
    #   A rule by file name (deprecated in the console) is an 'attr' rule with
    #   always_auth (Allow) or always_unauth (Ban), a rule by checksum an
    #   'auth-cksum' rule.
    def get_executable_files(self):
        """
        Get the list of executable file rules, as dicts {'name' (Rule Name),
        'action' ('Allow' or 'Ban'), 'type' ('name', 'sha1' or 'sha256'), 'value'}.
        """
        files = []
        for rule in self.get_rules('attr'):
            for key, action in (('always_auth', 'Allow'), ('always_unauth', 'Ban')):
                if rule.get(key) == 'true':
                    files.append({'name': rule.get('tag'), 'action': action,
                                  'type': 'name', 'value': rule.get('file')})
        for rule in self.get_rules('auth-cksum'):
            key = 'cksum' if 'cksum' in rule else 'cksum256'
            files.append({'name': rule.get('tag'), 'action': rule.get('action'),
                          'type': 'sha1' if key == 'cksum' else 'sha256', 'value': rule.get(key)})
        return files

    def add_executable_file(self, rule_name, value, ban=False):
        """
        Add an executable file rule. value is a SHA-1 or SHA-256 checksum, or else
        a file name (File Name rule type, deprecated in the console). The
        rule name and the value are required and trimmed, 255 characters
        (server check).
        """
        rule_name = check_length('Rule Name', str(rule_name).strip(), 255, required=True)
        value = check_length('Value', str(value).strip(), 255, required=True)
        try:
            key = self._checksum_key(value)
        except ValueError:
            return self.add_rule({'type': 'attr', 'file': value, 'tag': rule_name,
                                  'always_unauth' if ban else 'always_auth': 'true'})
        return self.add_rule({'type': 'auth-cksum', key: value.lower(), 'tag': rule_name,
                              'action': 'Ban' if ban else 'Allow'})

    def remove_executable_file(self, rule_name):
        """
        Remove the executable file rule(s) with a Rule Name.
        """
        count = self.remove_rules('auth-cksum', {'tag': rule_name})
        for rule in self.get_rules('attr', {'tag': rule_name}):
            if rule.get('always_auth') == 'true' or rule.get('always_unauth') == 'true':
                count += self.remove_rules('attr', rule)
        return count

    # ------------------------------ EXCLUSIONS TAB ------------------------------
    #   Same exclusions as the Exception Rules policy: see SCExclusionRules
    #   (get_exclusion_list, add_exclusion, remove_exclusion, contains_exclusion).

    # ------------------------------ FILTERS TAB ------------------------------
    #   Each filter is a list of conditions (AND), returned as dicts
    #   {'condition', 'match', 'pattern'} (see SCPolicy.get_conditions()).
    # Policy Discovery & Events: conditions File, Event, Process (Program), Reg
    # (Registry), User; match equals, begins, ends, contains, doesnt_contain.
    # A filter is an 'ob-exclusion' rule, plus a 'mon-advanced' rule with the
    # same rule-uuid when "Apply rule to events also" is checked.
    def get_filters(self):
        """
        Get the list of Policy Discovery & Events filters, as dicts {'uuid',
        'conditions', 'apply_to_events'}.
        """
        events = set(r.get('rule-uuid') for r in self.get_rules('mon-advanced'))
        return [{'uuid': r.get('rule-uuid'), 'conditions': self.get_conditions(r),
                 'apply_to_events': r.get('rule-uuid') in events}
                for r in self.get_rules('ob-exclusion')]

    def add_filter(self, conditions, apply_to_events=False):
        """
        Add a Policy Discovery & Events filter.

        :param: conditions: A list of (condition, match, pattern) tuples or dicts,
                            e.g. [('Process', 'equals', 'setup.exe')].
        :param: apply_to_events: "Apply rule to events also" checkbox.
        :return: The rule-uuid of the new filter.
        """
        rule_uuid = str(uuid.uuid4())
        rule = {'action': 'exclude', 'rule-uuid': rule_uuid}
        rule.update(self.make_conditions(conditions))
        self.add_rule(dict(rule, type='ob-exclusion'))
        if apply_to_events:
            self.add_rule(dict(rule, type='mon-advanced'))
        return rule_uuid

    def remove_filter(self, rule_uuid):
        """
        Remove a Policy Discovery & Events filter by its rule-uuid.
        """
        count = self.remove_rules('ob-exclusion', {'rule-uuid': rule_uuid})
        count += self.remove_rules('mon-advanced', {'rule-uuid': rule_uuid})
        return count > 0

    # Inventory: conditions File, Type (File type), app-name, app-version,
    # vendor-name, has-certificate; match equals, begins, ends, contains.
    # A filter is an 'advanced-inv-exclusion' rule.
    def get_inventory_filters(self):
        """
        Get the list of Inventory filters, as dicts {'uuid', 'conditions'}.
        """
        return [{'uuid': r.get('rule-uuid'), 'conditions': self.get_conditions(r)}
                for r in self.get_rules('advanced-inv-exclusion')]

    def add_inventory_filter(self, conditions):
        """
        Add an Inventory filter (see add_filter for conditions).

        :return: The rule-uuid of the new filter.
        """
        rule_uuid = str(uuid.uuid4())
        rule = {'type': 'advanced-inv-exclusion', 'action': 'exclude', 'rule-uuid': rule_uuid}
        rule.update(self.make_conditions(conditions))
        self.add_rule(rule)
        return rule_uuid

    def remove_inventory_filter(self, rule_uuid):
        """
        Remove an Inventory filter by its rule-uuid.
        """
        return self.remove_rules('advanced-inv-exclusion', {'rule-uuid': rule_uuid}) > 0

    # ------------------------------ EXECUTION CONTROL TAB ------------------------------
    #   Columns: Rule Description, Action, Process Name, Path, Command Line
    #   Argument, Parent Process Name, User Name.
    #   Action "Based on specified attributes" ('allow', 'block' or 'monitor') is an
    #   'execution-control' rule whose conditions are:
    #     'path', 'parent_process_name', 'user'      match 'equals' or 'notEquals'
    #     'command_line'   match 'noArgSpecified', 'equals', 'notEquals', 'matches'
    #                      or 'notMatches'
    #   Action "Block interactive mode for console-based process" is an 'attr'
    #   rule with block_interactive.
    def get_execution_control_rules(self):
        """
        Get the list of Execution Control rules, as dicts {'process_name', 'action',
        'conditions', 'description'}; action is 'block_interactive' for "Block
        interactive mode for console-based process".
        """
        rules = [{'process_name': r.get('process-name'), 'action': r.get('action'),
                  'conditions': self.get_conditions(r), 'description': r.get('rule-description')}
                 for r in self.get_rules('execution-control')]
        rules += [{'process_name': r.get('file'), 'action': 'block_interactive',
                   'conditions': [], 'description': None}
                  for r in self.get_rules('attr', {'block_interactive': 'true'})]
        return rules

    def add_execution_control_rule(self, process_name, action='block', conditions=(),
                                   description=''):
        """
        Add an Execution Control rule.

        :param: process_name: Process Name.
        :param: action: 'allow', 'block', 'monitor' or 'block_interactive'.
        :param: conditions: A list of (condition, match, pattern) tuples or dicts,
                            e.g. [('command_line', 'matches', '.*-enc.*')].
        :param: description: Rule Description.
        """
        process_name = check_length('Process Name', str(process_name).strip(), 260, required=True)
        if not is_sc_file_name(process_name):
            raise ValueError('Invalid process name (see is_sc_file_name): {!r}'.format(process_name))
        check_length('Rule Description', description or '', 260)
        if action != 'block_interactive':
            self.__check_execution_conditions(conditions)
        if action == 'block_interactive':
            return self.add_rule({'type': 'attr', 'file': process_name,
                                  'block_interactive': 'true'})
        if action not in ('allow', 'block', 'monitor'):
            raise ValueError('Action must be "allow", "block", "monitor" or "block_interactive".')
        rule = {'type': 'execution-control', 'process-name': process_name, 'action': action,
                'rule-description': description}
        rule.update(self.make_conditions(conditions))
        return self.add_rule(rule)

    @staticmethod
    def __check_execution_conditions(conditions):
        """
        The checks of the Execution Control dialog: at least one attribute,
        none empty but a command line with 'noArgSpecified'; the path is
        checked by is_sc_execution_path, the parent process name by
        is_sc_file_name.
        """
        if not conditions:
            raise ValueError('An Execution Control rule needs at least one attribute (path, '
                             'command line, parent process name or user name).')
        for condition in conditions:
            if isinstance(condition, dict):
                condition = (condition['condition'], condition['match'], condition['pattern'])
            name, match, pattern = condition[0], condition[1], str(condition[2] or '')
            if name == 'command_line' and match == 'noArgSpecified':
                continue
            if not pattern.strip():
                raise ValueError('Applicable fields cannot be empty: {}'.format(name))
            if name == 'path' and not is_sc_execution_path(pattern):
                raise ValueError('Invalid path (see is_sc_execution_path): {!r}'.format(pattern))
            if name == 'parent_process_name' and not is_sc_file_name(pattern):
                raise ValueError('Invalid parent process name: {!r}'.format(pattern))

    def remove_execution_control_rules(self, process_name):
        """
        Remove all the Execution Control rules of a Process Name.

        :return: The number of rules removed.
        """
        return (self.remove_rules('execution-control', {'process-name': process_name}) +
                self.remove_rules('attr', {'file': process_name, 'block_interactive': 'true'}))


    # ------------------------------ Markdown export ------------------------------
    # Tabs of the console (Application Control Rules), with their columns
    # (ePO 5.10). Unix: Updater Processes, Directories, Executable Files,
    # Exclusions and Filters (events only).
    EXECUTION_ACTIONS = {'allow': 'Allow', 'block': 'Block', 'monitor': 'Monitor',
                         'block_interactive': 'Block interactive mode'}
    EXECUTION_MATCHES = {'equals': 'Equals', 'notEquals': 'Not equals',
                         'noArgSpecified': 'No argument specified', 'matches': 'Matches',
                         'notMatches': 'Not matches'}
    EXECUTABLE_TYPES = {'name': 'File Name', 'sha1': 'File SHA-1', 'sha256': 'File SHA-256'}

    @staticmethod
    def md_certificate(pem):
        """
        Returns (Issued To, Issued By, Expiration Date) of a PEM certificate,
        as computed by the console (subject and issuer common names; the
        expiration date in UTC, the console shows it in the browser time
        zone), or None if it can't be decoded (uses the certificate decoder
        of the Python ssl module). The full common name is kept: the console
        cuts it at the first comma (e.g. "McAfee" for "McAfee, Inc." or
        "McAfee, LLC"), a display bug seen on the ePO 5.10 lab.
        """
        try:
            import os
            import ssl
            import tempfile
            with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as pem_file:
                pem_file.write(pem)
            try:
                info = ssl._ssl._test_decode_cert(pem_file.name)
            finally:
                os.remove(pem_file.name)
            name = lambda rdns: dict(item for rdn in rdns for item in rdn).get('commonName')
            import datetime
            expiration = datetime.datetime.fromtimestamp(
                ssl.cert_time_to_seconds(info['notAfter']), datetime.timezone.utc)
            return (name(info['subject']), name(info['issuer']),
                    expiration.strftime('%Y-%m-%d %H:%M:%S UTC'))
        except Exception:
            return None

    def __md_certificates(self, table):
        rows = []
        for cert in self.get_certificates():
            decoded = self.md_certificate(cert['pem']) if cert['pem'] else None
            if decoded is None:
                import base64
                import hashlib
                body = ''.join(line for line in cert['pem'].splitlines() if '-----' not in line)
                try:
                    thumbprint = hashlib.sha1(base64.b64decode(body)).hexdigest()
                except Exception:
                    thumbprint = ''
                decoded = ('SHA-1 ' + thumbprint, '', '')
            rows.append(list(decoded) + [cert['updater'] or 'No', cert['label'] or ''])
        return table(['Issued To', 'Issued By', 'Expiration Date', 'Updater', 'Updater Label'],
                     rows)

    def __md_execution_control(self, table):
        rows = []
        for rule in self.get_execution_control_rules():
            cells = {}
            for condition in rule['conditions']:
                cells[condition['condition']] = '{} : {}'.format(
                    self.EXECUTION_MATCHES.get(condition['match'], condition['match']),
                    condition['pattern'] or '')
            rows.append([rule['description'] or '',
                         self.EXECUTION_ACTIONS.get(rule['action'], rule['action']),
                         rule['process_name'], cells.get('path', ''),
                         cells.get('command_line', ''), cells.get('parent_process_name', ''),
                         cells.get('user', '')])
        return table(['Rule Description', 'Action', 'Process Name', 'Path',
                      'Command Line Argument', 'Parent Process Name', 'User Name'], rows)

    def md_tabs(self):
        """
        Returns the console tabs of the rules as Markdown ("###" per tab).
        """
        table = Policy.md_table
        unix = self.is_unix()
        tabs = [('Updater Processes', self.md_updaters_table(table))]
        if not unix:
            installers = []
            for rule in self.get_installers():
                key = 'cksum' if 'cksum' in rule else 'cksum256'
                name, _, version = (rule.get('version') or '').rpartition('\\')
                installers.append([name, 'SHA-1' if key == 'cksum' else 'SHA-256',
                                   rule.get(key), version, rule.get('vendor'), rule.get('tag')])
            tabs += [('Certificates', self.__md_certificates(table)),
                     ('Installers', table(['Installer Name', 'Type', 'SHA-1/SHA-256', 'Version',
                                           'Vendor', 'Installer Label'], installers))]
        directories = [[rule.get('path'), rule.get('action')] +
                       ([] if unix else ['Yes' if rule.get('updater') == 'true' else 'No'])
                       for rule in self.get_trusted_directories()]
        tabs.append(('Directories', table(['Path', 'Action'] + ([] if unix else ['Updater']),
                                          directories)))
        if not unix:
            tabs.append(('Users', self.md_users_table(table)))
        tabs += [('Executable Files', table(
                     ['Rule Name', 'Allow/Ban', 'Type', 'Value'],
                     [[rule['name'], rule['action'], self.EXECUTABLE_TYPES.get(rule['type']),
                       rule['value']] for rule in self.get_executable_files()])),
                 ('Exclusions', self.md_exclusions_table(table))]
        filters = '#### {}\n\n'.format('Events' if unix else 'Policy Discovery & Events')
        filters += table(['Conditions', 'Apply rule to events also'],
                         [[self.md_conditions(f['conditions']),
                           'Yes' if f['apply_to_events'] else 'No'] for f in self.get_filters()],
                         numbered=True)
        if not unix:
            filters += '\n#### Inventory\n\n' + table(
                ['Conditions'], [[self.md_conditions(f['conditions'])]
                                 for f in self.get_inventory_filters()], numbered=True)
        tabs.append(('Filters', filters))
        if not unix:
            tabs.append(('Execution Control', self.__md_execution_control(table)))
        return '\n'.join('### {}\n\n{}'.format(title, body) for title, body in tabs)

class SCAWLPolicyRules(SCAWLRules, SCPolicy):
    """
    The SCAWLPolicyRules class can be used to edit the Solidcore policies:
    Application Control > Application Control Rules (Windows) and (Unix).

    Note: ePO stores these policies under the internal types "AWL Rules (Windows)"
    and "AWL Rules (Unix)". Only the policy's own rules ("My Rules") are edited;
    the shared Rule Groups it references are listed by get_rule_group_names()
    and can be removed from the policy with remove_rule_group().
    Each tab of the console is a list of rules, returned as raw rule dicts by the
    get_* methods (see SCPolicy.get_rules() for the settings of a rule).
    """

    TYPE_IDS = ('AWL Rules (Windows)', 'AWL Rules (Unix)')

    @property
    def MD_CATEGORY(self):
        return 'Application Control Rules ({})'.format('Unix' if self.is_unix() else 'Windows')

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples:
        the Rule Groups, then the tabs of each rule group (see
        Policy.to_markdown).
        """
        return self.md_rule_group_sections(self.md_tabs)
