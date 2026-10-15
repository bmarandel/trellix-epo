# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESATPPolicyOptions (Endpoint Security Adaptive
Threat Protection: Options).

Storage learnt from a test policy changed in the ePO 5.10 console (all the
settings are in the General section):

- "Enable Adaptive Threat Protection" and its "Enable Observe mode" are one
  setting, operationMode: 0 = disabled, 1 = enabled, 2 = enabled in Observe
  mode. In Observe mode the console checks and locks the Observe mode of the
  enhanced script scanning and of the Credential Theft Protection.
- Reputation thresholds (containLevel, blockLevel, repairLevel, promptLevel,
  atdLevel) are reputation levels: 85 Most Likely Trusted, 70 Might be
  Trusted, 50 Unknown, 30 Might be Malicious, 15 Most Likely Malicious,
  1 Known Malicious. The console refuses to save when an enabled action has
  a threshold above the one of a "stronger" enabled action (Clean <= Block
  <= Contain <= Notify).
- The user message is customPromptText with customPromptTextEnabled = 1;
  when the message is empty, the console shows (and the client uses) its
  default message.
"""

from ...policies import Policy
from ...validators import check_int, check_length


class ESATPPolicyOptions(Policy):
    """
    The ESATPPolicyOptions class can be used to edit the Endpoint Security
    Adaptive Threat Protection policy: Options (checked against the ePO 5.10
    console).
    """

    MD_PRODUCT = 'Endpoint Security Adaptive Threat Protection'
    MD_CATEGORY = 'Options'
    TYPE = 'General'

    DISABLED, ENABLED, OBSERVE = '0', '1', '2'
    REPUTATIONS = {'85': 'Most Likely Trusted', '70': 'Might be Trusted', '50': 'Unknown',
                   '30': 'Might be Malicious', '15': 'Most Likely Malicious',
                   '1': 'Known Malicious'}
    # Thresholds offered by the console for each action.
    CONTAIN_LEVELS = BLOCK_LEVELS = ['70', '50', '30', '15', '1']
    CLEAN_LEVELS = ['30', '15', '1']
    NOTIFY_LEVELS = ['85', '70', '50', '30', '15', '1']
    SANDBOX_LEVELS = ['85', '50', '15']
    SENSITIVITY_LEVELS = {'0': 'Low', '1': 'Medium', '2': 'High'}
    RULE_GROUPS = {'Low': 'Productivity', 'Medium': 'Balanced', 'High': 'Security'}
    # Description shown by the console under the rule group selection.
    RULE_GROUP_TEXTS = {
        'Low': 'Use the Productivity rule group for high-change systems with frequent '
               'installations and updates of trusted software. This group uses the least number '
               'of rules. Users experience minimum prompts and blocks when new files are '
               'detected.',
        'Medium': 'Use the Balanced rule group for typical business systems with infrequent new '
                  'software and changes. This group uses more rules - and users experience more '
                  'prompts and blocks - than the Productivity group.',
        'High': 'Use the Security rule group for low-change systems, such as IT-managed systems '
                'and servers with tight control. This group uses the maximum number of rules. '
                'Users experience more prompts and blocks than with the Balanced group.'}
    REPUTATION_SOURCES = {'1': 'Use Trellix GTI if the TIE server is not reachable',
                          '0': 'Use only the TIE server', '2': 'Use only Trellix GTI'}
    DEFAULT_ACTIONS = {'0': 'Block', '1': 'Allow'}
    DEFAULT_MESSAGE = 'Trellix Endpoint Security detected a file with an unknown reputation.'

    # Checkbox settings: (setting name, console label).
    __CHECKBOXES = {
        'telemetry': 'Allow the Threat Intelligence Exchange server to collect anonymous '
                     'diagnostic and usage data',
        'networkScanEnabled': 'Scan processes started from network drives (Windows only)',
        'accessProtection': 'Prevent users from changing settings (Threat Intelligence '
                            'Exchange 1.0 clients only) (Windows only)',
        'allowDisableViaMcTray': 'Allow users to disable Adaptive Threat Protection from the '
                                 'Trellix system tray icon',
        'realProtectStaticEnabled': 'Enable client-based scanning',
        'realProtectStaticOfflineModeEnabled': 'Enable offline scanning (Might result in '
                                               'increased false positives)',
        'realProtectEnabled': 'Enable cloud-based scanning',
        'ATP_AMSI_ENABLED': 'Enable enhanced script scanning (includes AMSI integration)',
        'ATPAMSIObserveMode': 'Enable Observe mode (Events are generated but actions are not '
                              'enforced)',
        'CTPEnabled': 'Enable Credential Theft Protection',
        'CTPObserveModeEnabled': 'Enable Observe mode (Events are generated but actions are '
                                 'not enforced)',
        'enhancedRemediationEnabled': 'Enable enhanced remediation',
        'enhancedRemFullMonitoringEnabled': 'Monitor and remediate deleted and changed files',
        'offlinePromptingDisabled': 'Disable threat notifications if the Threat Intelligence '
                                    'Exchange server is not reachable',
        'StoryGraphEnabled': 'Enable Story Graph Tracing',
    }
    # Reputation actions: name -> (enabled setting, level setting, levels, console label).
    __ACTIONS = {
        'contain': ('containEnabled', 'containLevel', CONTAIN_LEVELS,
                    'Trigger Dynamic Application Containment when reputation threshold '
                    'reaches (Windows only)'),
        'block': ('blockEnabled', 'blockLevel', BLOCK_LEVELS,
                  'Block when reputation threshold reaches'),
        'clean': ('repairEnabled', 'repairLevel', CLEAN_LEVELS,
                  'Clean when reputation threshold reaches'),
        'notify': ('promptEnabled', 'promptLevel', NOTIFY_LEVELS,
                   'Notify the user when reputation threshold reaches'),
    }

    def __init__(self, policy_from_esatppolicies=None):
        super(ESATPPolicyOptions, self).__init__(policy_from_esatppolicies)
        if policy_from_esatppolicies is not None:
            if self.get_type() != self.TYPE:
                raise ValueError('Wrong policy! Policy type must be "{}".'.format(self.TYPE))

    def __repr__(self):
        return 'ESATPPolicyOptions()'

    def get_option(self, setting):
        """
        Get the value of a setting of the policy, e.g. get_option('telemetry').
        """
        return self.get_setting_value('General', setting)

    def set_option(self, setting, value):
        """
        Set the value of an existing setting of the policy, e.g.
        set_option('telemetry', '0').
        """
        return self.set_setting_value('General', setting, str(value))

    @classmethod
    def options(cls):
        """
        Returns the checkbox options as a dict {setting name: console label}.
        """
        return dict(cls.__CHECKBOXES)

    def __check_mode(self, mode):
        if str(mode) not in ['0', '1']:
            raise ValueError('The state must be "1" or "0".')
        return str(mode)

    def __checkbox(self, setting, mode):
        return self.set_option(setting, self.__check_mode(mode))

    # ------------------------------ Adaptive Threat Protection ------------------------------
    def get_operation_mode(self):
        """
        Get the operation mode: DISABLED ('0'), ENABLED ('1') or OBSERVE ('2',
        enabled in Observe mode).
        """
        return self.get_option('operationMode')

    def set_operation_mode(self, mode):
        """
        Set the operation mode: DISABLED ('0'), ENABLED ('1') or OBSERVE ('2').
        As in the console, the Observe mode also turns on the Observe mode of
        the enhanced script scanning and of the Credential Theft Protection.
        """
        if str(mode) not in [self.DISABLED, self.ENABLED, self.OBSERVE]:
            raise ValueError('The operation mode must be "0", "1" or "2".')
        if str(mode) == self.OBSERVE:
            self.set_option('ATPAMSIObserveMode', '1')
            self.set_option('CTPObserveModeEnabled', '1')
        return self.set_option('operationMode', mode)

    operation_mode = property(get_operation_mode, set_operation_mode)

    def get_atp(self):
        """
        Get state of Enable Adaptive Threat Protection ('1' or '0').
        """
        mode = self.get_operation_mode()
        return None if mode is None else ('0' if mode == self.DISABLED else '1')

    def set_atp(self, mode):
        """
        Set state of Enable Adaptive Threat Protection ('1' or '0'). Disabling
        it also clears the Observe mode, as in the console.
        """
        if self.__check_mode(mode) == '0':
            return self.set_operation_mode(self.DISABLED)
        if self.get_operation_mode() == self.DISABLED:
            return self.set_operation_mode(self.ENABLED)
        return True

    atp = property(get_atp, set_atp)

    def get_observe_mode(self):
        """
        Get state of Enable Observe mode (Events are generated but actions are
        not enforced) (Windows only) ('1' or '0').
        """
        mode = self.get_operation_mode()
        return None if mode is None else ('1' if mode == self.OBSERVE else '0')

    def set_observe_mode(self, mode):
        """
        Set state of Enable Observe mode ('1' or '0'). Adaptive Threat
        Protection must be enabled.
        """
        mode = self.__check_mode(mode)
        if self.get_operation_mode() == self.DISABLED:
            raise ValueError('Enable Adaptive Threat Protection first.')
        return self.set_operation_mode(self.OBSERVE if mode == '1' else self.ENABLED)

    observe_mode = property(get_observe_mode, set_observe_mode)

    def get_telemetry(self):
        """
        Get state of Allow the Threat Intelligence Exchange server to collect
        anonymous diagnostic and usage data ('1' or '0').
        """
        return self.get_option('telemetry')

    def set_telemetry(self, mode):
        """
        Set state of Allow the Threat Intelligence Exchange server to collect
        anonymous diagnostic and usage data ('1' or '0').
        """
        return self.__checkbox('telemetry', mode)

    telemetry = property(get_telemetry, set_telemetry)

    def get_network_scan(self):
        """
        Get state of Scan processes started from network drives ('1' or '0').
        """
        return self.get_option('networkScanEnabled')

    def set_network_scan(self, mode):
        """
        Set state of Scan processes started from network drives ('1' or '0').
        """
        return self.__checkbox('networkScanEnabled', mode)

    network_scan = property(get_network_scan, set_network_scan)

    def get_prevent_changes(self):
        """
        Get state of Prevent users from changing settings (Threat Intelligence
        Exchange 1.0 clients only) ('1' or '0').
        """
        return self.get_option('accessProtection')

    def set_prevent_changes(self, mode):
        """
        Set state of Prevent users from changing settings (Threat Intelligence
        Exchange 1.0 clients only) ('1' or '0').
        """
        return self.__checkbox('accessProtection', mode)

    prevent_changes = property(get_prevent_changes, set_prevent_changes)

    def get_allow_disable_from_tray(self):
        """
        Get state of Allow users to disable Adaptive Threat Protection from
        the Trellix system tray icon ('1' or '0').
        """
        return self.get_option('allowDisableViaMcTray')

    def set_allow_disable_from_tray(self, mode):
        """
        Set state of Allow users to disable Adaptive Threat Protection from
        the Trellix system tray icon ('1' or '0').
        """
        return self.__checkbox('allowDisableViaMcTray', mode)

    allow_disable_from_tray = property(get_allow_disable_from_tray, set_allow_disable_from_tray)

    # ------------------------------ ML Protect Scanning (Windows only) ------------------------------
    def get_client_scanning(self):
        """
        Get state of Enable client-based scanning ('1' or '0').
        """
        return self.get_option('realProtectStaticEnabled')

    def set_client_scanning(self, mode):
        """
        Set state of Enable client-based scanning ('1' or '0').
        """
        return self.__checkbox('realProtectStaticEnabled', mode)

    client_scanning = property(get_client_scanning, set_client_scanning)

    def get_offline_scanning(self):
        """
        Get state of Enable offline scanning (Might result in increased false
        positives) ('1' or '0').
        """
        return self.get_option('realProtectStaticOfflineModeEnabled')

    def set_offline_scanning(self, mode):
        """
        Set state of Enable offline scanning (Might result in increased false
        positives) ('1' or '0').
        """
        return self.__checkbox('realProtectStaticOfflineModeEnabled', mode)

    offline_scanning = property(get_offline_scanning, set_offline_scanning)

    def get_sensitivity_level(self):
        """
        Get the client-based scanning Sensitivity level: '0' Low, '1' Medium,
        '2' High.
        """
        return self.get_option('rpSensitivityLevel')

    def set_sensitivity_level(self, level):
        """
        Set the client-based scanning Sensitivity level: '0' Low, '1' Medium,
        '2' High.
        """
        if str(level) not in self.SENSITIVITY_LEVELS:
            raise ValueError('Sensitivity level must be within {}.'.format(
                list(self.SENSITIVITY_LEVELS)))
        return self.set_option('rpSensitivityLevel', level)

    sensitivity_level = property(get_sensitivity_level, set_sensitivity_level)

    def get_cloud_scanning(self):
        """
        Get state of Enable cloud-based scanning ('1' or '0').
        """
        return self.get_option('realProtectEnabled')

    def set_cloud_scanning(self, mode):
        """
        Set state of Enable cloud-based scanning ('1' or '0').
        """
        return self.__checkbox('realProtectEnabled', mode)

    cloud_scanning = property(get_cloud_scanning, set_cloud_scanning)

    def get_script_scanning(self):
        """
        Get state of Enable enhanced script scanning (includes AMSI
        integration) ('1' or '0').
        """
        return self.get_option('ATP_AMSI_ENABLED')

    def set_script_scanning(self, mode):
        """
        Set state of Enable enhanced script scanning (includes AMSI
        integration) ('1' or '0').
        """
        return self.__checkbox('ATP_AMSI_ENABLED', mode)

    script_scanning = property(get_script_scanning, set_script_scanning)

    def get_script_scanning_observe(self):
        """
        Get state of the Observe mode of the enhanced script scanning ('1' or '0').
        """
        return self.get_option('ATPAMSIObserveMode')

    def set_script_scanning_observe(self, mode):
        """
        Set state of the Observe mode of the enhanced script scanning ('1' or
        '0'). Locked to '1' by the console in Observe mode (see
        set_operation_mode).
        """
        if self.__check_mode(mode) == '0' and self.get_operation_mode() == self.OBSERVE:
            raise ValueError('Adaptive Threat Protection is in Observe mode.')
        return self.set_option('ATPAMSIObserveMode', mode)

    script_scanning_observe = property(get_script_scanning_observe, set_script_scanning_observe)

    def get_credential_theft_protection(self):
        """
        Get state of Enable Credential Theft Protection ('1' or '0').
        """
        return self.get_option('CTPEnabled')

    def set_credential_theft_protection(self, mode):
        """
        Set state of Enable Credential Theft Protection ('1' or '0').
        """
        return self.__checkbox('CTPEnabled', mode)

    credential_theft_protection = property(get_credential_theft_protection,
                                           set_credential_theft_protection)

    def get_credential_theft_protection_observe(self):
        """
        Get state of the Observe mode of the Credential Theft Protection ('1' or '0').
        """
        return self.get_option('CTPObserveModeEnabled')

    def set_credential_theft_protection_observe(self, mode):
        """
        Set state of the Observe mode of the Credential Theft Protection ('1'
        or '0'). Locked to '1' by the console in Observe mode (see
        set_operation_mode).
        """
        if self.__check_mode(mode) == '0' and self.get_operation_mode() == self.OBSERVE:
            raise ValueError('Adaptive Threat Protection is in Observe mode.')
        return self.set_option('CTPObserveModeEnabled', mode)

    credential_theft_protection_observe = property(get_credential_theft_protection_observe,
                                                   set_credential_theft_protection_observe)

    # ------------------------------ Rule Assignment ------------------------------
    def get_rule_group(self):
        """
        Get the rule group for this policy: 'Low' (Productivity), 'Medium'
        (Balanced) or 'High' (Security).
        """
        return self.get_option('securityPosture')

    def set_rule_group(self, posture):
        """
        Set the rule group for this policy: 'Low' (Productivity), 'Medium'
        (Balanced) or 'High' (Security).
        """
        if posture not in self.RULE_GROUPS:
            raise ValueError('Rule group must be within {}.'.format(list(self.RULE_GROUPS)))
        return self.set_option('securityPosture', posture)

    rule_group = property(get_rule_group, set_rule_group)

    # ------------------------------ Action Enforcement ------------------------------
    def get_action(self, action):
        """
        Get a reputation action ('contain', 'block', 'clean' or 'notify'): a
        tuple (enabled '1'/'0', threshold reputation level, e.g. '30').
        """
        enabled, level, _, _ = self.__ACTIONS[action]
        return self.get_option(enabled), self.get_option(level)

    def set_action(self, action, enabled, level=None):
        """
        Set a reputation action ('contain', 'block', 'clean' or 'notify'):
        enabled ('1' or '0') and threshold reputation level (see the
        *_LEVELS lists, None = keep it). As in the console, the thresholds
        of the enabled actions must keep this order: Clean <= Block <=
        Contain <= Notify; the policy is left unchanged otherwise.
        """
        enabled_setting, level_setting, levels, _ = self.__ACTIONS[action]
        enabled = self.__check_mode(enabled)
        if level is not None and str(level) not in levels:
            raise ValueError('The {} threshold must be within {}.'.format(action, levels))
        before = self.get_action(action)
        self.set_option(enabled_setting, enabled)
        if level is not None:
            self.set_option(level_setting, level)
        errors = self.check_thresholds()
        if errors:
            self.set_option(enabled_setting, before[0])
            self.set_option(level_setting, before[1])
            raise ValueError(' '.join(errors))
        return True

    def check_thresholds(self):
        """
        Returns the errors the console would display for the reputation
        thresholds of the enabled actions (empty list if none).
        """
        values = {}
        for action in self.__ACTIONS:
            enabled, level = self.get_action(action)
            if enabled == '1' and level is not None:
                values[action] = int(level)
        errors = []
        for weaker, stronger in [('clean', 'contain'), ('clean', 'block'), ('clean', 'notify'),
                                 ('block', 'contain'), ('block', 'notify'),
                                 ('contain', 'notify')]:
            if weaker in values and stronger in values and values[weaker] > values[stronger]:
                errors.append('The {} threshold must not be above the {} threshold.'.format(
                    weaker, stronger))
        return errors

    def get_enhanced_remediation(self):
        """
        Get state of Enable enhanced remediation ('1' or '0').
        """
        return self.get_option('enhancedRemediationEnabled')

    def set_enhanced_remediation(self, mode):
        """
        Set state of Enable enhanced remediation ('1' or '0').
        """
        return self.__checkbox('enhancedRemediationEnabled', mode)

    enhanced_remediation = property(get_enhanced_remediation, set_enhanced_remediation)

    def get_remediation_monitoring(self):
        """
        Get state of Monitor and remediate deleted and changed files ('1' or '0').
        """
        return self.get_option('enhancedRemFullMonitoringEnabled')

    def set_remediation_monitoring(self, mode):
        """
        Set state of Monitor and remediate deleted and changed files ('1' or '0').
        """
        return self.__checkbox('enhancedRemFullMonitoringEnabled', mode)

    remediation_monitoring = property(get_remediation_monitoring, set_remediation_monitoring)

    # ------------------------------ Threat Detection User Messaging ------------------------------
    def get_notifications(self):
        """
        Get the threat notifications: a dict with 'enabled' (Display threat
        notifications to user, '1'/'0'), 'level' (Notify the user when
        reputation threshold reaches), 'default_action' ('0' Block, '1'
        Allow), 'timeout' (minutes), 'message' ('' = console default
        message) and 'disable_offline' (Disable threat notifications if the
        Threat Intelligence Exchange server is not reachable, '1'/'0').
        """
        custom = self.get_option('customPromptTextEnabled') == '1'
        timeout = self.get_option('promptTimeout')
        return {'enabled': self.get_option('promptEnabled'),
                'level': self.get_option('promptLevel'),
                'default_action': self.get_option('promptDefault'),
                'timeout': int(timeout) if timeout else None,
                'message': (self.get_option('customPromptText') or '') if custom else '',
                'disable_offline': self.get_option('offlinePromptingDisabled')}

    def set_notifications(self, enabled, level=None, default_action=None, timeout=None,
                          message=None, disable_offline=None):
        """
        Set the threat notifications (see get_notifications; None = keep the
        current value). The timeout is 1-5 minutes; the message is limited to
        160 characters (a line break counts for one, stored as \n); an empty
        message or the console default message (DEFAULT_MESSAGE) is stored
        as no custom message, as the console does.
        """
        if default_action is not None and str(default_action) not in self.DEFAULT_ACTIONS:
            raise ValueError('Default action must be "0" (Block) or "1" (Allow).')
        if timeout is not None:
            timeout = check_int('Specify length (minutes) of timeout', timeout, 1, 5)
        if message is not None:
            message = check_length('Message', str(message).replace('\r\n', '\n'), 160)
            if message == self.DEFAULT_MESSAGE:
                message = ''
        self.set_action('notify', enabled, level)
        if default_action is not None:
            self.set_option('promptDefault', default_action)
        if timeout is not None:
            self.set_option('promptTimeout', timeout)
        if message is not None:
            self.set_option('customPromptText', message)
            self.set_option('customPromptTextEnabled', '1' if message else '0')
        if disable_offline is not None:
            self.__checkbox('offlinePromptingDisabled', disable_offline)
        return True

    # ------------------------------ Reputation Source ------------------------------
    def get_reputation_source(self):
        """
        Get the Reputation Source: '1' Use Trellix GTI if the TIE server is
        not reachable, '0' Use only the TIE server, '2' Use only Trellix GTI.
        """
        return self.get_option('reputationSelector')

    def set_reputation_source(self, source):
        """
        Set the Reputation Source: '1' Use Trellix GTI if the TIE server is
        not reachable, '0' Use only the TIE server, '2' Use only Trellix GTI.
        """
        if str(source) not in self.REPUTATION_SOURCES:
            raise ValueError('Reputation source must be within {}.'.format(
                list(self.REPUTATION_SOURCES)))
        return self.set_option('reputationSelector', source)

    reputation_source = property(get_reputation_source, set_reputation_source)

    # ------------------------------ Sandboxing ------------------------------
    def get_sandboxing(self):
        """
        Get the Sandboxing options: a dict with 'enabled' (Send files not yet
        verified for analysis, '1'/'0'), 'level' (Submit files when
        reputation threshold reaches: '85', '50' or '15') and 'size_limit'
        (Limit size (MB) to).
        """
        size = self.get_option('atdFileSizeLimit')
        return {'enabled': self.get_option('atdEnabled'), 'level': self.get_option('atdLevel'),
                'size_limit': int(size) if size else None}

    def set_sandboxing(self, enabled, level=None, size_limit=None):
        """
        Set the Sandboxing options (see get_sandboxing; None = keep the
        current value). The size limit is 1-128 MB.
        """
        enabled = self.__check_mode(enabled)
        if level is not None and str(level) not in self.SANDBOX_LEVELS:
            raise ValueError('The threshold must be within {}.'.format(self.SANDBOX_LEVELS))
        if size_limit is not None:
            size_limit = check_int('Limit size (MB) to', size_limit, 1, 128)
        self.set_option('atdEnabled', enabled)
        if level is not None:
            self.set_option('atdLevel', level)
        if size_limit is not None:
            self.set_option('atdFileSizeLimit', size_limit)
        return True

    # ------------------------------ Story Graph ------------------------------
    def get_story_graph(self):
        """
        Get state of Enable Story Graph Tracing ('1' or '0').
        """
        return self.get_option('StoryGraphEnabled')

    def set_story_graph(self, mode):
        """
        Set state of Enable Story Graph Tracing ('1' or '0').
        """
        return self.__checkbox('StoryGraphEnabled', mode)

    story_graph = property(get_story_graph, set_story_graph)

    # ------------------------------ Markdown export ------------------------------
    def __md_level(self, level):
        return self.REPUTATIONS.get(level, level)

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        check = self.md_check
        row = lambda setting: [self.__CHECKBOXES[setting], check(self.get_option(setting))]
        sections = []
        rows = [['Enable Adaptive Threat Protection', check(self.get_atp())]]
        if self.get_atp() == '1':
            rows.append(['Enable Observe mode (Events are generated but actions are not '
                         'enforced) (Windows only)', check(self.get_observe_mode())])
        rows += [row(setting) for setting in ['telemetry', 'networkScanEnabled',
                                              'accessProtection', 'allowDisableViaMcTray']]
        sections.append(('Adaptive Threat Protection', self.md_settings(rows)))
        rows = [row('realProtectStaticEnabled')]
        if self.get_client_scanning() == '1':
            level = self.get_sensitivity_level()
            rows += [row('realProtectStaticOfflineModeEnabled'),
                     ['Sensitivity level', self.SENSITIVITY_LEVELS.get(level, level)]]
        rows.append(row('realProtectEnabled'))
        rows.append(row('ATP_AMSI_ENABLED'))
        if self.get_script_scanning() == '1':
            rows.append(['Enhanced script scanning: ' + self.__CHECKBOXES['ATPAMSIObserveMode'],
                         check(self.get_script_scanning_observe())])
        rows.append(row('CTPEnabled'))
        if self.get_credential_theft_protection() == '1':
            rows.append(['Credential Theft Protection: ' +
                         self.__CHECKBOXES['CTPObserveModeEnabled'],
                         check(self.get_credential_theft_protection_observe())])
        sections.append(('ML Protect Scanning (Windows only)', self.md_settings(rows)))
        posture = self.get_rule_group()
        text = self.md_settings([['Select the rule group for this policy',
                                  self.RULE_GROUPS.get(posture, posture)]])
        if posture in self.RULE_GROUP_TEXTS:
            text += '\n' + self.RULE_GROUP_TEXTS[posture] + '\n'
        sections.append(('Rule Assignment', text))
        rows = []
        for action in ['contain', 'block', 'clean']:
            enabled, level = self.get_action(action)
            label = self.__ACTIONS[action][3]
            rows.append([label, self.__md_level(level) if enabled == '1' else check(enabled)])
            if action == 'clean' and enabled == '1':
                rows.append(row('enhancedRemediationEnabled'))
                if self.get_enhanced_remediation() == '1':
                    rows.append(row('enhancedRemFullMonitoringEnabled'))
        sections.append(('Action Enforcement', 'Select the reputation threshold for the '
                         'following actions.\n\n' + self.md_settings(rows)))
        notifications = self.get_notifications()
        rows = [['Display threat notifications to user', check(notifications['enabled'])]]
        if notifications['enabled'] == '1':
            action = notifications['default_action']
            rows += [[self.__ACTIONS['notify'][3], self.__md_level(notifications['level'])],
                     ['Default Action', self.DEFAULT_ACTIONS.get(action, action)],
                     ['Specify length (minutes) of timeout', notifications['timeout']],
                     ['Message', notifications['message'] or self.DEFAULT_MESSAGE],
                     row('offlinePromptingDisabled')]
        sections.append(('Threat Detection User Messaging', self.md_settings(rows)))
        source = self.get_reputation_source()
        sections.append(('Reputation Source', self.md_settings([
            ['Reputation source', self.REPUTATION_SOURCES.get(source, source)]])))
        sandboxing = self.get_sandboxing()
        rows = [['Send files not yet verified for analysis', check(sandboxing['enabled'])]]
        if sandboxing['enabled'] == '1':
            rows += [['Submit files when reputation threshold reaches',
                      self.__md_level(sandboxing['level'])],
                     ['Limit size (MB) to', sandboxing['size_limit']]]
        sections.append(('Sandboxing', self.md_settings(rows)))
        sections.append(('Story Graph', self.md_settings([row('StoryGraphEnabled')])))
        return sections
