# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes for the Solidcore "General" policies (SCOR_GEN):
SCGENPolicyConfiguration and SCGENPolicyExceptionRules.
"""

from .scpolicies import SCPolicy
from .rules import SCExclusionRules
from ..validators import check_int

class SCGENPolicyConfiguration(SCPolicy):
    """
    The SCGENPolicyConfiguration class can be used to edit the Solidcore policy:
    General > Configuration (Client).

    Note: ePO stores this policy under the internal type "Lockdown Rules". All
    values are strings: '1'/'0' for the State constants (Enable checkboxes) and
    for the 0/1 fields of the Certificate and Custom configuration tabs.
    """

    TYPE_IDS = ('Lockdown Rules',)

    # Number fields of the console (Numberbox min-max of the Solidcore 8.4
    # page, checked on the lab; the server also checks the CLI, throttling
    # and content change tracking ones): config name -> (label, min, max).
    CONFIG_LIMITS = {
        'AgentEventsThresholdOnWakeup': ('Events threshold', 1, 999999),
        'SupplierCacheSizeOnWakeup': ('Events cache size', 1, 999999),
        'InvDiffAgentEventsThreshold': ('Inventory threshold', 1, 999999),
        'ObAgentEventsThresholdOnWakeup': ('Policy discovery threshold', 1, 999999),
        'ObSupplierCacheSizeOnWakeup': ('Policy discovery cache size', 1, 999999),
        'FileDiffMaxSize': ('Content change tracking maximum file size (KB)', 1, 10000),
        'FileDiffMaxFiles': ('Content change tracking maximum file limit per rule', 1, 10000),
        'logFileSize': ('Solidcore log file size (KB)', 2000, 100000),
        'logFileNum': ('Number of solidcore log files', 5, 50),
        'invMergeTimeout': ('Inventory merge timeout', 1800, 10000),
        'invMergeBySizePeriod': ('Inventory merge by size period', 150, 300),
        'mpCompat': ('mpCompat', 0, 2),
        'inventoryCaseSensitivityEnabled': ('inventoryCaseSensitivityEnabled', 0, 2),
    }
    # The other number fields of the Certificate and Custom configuration
    # tabs take 0 or 1.
    for _name in ['checkCertTrustWithVTP', 'allowFailedCertTrustWithVTP',
                  'catalogCertExtractionDisabled', 'embeddedCertExtractionDisabled',
                  'disableDeviceGuardCompat', 'isInvBackupEnabled', 'isInvBootBackupEnabled',
                  'soIsTidOptimizationEnabled', 'cksumCalcMode', 'cksumParallelCalcMode',
                  'enableBinAllowedByCertOrChecksumToBeUpdaters', 'volumeMountRefCountDisabled',
                  'unloadUnmountedVolumeDisabled', 'disableReputationCache',
                  'skipValidateFileLength', 'disableCertCheck', 'isTrustedLocalGroupEnabled']:
        CONFIG_LIMITS[_name] = (_name, 0, 1)
    del _name
    # CLI lockdown: setting of the local-cli-lock rule -> (label, min, max).
    CLI_LIMITS = {'attempts': ('Disable CLI after failed attempts', 1, 100),
                  'attempts_within_minutes': ('Failed attempts within minutes', 1, 1440),
                  'lockdowntime_minutes': ('Disable CLI for minutes', 1, 1440)}
    # Characters the console removes as they are typed (scorFDvalidateExtensions,
    # scorValidatePaths).
    CONFIG_FORBIDDEN = {'FileDiffAttrOnlyTypes': '.:?<>|*"\\/',
                        'pathsWritableOnlyByUpdater': '?<>|,*"/'}

    def set_config(self, name, value):
        """
        Sets the value of a 'config' rule (see SCPolicy.set_config), refusing
        what the console refuses (CONFIG_LIMITS, CONFIG_FORBIDDEN).
        """
        if name in self.CONFIG_LIMITS:
            label, minimum, maximum = self.CONFIG_LIMITS[name]
            value = str(check_int(label, value, minimum, maximum))
        elif name in self.CONFIG_FORBIDDEN:
            value = str(value)
            if value != value.strip() or any(char in value for char in self.CONFIG_FORBIDDEN[name]):
                raise ValueError('{} cannot contain {} (nor surrounding blanks): {!r}'.format(
                    name, ' '.join(self.CONFIG_FORBIDDEN[name]), value))
        return super(SCGENPolicyConfiguration, self).set_config(name, value)

    def _set_rule_value(self, rule_type, key, value):
        if rule_type == 'local-cli-lock' and key in self.CLI_LIMITS:
            label, minimum, maximum = self.CLI_LIMITS[key]
            value = str(check_int(label, value, minimum, maximum))
        return super(SCGENPolicyConfiguration, self)._set_rule_value(rule_type, key, value)

    # ------------------------------ CLI TAB ------------------------------
    # Local CLI Access Password:
    #   The password is hashed by the ePO server when the policy is saved (the
    #   algorithm isn't known), so it can only be read as its raw hashes, or
    #   copied from another policy with set_cli_password_hash().
    def get_cli_password_hash(self):
        """
        Get the Local CLI Access Password as a dict of its raw settings:
        {'password' (SHA-1), 'password_sha512', 'salt'}, or None if not set.
        """
        rule = self.get_rule('local-access-passwd')
        if rule is None:
            return None
        return {key: rule.get(key) for key in ('password', 'password_sha512', 'salt')}

    def set_cli_password_hash(self, password_hash):
        """
        Set the Local CLI Access Password from the raw settings returned by
        get_cli_password_hash() (e.g. from another policy).
        """
        if self.update_rules('local-access-passwd', None, password_hash) == 0:
            rule = {'type': 'local-access-passwd'}
            rule.update(password_hash)
            return self.add_rule(rule)
        return True

    # ------------------------------ CLI TAB ------------------------------
    #   Local CLI Access Configuration:
    #     Enable (State.ENABLED / State.DISABLED)
    def get_cli_access(self):
        """
        Get state of Local CLI Access Configuration - Enable
        """
        return self._get_rule_value('local-cli-lock', 'status')

    def set_cli_access(self, value):
        """
        Set state of Local CLI Access Configuration - Enable
        """
        return self._set_rule_value('local-cli-lock', 'status', value)

    cli_access = property(get_cli_access, set_cli_access)

    #     Disable CLI after <n> failed attempts ...
    def get_cli_failed_attempts(self):
        """
        Get the number of failed attempts before the CLI is disabled
        """
        return self._get_rule_value('local-cli-lock', 'attempts')

    def set_cli_failed_attempts(self, value):
        """
        Set the number of failed attempts before the CLI is disabled
        """
        return self._set_rule_value('local-cli-lock', 'attempts', value)

    cli_failed_attempts = property(get_cli_failed_attempts, set_cli_failed_attempts)

    #     ... within <n> minutes
    def get_cli_attempts_within_minutes(self):
        """
        Get the period (minutes) in which failed attempts are counted
        """
        return self._get_rule_value('local-cli-lock', 'attempts_within_minutes')

    def set_cli_attempts_within_minutes(self, value):
        """
        Set the period (minutes) in which failed attempts are counted
        """
        return self._set_rule_value('local-cli-lock', 'attempts_within_minutes', value)

    cli_attempts_within_minutes = property(get_cli_attempts_within_minutes, set_cli_attempts_within_minutes)

    #     Disable CLI for <n> minutes
    def get_cli_lockdown_minutes(self):
        """
        Get the period (minutes) the CLI stays disabled after failed attempts
        """
        return self._get_rule_value('local-cli-lock', 'lockdowntime_minutes')

    def set_cli_lockdown_minutes(self, value):
        """
        Set the period (minutes) the CLI stays disabled after failed attempts
        """
        return self._set_rule_value('local-cli-lock', 'lockdowntime_minutes', value)

    cli_lockdown_minutes = property(get_cli_lockdown_minutes, set_cli_lockdown_minutes)

    # ------------------------------ THROTTLING TAB ------------------------------
    #   Throttling Settings:
    #     Enable Throttling (State.ENABLED / State.DISABLED)
    def get_throttling(self):
        """
        Get state of Enable Throttling
        """
        return self.get_feature('throttle')

    def set_throttling(self, value):
        """
        Set state of Enable Throttling
        """
        return self.set_feature('throttle', value)

    throttling = property(get_throttling, set_throttling)

    #     Events
    def get_throttling_events(self):
        """
        Get state of Throttling - Events
        """
        return self.get_feature('throttle-evt')

    def set_throttling_events(self, value):
        """
        Set state of Throttling - Events
        """
        return self.set_feature('throttle-evt', value)

    throttling_events = property(get_throttling_events, set_throttling_events)

    #       Threshold
    def get_events_threshold(self):
        """
        Get Throttling - Events - Threshold
        """
        return self.get_config('AgentEventsThresholdOnWakeup')

    def set_events_threshold(self, value):
        """
        Set Throttling - Events - Threshold
        """
        return self.set_config('AgentEventsThresholdOnWakeup', value)

    events_threshold = property(get_events_threshold, set_events_threshold)

    #       Cache Size
    def get_events_cache_size(self):
        """
        Get Throttling - Events - Cache Size
        """
        return self.get_config('SupplierCacheSizeOnWakeup')

    def set_events_cache_size(self, value):
        """
        Set Throttling - Events - Cache Size
        """
        return self.set_config('SupplierCacheSizeOnWakeup', value)

    events_cache_size = property(get_events_cache_size, set_events_cache_size)

    #     Inventory Updates
    def get_throttling_inventory(self):
        """
        Get state of Throttling - Inventory Updates
        """
        return self.get_feature('throttle-inv')

    def set_throttling_inventory(self, value):
        """
        Set state of Throttling - Inventory Updates
        """
        return self.set_feature('throttle-inv', value)

    throttling_inventory = property(get_throttling_inventory, set_throttling_inventory)

    #       Threshold
    def get_inventory_threshold(self):
        """
        Get Throttling - Inventory Updates - Threshold
        """
        return self.get_config('InvDiffAgentEventsThreshold')

    def set_inventory_threshold(self, value):
        """
        Set Throttling - Inventory Updates - Threshold
        """
        return self.set_config('InvDiffAgentEventsThreshold', value)

    inventory_threshold = property(get_inventory_threshold, set_inventory_threshold)

    #     Policy Discovery (Observations)
    def get_throttling_policy_discovery(self):
        """
        Get state of Throttling - Policy Discovery (Observations)
        """
        return self.get_feature('throttle-ob')

    def set_throttling_policy_discovery(self, value):
        """
        Set state of Throttling - Policy Discovery (Observations)
        """
        return self.set_feature('throttle-ob', value)

    throttling_policy_discovery = property(get_throttling_policy_discovery, set_throttling_policy_discovery)

    #       Threshold
    def get_policy_discovery_threshold(self):
        """
        Get Throttling - Policy Discovery - Threshold
        """
        return self.get_config('ObAgentEventsThresholdOnWakeup')

    def set_policy_discovery_threshold(self, value):
        """
        Set Throttling - Policy Discovery - Threshold
        """
        return self.set_config('ObAgentEventsThresholdOnWakeup', value)

    policy_discovery_threshold = property(get_policy_discovery_threshold, set_policy_discovery_threshold)

    #       Cache Size
    def get_policy_discovery_cache_size(self):
        """
        Get Throttling - Policy Discovery - Cache Size
        """
        return self.get_config('ObSupplierCacheSizeOnWakeup')

    def set_policy_discovery_cache_size(self, value):
        """
        Set Throttling - Policy Discovery - Cache Size
        """
        return self.set_config('ObSupplierCacheSizeOnWakeup', value)

    policy_discovery_cache_size = property(get_policy_discovery_cache_size, set_policy_discovery_cache_size)

    # ------------------------------ MISCELLANEOUS TAB ------------------------------
    #   Content Change Tracking: Maximum file size (KB)
    def get_file_diff_max_size(self):
        """
        Get Content Change Tracking: Maximum file size (KB)
        """
        return self.get_config('FileDiffMaxSize')

    def set_file_diff_max_size(self, value):
        """
        Set Content Change Tracking: Maximum file size (KB)
        """
        return self.set_config('FileDiffMaxSize', value)

    file_diff_max_size = property(get_file_diff_max_size, set_file_diff_max_size)

    #   Content Change Tracking: File-extensions for attributes-only tracking
    #     (comma-separated file extensions only)
    def get_file_diff_attr_only_types(self):
        """
        Get Content Change Tracking: File-extensions for attributes-only tracking
        """
        return self.get_config('FileDiffAttrOnlyTypes')

    def set_file_diff_attr_only_types(self, value):
        """
        Set Content Change Tracking: File-extensions for attributes-only tracking
        """
        return self.set_config('FileDiffAttrOnlyTypes', value)

    file_diff_attr_only_types = property(get_file_diff_attr_only_types, set_file_diff_attr_only_types)

    #   Content Change Tracking: Maximum file limit per rule
    def get_file_diff_max_files(self):
        """
        Get Content Change Tracking: Maximum file limit per rule
        """
        return self.get_config('FileDiffMaxFiles')

    def set_file_diff_max_files(self, value):
        """
        Set Content Change Tracking: Maximum file limit per rule
        """
        return self.set_config('FileDiffMaxFiles', value)

    file_diff_max_files = property(get_file_diff_max_files, set_file_diff_max_files)

    #   Paths Writable only by Updaters
    #     (semi-colon separated directory paths only, 'NA' when empty)
    def get_paths_writable_only_by_updaters(self):
        """
        Get Paths Writable only by Updaters
        """
        return self.get_config('pathsWritableOnlyByUpdater')

    def set_paths_writable_only_by_updaters(self, value):
        """
        Set Paths Writable only by Updaters
        """
        return self.set_config('pathsWritableOnlyByUpdater', value)

    paths_writable_only_by_updaters = property(get_paths_writable_only_by_updaters, set_paths_writable_only_by_updaters)

    # ------------------------------ LOGGING CONFIGURATION TAB ------------------------------
    #   Solidcore log file size (KB)
    def get_log_file_size(self):
        """
        Get Solidcore log file size (KB)
        """
        return self.get_config('logFileSize')

    def set_log_file_size(self, value):
        """
        Set Solidcore log file size (KB)
        """
        return self.set_config('logFileSize', value)

    log_file_size = property(get_log_file_size, set_log_file_size)

    #   Number of solidcore log files
    def get_log_file_num(self):
        """
        Get Number of solidcore log files
        """
        return self.get_config('logFileNum')

    def set_log_file_num(self, value):
        """
        Set Number of solidcore log files
        """
        return self.set_config('logFileNum', value)

    log_file_num = property(get_log_file_num, set_log_file_num)

    # ------------------------------ INVENTORY CONFIGURATION TAB ------------------------------
    #   Inventory merge timeout period (seconds)
    def get_inventory_merge_timeout(self):
        """
        Get Inventory merge timeout period (seconds)
        """
        return self.get_config('invMergeTimeout')

    def set_inventory_merge_timeout(self, value):
        """
        Set Inventory merge timeout period (seconds)
        """
        return self.set_config('invMergeTimeout', value)

    inventory_merge_timeout = property(get_inventory_merge_timeout, set_inventory_merge_timeout)

    #   Inventory merge by size period (seconds)
    def get_inventory_merge_by_size_period(self):
        """
        Get Inventory merge by size period (seconds)
        """
        return self.get_config('invMergeBySizePeriod')

    def set_inventory_merge_by_size_period(self, value):
        """
        Set Inventory merge by size period (seconds)
        """
        return self.set_config('invMergeBySizePeriod', value)

    inventory_merge_by_size_period = property(get_inventory_merge_by_size_period, set_inventory_merge_by_size_period)

    # ------------------------------ CERTIFICATE CONFIGURATION TAB ------------------------------
    #   Enable VTP trust check ('1' or '0')
    def get_vtp_trust_check(self):
        """
        Get Enable VTP trust check
        """
        return self.get_config('checkCertTrustWithVTP')

    def set_vtp_trust_check(self, value):
        """
        Set Enable VTP trust check
        """
        return self.set_config('checkCertTrustWithVTP', value)

    vtp_trust_check = property(get_vtp_trust_check, set_vtp_trust_check)

    #   Allow failed CertTrust with VTP ('1' or '0')
    def get_allow_failed_cert_trust_with_vtp(self):
        """
        Get Allow failed CertTrust with VTP
        """
        return self.get_config('allowFailedCertTrustWithVTP')

    def set_allow_failed_cert_trust_with_vtp(self, value):
        """
        Set Allow failed CertTrust with VTP
        """
        return self.set_config('allowFailedCertTrustWithVTP', value)

    allow_failed_cert_trust_with_vtp = property(get_allow_failed_cert_trust_with_vtp, set_allow_failed_cert_trust_with_vtp)

    #   Catalog certificate extraction disabled ('1' or '0')
    def get_catalog_cert_extraction_disabled(self):
        """
        Get Catalog certificate extraction disabled
        """
        return self.get_config('catalogCertExtractionDisabled')

    def set_catalog_cert_extraction_disabled(self, value):
        """
        Set Catalog certificate extraction disabled
        """
        return self.set_config('catalogCertExtractionDisabled', value)

    catalog_cert_extraction_disabled = property(get_catalog_cert_extraction_disabled, set_catalog_cert_extraction_disabled)

    #   Embedded certificate extraction disabled ('1' or '0')
    def get_embedded_cert_extraction_disabled(self):
        """
        Get Embedded certificate extraction disabled
        """
        return self.get_config('embeddedCertExtractionDisabled')

    def set_embedded_cert_extraction_disabled(self, value):
        """
        Set Embedded certificate extraction disabled
        """
        return self.set_config('embeddedCertExtractionDisabled', value)

    embedded_cert_extraction_disabled = property(get_embedded_cert_extraction_disabled, set_embedded_cert_extraction_disabled)

    # ------------------------------ CUSTOM CONFIGURATION TAB ------------------------------
    #   MPCompat - Provides information on patching activities performed on
    #   ntdll.dll by other processes.
    def get_mp_compat(self):
        """
        Get MPCompat
        """
        return self.get_config('mpCompat')

    def set_mp_compat(self, value):
        """
        Set MPCompat
        """
        return self.set_config('mpCompat', value)

    mp_compat = property(get_mp_compat, set_mp_compat)

    #   DisableDeviceGuardCompat - Changes the function to be hooked for injection.
    def get_disable_device_guard_compat(self):
        """
        Get DisableDeviceGuardCompat
        """
        return self.get_config('disableDeviceGuardCompat')

    def set_disable_device_guard_compat(self, value):
        """
        Set DisableDeviceGuardCompat
        """
        return self.set_config('disableDeviceGuardCompat', value)

    disable_device_guard_compat = property(get_disable_device_guard_compat, set_disable_device_guard_compat)

    #   IsInvBackupEnabled - Allows/blocks inventory backup on managed clients.
    def get_inventory_backup(self):
        """
        Get IsInvBackupEnabled
        """
        return self.get_config('isInvBackupEnabled')

    def set_inventory_backup(self, value):
        """
        Set IsInvBackupEnabled
        """
        return self.set_config('isInvBackupEnabled', value)

    inventory_backup = property(get_inventory_backup, set_inventory_backup)

    #   IsInvBootBackupEnabled - Controls inventory backup before client restart.
    def get_inventory_boot_backup(self):
        """
        Get IsInvBootBackupEnabled
        """
        return self.get_config('isInvBootBackupEnabled')

    def set_inventory_boot_backup(self, value):
        """
        Set IsInvBootBackupEnabled
        """
        return self.set_config('isInvBootBackupEnabled', value)

    inventory_boot_backup = property(get_inventory_boot_backup, set_inventory_boot_backup)

    #   SoIsTidOptimizationEnabled - Optimizes the Solidification thread
    #   (excluding disable mode).
    def get_tid_optimization(self):
        """
        Get SoIsTidOptimizationEnabled
        """
        return self.get_config('soIsTidOptimizationEnabled')

    def set_tid_optimization(self, value):
        """
        Set SoIsTidOptimizationEnabled
        """
        return self.set_config('soIsTidOptimizationEnabled', value)

    tid_optimization = property(get_tid_optimization, set_tid_optimization)

    #   CksumCalcMode - Manages TACC checksum calculation for new processes.
    def get_checksum_calc_mode(self):
        """
        Get CksumCalcMode
        """
        return self.get_config('cksumCalcMode')

    def set_checksum_calc_mode(self, value):
        """
        Set CksumCalcMode
        """
        return self.set_config('cksumCalcMode', value)

    checksum_calc_mode = property(get_checksum_calc_mode, set_checksum_calc_mode)

    #   CksumParallelCalcMode - Enables parallel thread checksum calculation.
    def get_checksum_parallel_calc_mode(self):
        """
        Get CksumParallelCalcMode
        """
        return self.get_config('cksumParallelCalcMode')

    def set_checksum_parallel_calc_mode(self, value):
        """
        Set CksumParallelCalcMode
        """
        return self.set_config('cksumParallelCalcMode', value)

    checksum_parallel_calc_mode = property(get_checksum_parallel_calc_mode, set_checksum_parallel_calc_mode)

    #   EnableBinAllowedByCertOrChecksumToBeUpdaters - Allows file execution based
    #   on a combination of certificate and updater name rule.
    def get_bin_allowed_by_cert_or_checksum_to_be_updaters(self):
        """
        Get EnableBinAllowedByCertOrChecksumToBeUpdaters
        """
        return self.get_config('enableBinAllowedByCertOrChecksumToBeUpdaters')

    def set_bin_allowed_by_cert_or_checksum_to_be_updaters(self, value):
        """
        Set EnableBinAllowedByCertOrChecksumToBeUpdaters
        """
        return self.set_config('enableBinAllowedByCertOrChecksumToBeUpdaters', value)

    bin_allowed_by_cert_or_checksum_to_be_updaters = property(get_bin_allowed_by_cert_or_checksum_to_be_updaters, set_bin_allowed_by_cert_or_checksum_to_be_updaters)

    #   VolumeMountRefCountDisabled - Disables volume mount/unmount reference counting.
    def get_volume_mount_ref_count_disabled(self):
        """
        Get VolumeMountRefCountDisabled
        """
        return self.get_config('volumeMountRefCountDisabled')

    def set_volume_mount_ref_count_disabled(self, value):
        """
        Set VolumeMountRefCountDisabled
        """
        return self.set_config('volumeMountRefCountDisabled', value)

    volume_mount_ref_count_disabled = property(get_volume_mount_ref_count_disabled, set_volume_mount_ref_count_disabled)

    #   UnloadUnmountedVolumeDisabled - Disables code unloads in inventory memory
    #   for absent volumes in the system.
    def get_unload_unmounted_volume_disabled(self):
        """
        Get UnloadUnmountedVolumeDisabled
        """
        return self.get_config('unloadUnmountedVolumeDisabled')

    def set_unload_unmounted_volume_disabled(self, value):
        """
        Set UnloadUnmountedVolumeDisabled
        """
        return self.set_config('unloadUnmountedVolumeDisabled', value)

    unload_unmounted_volume_disabled = property(get_unload_unmounted_volume_disabled, set_unload_unmounted_volume_disabled)

    #   InventoryCaseSensitivityEnabled - Enables/disables case-sensitivity for
    #   inventory items.
    def get_inventory_case_sensitivity(self):
        """
        Get InventoryCaseSensitivityEnabled
        """
        return self.get_config('inventoryCaseSensitivityEnabled')

    def set_inventory_case_sensitivity(self, value):
        """
        Set InventoryCaseSensitivityEnabled
        """
        return self.set_config('inventoryCaseSensitivityEnabled', value)

    inventory_case_sensitivity = property(get_inventory_case_sensitivity, set_inventory_case_sensitivity)

    #   DisableReputationCache - Disables the Reputation cache.
    def get_disable_reputation_cache(self):
        """
        Get DisableReputationCache
        """
        return self.get_config('disableReputationCache')

    def set_disable_reputation_cache(self, value):
        """
        Set DisableReputationCache
        """
        return self.set_config('disableReputationCache', value)

    disable_reputation_cache = property(get_disable_reputation_cache, set_disable_reputation_cache)

    #   SkipValidateFileLength - Allows blocked file creation due to file path
    #   length validation.
    def get_skip_validate_file_length(self):
        """
        Get SkipValidateFileLength
        """
        return self.get_config('skipValidateFileLength')

    def set_skip_validate_file_length(self, value):
        """
        Set SkipValidateFileLength
        """
        return self.set_config('skipValidateFileLength', value)

    skip_validate_file_length = property(get_skip_validate_file_length, set_skip_validate_file_length)

    #   DisableCertCheck - Enhances boot time performance.
    def get_disable_cert_check(self):
        """
        Get DisableCertCheck
        """
        return self.get_config('disableCertCheck')

    def set_disable_cert_check(self, value):
        """
        Set DisableCertCheck
        """
        return self.set_config('disableCertCheck', value)

    disable_cert_check = property(get_disable_cert_check, set_disable_cert_check)

    #   IsTrustedLocalGroupEnabled - Enables/disables Trusted Local Group feature.
    def get_trusted_local_group(self):
        """
        Get IsTrustedLocalGroupEnabled
        """
        return self.get_config('isTrustedLocalGroupEnabled')

    def set_trusted_local_group(self, value):
        """
        Set IsTrustedLocalGroupEnabled
        """
        return self.set_config('isTrustedLocalGroupEnabled', value)

    trusted_local_group = property(get_trusted_local_group, set_trusted_local_group)

    # Hidden settings (confirmed not shown in the ePO console):
    def __get_inv_diff_config(self):
        """
        Get Hidden setting - InvDiffConfig
        """
        return self.get_config('InvDiffConfig')

    def __get_inv_diff_config2(self):
        """
        Get Hidden setting - InvDiffConfig2 (hidden "invDiffConfig2" checkbox
        of the Miscellaneous tab)
        """
        return self.get_config('InvDiffConfig2')

    # ------------------------------ Markdown export ------------------------------
    # One section per console tab (Solidcore > General > Configuration
    # (Client), ePO 5.10 console labels). See Policy.to_markdown().
    MD_CATEGORY = 'Configuration (Client)'

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console tab (see Policy.to_markdown).
        """
        check = self.md_check
        # The password is hashed by the ePO server: only whether one is set.
        password = 'Set' if self.get_cli_password_hash() else 'Not set'
        enabled = self.get_cli_access()
        rows = [['Enable', check(enabled)]]
        if enabled == '1':
            rows += [['Disable CLI after ... failed attempts within ... minutes',
                      '{} failed attempts within {} minutes'.format(
                          self.get_cli_failed_attempts(), self.get_cli_attempts_within_minutes())],
                     ['Disable CLI for (minutes)', self.get_cli_lockdown_minutes()]]
        cli = self.md_group('Local CLI Access Password', [['Password', password]]) + '\n' + \
            self.md_group('Local CLI Access Configuration', rows)
        throttling = self.md_group('Throttling Settings', [
            ['Enable Throttling', check(self.get_throttling())],
            ['Events', check(self.get_throttling_events())],
            ['Events - Threshold', self.get_events_threshold()],
            ['Events - Cache Size', self.get_events_cache_size()],
            ['Inventory Updates', check(self.get_throttling_inventory())],
            ['Inventory Updates - Threshold', self.get_inventory_threshold()],
            ['Policy Discovery (Observations)', check(self.get_throttling_policy_discovery())],
            ['Policy Discovery (Observations) - Threshold', self.get_policy_discovery_threshold()],
            ['Policy Discovery (Observations) - Cache Size',
             self.get_policy_discovery_cache_size()]])
        miscellaneous = self.md_settings([
            ['Content Change Tracking: Maximum file size (KB)', self.get_file_diff_max_size()],
            ['Content Change Tracking: File-extensions for attributes-only tracking',
             self.get_file_diff_attr_only_types()],
            ['Content Change Tracking: Maximum file limit per rule', self.get_file_diff_max_files()],
            ['Paths Writable only by Updaters', self.get_paths_writable_only_by_updaters()]])
        logging = self.md_settings([
            ['Solidcore log file size (KB)', self.get_log_file_size()],
            ['Number of solidcore log files', self.get_log_file_num()]])
        inventory = self.md_settings([
            ['Inventory merge timeout period (seconds)', self.get_inventory_merge_timeout()],
            ['Inventory merge by size period (seconds)',
             self.get_inventory_merge_by_size_period()]])
        certificate = self.md_settings([
            ['Enable VTP trust check', self.get_vtp_trust_check()],
            ['Allow failed CertTrust with VTP', self.get_allow_failed_cert_trust_with_vtp()],
            ['Catalog certificate extraction disabled', self.get_catalog_cert_extraction_disabled()],
            ['Embedded certificate extraction disabled',
             self.get_embedded_cert_extraction_disabled()]])
        custom = self.md_settings([
            ['MPCompat', self.get_mp_compat()],
            ['DisableDeviceGuardCompat', self.get_disable_device_guard_compat()],
            ['IsInvBackupEnabled', self.get_inventory_backup()],
            ['IsInvBootBackupEnabled', self.get_inventory_boot_backup()],
            ['SoIsTidOptimizationEnabled', self.get_tid_optimization()],
            ['CksumCalcMode', self.get_checksum_calc_mode()],
            ['CksumParallelCalcMode', self.get_checksum_parallel_calc_mode()],
            ['EnableBinAllowedByCert OrChecksumToBeUpdaters',
             self.get_bin_allowed_by_cert_or_checksum_to_be_updaters()],
            ['VolumeMountRefCountDisabled', self.get_volume_mount_ref_count_disabled()],
            ['UnloadUnmountedVolumeDisabled', self.get_unload_unmounted_volume_disabled()],
            ['InventoryCaseSensitivityEnabled', self.get_inventory_case_sensitivity()],
            ['DisableReputationCache', self.get_disable_reputation_cache()],
            ['SkipValidateFileLength', self.get_skip_validate_file_length()],
            ['DisableCertCheck', self.get_disable_cert_check()],
            ['IsTrustedLocalGroupEnabled', self.get_trusted_local_group()]])
        return [('CLI', cli), ('Throttling', throttling), ('Miscellaneous', miscellaneous),
                ('Logging configuration', logging), ('Inventory configuration', inventory),
                ('Certificate configuration', certificate), ('Custom configuration', custom)]

class SCGENPolicyExceptionRules(SCExclusionRules, SCPolicy):
    """
    The SCGENPolicyExceptionRules class can be used to edit the Solidcore policies:
    General > Exception Rules (Windows) and General > Exception Rules (Unix).

    Note: ePO stores these policies under the internal types "Attr Rules (Windows)"
    and "Attr Rules (Unix)". See SCExclusionRules for the exclusion list methods.
    """

    TYPE_IDS = ('Attr Rules (Windows)', 'Attr Rules (Unix)')

    @property
    def MD_CATEGORY(self):
        return 'Exception Rules ({})'.format('Unix' if self.is_unix() else 'Windows')

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples:
        the exclusion list of the console (see Policy.to_markdown).
        """
        return [('Exception Rules', self.md_exclusions_table(self.md_table))]
