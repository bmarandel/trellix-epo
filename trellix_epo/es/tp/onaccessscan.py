# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESTPPolicyOnAccessScan.
"""

from ...policies import Policy
from ...validators import check_int, check_length, is_ens_process_name
from .exclusions import ExclusionList, check_file_type_list, check_exclusion_rows

class ESTPPolicyOnAccessScan(Policy):
    """
    The ESTPPolicyOnAccessScan class can be used to edit the Endpoint Security
    Threat Prevention policy: On-Access Scan.
    """

    def __init__(self, policy_from_estppolicies=None):
        super(ESTPPolicyOnAccessScan, self).__init__(policy_from_estppolicies)
        if policy_from_estppolicies is not None:
            if self.get_type() != 'EAM_General_Policies':
                raise ValueError('Wrong policy! Policy type must be "EAM_General_Policies".')

    def _info_counts(self):
        """
        The counts of get_info() and of the representation: the processes of the Process Settings.
        """
        return {'processes': len(self.get_process_list())}

    MD_PRODUCT = 'Endpoint Security Threat Prevention'
    MD_CATEGORY = 'On-Access Scan'

    # ------------------------------ On-Access Policy ------------------------------
    # On-Access Scan:
    #   Enable On-Access Scan
    #   Disable and unregister with Windows Security Center
    #   '1' = Enable                     OASState().ENABLED
    #   '0' = Disable                    OASState().DISABLED
    #   '2' = Disable and unregister     OASState().DISABLED_UNREGISTER_WSC
    #         (stored as bOASEnabled = 0 and bUnregisterWithWSC = 1)
    def get_on_access_scan(self):
        """
        Get the On-Access Scan feature state: '1' (Enable), '0' (Disable)
        or '2' (Disable and unregister with Windows Security Center).
        """
        mode = self.get_setting_value('General', 'bOASEnabled')
        if mode == '0' and self.get_setting_value('General', 'bUnregisterWithWSC') == '1':
            mode = '2'
        return mode

    def set_on_access_scan(self, mode):
        """
        Set the On-Access Scan feature state: '1' (Enable), '0' (Disable)
        or '2' (Disable and unregister with Windows Security Center).
        bUnregisterWithWSC is created if missing, as the console does on save.
        """
        if mode not in ['0', '1', '2']:
            raise ValueError('Mode must be within ["0", "1", "2"].')
        self.set_setting_value('General', 'bUnregisterWithWSC', '1' if mode == '2' else '0',
                               force=True)
        return self.set_setting_value('General', 'bOASEnabled', '1' if mode == '1' else '0')

    on_access_scan = property(get_on_access_scan, set_on_access_scan)

    #	Enable On-Access Scan on system startup
    def get_scan_on_startup(self):
        """
        Get the On-Access Scan on system startup state
        """
        return self.get_setting_value('General', 'bStartEnabled')

    def set_scan_on_startup(self, mode):
        """
        Set the On-Access Scan on system startup state
        """
        return self.set_setting_value('General', 'bStartEnabled', mode)

    scan_on_startup = property(get_scan_on_startup, set_scan_on_startup)

	#	Allow users to disable On-Access Scan from the McAfee system tray icon
    def get_allow_user_to_disable_oas(self):
        """
        Get state of Allow users to disable On-Access Scan from the McAfee system tray icon
        """
        return self.get_setting_value('General', 'bAllowDisableViaMcTray')

    def set_allow_user_to_disable_oas(self, mode):
        """
        Set state of Allow users to disable On-Access Scan from the McAfee system tray icon
        """
        return self.set_setting_value('General', 'bAllowDisableViaMcTray', mode)

    allow_user_to_disable_oas = property(get_allow_user_to_disable_oas,
                                         set_allow_user_to_disable_oas)

    #	Specify maximum number of seconds for each file scan
    def get_max_scan_time_enforced(self):
        """
        Get if maximum scan time is enforced
        """
        return self.get_setting_value('General', 'bEnforceMaxScanTime')

    def set_max_scan_time_enforced(self, mode):
        """
        Set enforcement of maximum scan time
        """
        return self.set_setting_value('General', 'bEnforceMaxScanTime', mode)

    max_scan_time_enforced = property(get_max_scan_time_enforced, set_max_scan_time_enforced)

    def get_max_scan_time(self):
        """
        Get the maximum number of seconds for each file scan
        """
        return int(self.get_setting_value('General', 'dwScannerThreadTimeout'))

    def set_max_scan_time(self, int_seconds):
        """
        Set the maximum number of seconds for each file scan
        """
        int_seconds = check_int('Maximum number of seconds for each file scan', int_seconds,
                                10, 9999)
        return self.set_setting_value('General', 'dwScannerThreadTimeout', str(int_seconds))

    max_scan_time = property(get_max_scan_time, set_max_scan_time)

    #	Scan boot sectors
    def get_scan_boot_sectors(self):
        """
        Get state of Scan boot sectors
        """
        return self.get_setting_value('General', 'bScanBootSectors')

    def set_scan_boot_sectors(self, mode):
        """
        Set state of Scan boot sectors
        """
        return self.set_setting_value('General', 'bScanBootSectors', mode)

    scan_boot_sectors = property(get_scan_boot_sectors, set_scan_boot_sectors)

    #	Scan processes on service startup and content update
    def get_scan_process_startup(self):
        """
        Get state of Scan processes on service startup and content update
        """
        return self.get_setting_value('General', 'scanProcessesOnEnable')

    def set_scan_process_startup(self, mode):
        """
        Set state of Scan processes on service startup and content update
        """
        return self.set_setting_value('General', 'scanProcessesOnEnable', mode)

    scan_process_startup = property(get_scan_process_startup, set_scan_process_startup)

    #	Scan trusted installers
    def get_scan_trusted_installers(self):
        """
        Get state of Scan trusted installers
        """
        return self.get_setting_value('General', 'scanTrustedInstallers')

    def set_scan_trusted_installers(self, mode):
        """
        Set state of Scan trusted installers
        """
        return self.set_setting_value('General', 'scanTrustedInstallers', mode)

    scan_trusted_installers = property(get_scan_trusted_installers, set_scan_trusted_installers)

    #	Scan when copying between local folders
    def get_scan_copy_between_local_folders(self):
        """
        Get state of Scan when copying between local folders
        """
        return self.get_setting_value('General', 'scanCopyLocalFolders')

    def set_scan_copy_between_local_folders(self, mode):
        """
        Set state of Scan when copying between local folders
        """
        return self.set_setting_value('General', 'scanCopyLocalFolders', mode)

    scan_copy_between_local_folders = property(get_scan_copy_between_local_folders,
                                               set_scan_copy_between_local_folders)

    #	Scan when copying from network folders and removable drives
    def get_scan_copy_from_network(self):
        """
        Get state of Scan when copying from network folders and removable drives
        """
        return self.get_setting_value('General', 'scanCopyNetworkRemovable')

    def set_scan_copy_from_network(self, mode):
        """
        Set state of Scan when copying from network folders and removable drives
        """
        return self.set_setting_value('General', 'scanCopyNetworkRemovable', mode)

    scan_copy_from_network = property(get_scan_copy_from_network, set_scan_copy_from_network)

    #	Detect suspicious email attachments
    def get_scan_email_attachments(self):
        """
        Get state of Detect suspicious email attachments
        """
        return self.get_setting_value('General', 'scanEmailAttachments')

    def set_scan_email_attachments(self, mode):
        """
        Set state of Detect suspicious email attachments
        """
        return self.set_setting_value('General', 'scanEmailAttachments', mode)

    scan_email_attachments = property(get_scan_email_attachments, set_scan_email_attachments)

    #	Disable read/write scan of Shadow Copy volumes for SYSTEM process (improves performance)
    def get_scan_shadow_copy(self):
        """
        Get state of Read/Write scan of Shadow Copy volumes for SYSTEM process
        """
        mode = self.get_setting_value('General', 'scanShadowCopyDisableStatus')
        return '0' if mode == '1' else '1'

    def set_scan_shadow_copy(self, mode):
        """
        Set state of Read/Write scan of Shadow Copy volumes for SYSTEM process
        """
        mode = '0' if mode == '1' else '1'
        return self.set_setting_value('General', 'scanShadowCopyDisableStatus', mode)

    scan_shadow_copy = property(get_scan_shadow_copy, set_scan_shadow_copy)

    # ------------------------------ On-Access Policy ------------------------------
    # Ransomware:
    #	Detect unknown ransomware based on behaviour
    def get_detect_unknown_ransomware(self):
        """
        Get state of Detect unknown ransomware based on behaviour
        """
        return self.get_setting_value('General', 'detectUnknownRansomware')

    def set_detect_unknown_ransomware(self, mode):
        """
        Set state of Detect unknown ransomware based on behaviour
        """
        return self.set_setting_value('General', 'detectUnknownRansomware', mode)

    detect_unknown_ransomware = property(get_detect_unknown_ransomware,
                                         set_detect_unknown_ransomware)

    #	Create ransomware bait files on file system
    def get_ransomware_bait_files(self):
        """
        Get state of Create ransomware bait files on file system
        """
        return self.get_setting_value('General', 'ransomwareBaitFiles')

    def set_ransomware_bait_files(self, mode):
        """
        Set state of Create ransomware bait files on file system
        """
        return self.set_setting_value('General', 'ransomwareBaitFiles', mode)

    ransomware_bait_files = property(get_ransomware_bait_files, set_ransomware_bait_files)

    # ------------------------------ On-Access Policy ------------------------------
    # McAfee GTI:
    #	Enable McAfee GTI
    #   0 = OFF         Gti().DISABLED
    #   1 = Very Low    Gti().VERY_LOW
    #   2 = Low         Gti().LOW
    #   3 = Medium      Gti().MEDIUM
    #   4 = High        Gti().HIGH
    #   5 = Very High   Gti().VERY_HIGH
    def get_gti_level(self):
        """
        Get the GTI level (Use Gti class from constants)
        """
        return self.get_setting_value('GTI', 'GTISensitivityLevel')

    def set_gti_level(self, level):
        """
        Set the GTI level (Use Gti class from constants)
        """
        if level not in ['0', '1', '2', '3', '4', '5']:
            raise ValueError('GTI sensitivity level must be within ["0", "1", "2", "3", "4", "5"].')
        return self.set_setting_value('GTI', 'GTISensitivityLevel', level)

    gti_level = property(get_gti_level, set_gti_level)

    # ------------------------------ On-Access Policy ------------------------------
    # Antimalware Scan Interface:
    #	Enable AMSI (provides enhanced script scanning)
    def get_scan_amsi(self):
        """
        Get state of Enable AMSI (provides enhanced script scanning)
        """
        return self.get_setting_value('General', 'scanUsingAMSIHooks')

    def set_scan_amsi(self, mode):
        """
        Set state of Enable AMSI (provides enhanced script scanning)
        """
        return self.set_setting_value('General', 'scanUsingAMSIHooks', mode)

    scan_amsi = property(get_scan_amsi, set_scan_amsi)

    #	Enable Observe mode (Events are generated but actions are not enforced)
    def get_scan_amsi_observe_mode(self):
        """
        Get state of Enable AMSI Observe mode (Events are generated but actions are not enforced)
        """
        return self.get_setting_value('General', 'enableAMSIObserveMode')

    def set_scan_amsi_observe_mode(self, mode):
        """
        Set state of Enable AMSI Observe mode (Events are generated but actions are not enforced)
        """
        return self.set_setting_value('General', 'enableAMSIObserveMode', mode)

    scan_amsi_observe_mode = property(get_scan_amsi_observe_mode, set_scan_amsi_observe_mode)

    # ------------------------------ On-Access Policy ------------------------------
    # Threat Detection User Messaging:
    #	Display the On-Access Scan window to users when a threat is detected
    def get_show_alert(self):
        """
        Get state of Display the On-Access Scan window to users when a threat is detected
        """
        return self.get_setting_value('Alerting', 'bShowAlerts')

    def set_show_alert(self, mode):
        """
        Set state of Display the On-Access Scan window to users when a threat is detected
        """
        return self.set_setting_value('Alerting', 'bShowAlerts', mode)

    show_alert = property(get_show_alert, set_show_alert)

    #	Message: (Default = McAfee Endpoint Security detected a threat.)
    def get_alert_message(self):
        """
        Get Threat Detection message
        """
        return self.get_setting_value('Alerting', 'szDialogMessage')

    def set_alert_message(self, str_message="McAfee Endpoint Security detected a threat."):
        """
        Set Threat Detection message (256 caracters maximum)
        """
        check_length('Message', str_message, 256, required=True)
        return self.set_setting_value('Alerting', 'szDialogMessage', str_message)

    alert_message = property(get_alert_message, set_alert_message)

    # ------------------------------ On-Access Policy ------------------------------
    # Process Settings:
    def get_use_standard_settings_only(self):
        """
        Get Use Standard settings for all processes or
        Configure different settings for High Risk and Low Risk processes
        """
        return self.get_setting_value('General', 'bOnlyUseDefaultConfig')

    def set_use_standard_settings_only(self, mode):
        """
        Set Use Standard settings for all processes or
        Configure different settings for High Risk and Low Risk processes
        """
        return self.set_setting_value('General', 'bOnlyUseDefaultConfig', mode)

    use_standard_settings_only = property(get_use_standard_settings_only,
                                          set_use_standard_settings_only)

    # ------------------------------ On-Access Policy ------------------------------
    # Process Settings:
    def get_process_list(self):
        """
        Get the process list
        (Standard settings will apply to all unlisted processes.)
        Return a ProcessList object.
        """
        rows = self.get_indexed_table('Application', 'dwApplicationCount',
                                      ['szApplicationItem', 'TypeItem'])
        if rows is None:
            return None
        return [[row['szApplicationItem'], 'Low Risk' if row['TypeItem'] == '0' else 'High Risk']
                for row in rows]

    def set_process_list(self, table):
        """
        Set the process list with a ProcessList object as input
        Return true or false.
        """
        rows = []
        names = set()
        for name, risk in table:
            check_length('Process', name, 259, required=True)
            if not is_ens_process_name(name):
                raise ValueError('Invalid process name: {!r}'.format(name))
            if name.strip().lower() in names:
                raise ValueError('Duplicate process: {!r}'.format(name))
            names.add(name.strip().lower())
            if risk == 'Low Risk':
                type_item = '0'
            elif risk == 'High Risk':
                type_item = '1'
            else:
                raise ValueError('Risk level unknown: {}.'.format(risk))
            rows.append({'szApplicationItem': name, 'TypeItem': type_item})
        return self.set_indexed_table('Application', 'dwApplicationCount',
                                      ['szApplicationItem', 'TypeItem'], rows)

    process_list = property(get_process_list, set_process_list)

    # ---------------------- On-Access Policy - Standard ---------------------------
    # Process Settings:
    #	Process Type: Standard
    def get_when_to_scan(self, __section__='Default-Detection'):
        """
        Get When to scan, Reading/Writing.
        Returns a int value as following
        '0': Do not scan when reading from or writing to disk
        '1': When writing to disk (deprecated)
        '2': When reading from disk (deprecated)
        '3': Let McAfee decide
        '4': Let me decide, when writing to disk
        '5': Let me decide, when reading from disk
        '6': Let me decide, when writing and reading.
        """
        writing_mode = self.get_setting_value(__section__, 'bScanWriting')
        reading_mode = self.get_setting_value(__section__, 'bScanReading')
        writing_mode_bypass = self.get_setting_value(__section__, 'bScanWritingByPass')
        reading_mode_bypass = self.get_setting_value(__section__, 'bScanReadingByPass')
        if writing_mode_bypass == '2' and reading_mode_bypass == '2':
            level = '6'
        elif reading_mode_bypass == '2':
            level = '5'
        elif writing_mode_bypass == '2':
            level = '4'
        elif writing_mode == '1' and reading_mode == '1':
            level = '3'
        elif reading_mode == '1':
            level = '2'
        elif writing_mode == '1':
            level = '1'
        else:
            level = '0'
        return level

    def set_when_to_scan(self, level, __section__='Default-Detection'):
        """
        Set When to scan, Reading/Writing.
        Use following level as input:
        '0': Do not scan when reading from or writing to disk
        '1': When writing to disk (deprecated)
        '2': When reading from disk (deprecated)
        '3': Let McAfee decide
        '4': Let me decide, when writing to disk
        '5': Let me decide, when reading from disk
        '6': Let me decide, when writing and reading.
        """
        success = False
        if level not in ['0', '1', '2', '3', '4', '5', '6']:
            raise ValueError('Level must be within ["0", "1", "2", "3", "4", "5", "6"].')
        if level == '0' and __section__ != 'LowRisk-Detection':
            raise ValueError('Section must be set to "LowRisk-Detection".')
        success = True
        if level == '0':
            writing_mode = '0'
            reading_mode = '0'
            writing_mode_bypass = '0'
            reading_mode_bypass = '0'
        elif level in ['1', '4']:
            writing_mode = '1'
            reading_mode = '0'
            writing_mode_bypass = '2'
            reading_mode_bypass = '0'
        elif level in ['2', '5']:
            writing_mode = '0'
            reading_mode = '1'
            writing_mode_bypass = '0'
            reading_mode_bypass = '2'
        elif level == '3':
            writing_mode = '1'
            reading_mode = '1'
            writing_mode_bypass = '1'
            reading_mode_bypass = '1'
        else:
            writing_mode = '1'
            reading_mode = '1'
            writing_mode_bypass = '2'
            reading_mode_bypass = '2'
        self.set_setting_value(__section__, 'bScanWriting', writing_mode)
        self.set_setting_value(__section__, 'bScanReading', reading_mode)
        self.set_setting_value(__section__, 'bScanWritingByPass', writing_mode_bypass)
        self.set_setting_value(__section__, 'bScanReadingByPass', reading_mode_bypass)
        return success

    when_to_scan = property(get_when_to_scan, set_when_to_scan)

    #	Scanning - What to Scan
    def get_what_to_scan(self, __section__='Default-Detection'):
        """
        Get what to scan
        Returns level and extension as a tupple:
        '1': All files
        '2': Default and specified file types
        '3': Default and specified file types with scan for macros
        '4': Specified file types only (Extension must be defined)
             -> To scan also all files with no extension add the extension ':::'.
        """
        level = self.get_setting_value(__section__, 'extensionMode')
        extensions = self.get_setting_value(__section__, 'szProgExts')
        return (level, extensions)

    def set_what_to_scan(self, level, extensions='', __section__='Default-Detection'):
        """
        Set what to scan
        Use level and extension as inputs:
        '1': All files
        '2': Default and specified file types
        '3': Default and specified file types with scan for macros
        '4': Specified file types only (Extension must be defined)
             -> To scan also all files with no extension add the extension ':::'.
        """
        if level not in ['1', '2', '3', '4']:
            raise ValueError('Level must be within ["1", "2", "3", "4"].')
        if level == '4' and len(extensions) < 3:
            raise ValueError('Extensions list, comma separated, must be defined for this level.')
        check_file_type_list(extensions)
        self.set_setting_value(__section__, 'extensionMode', level)
        self.set_setting_value(__section__, 'szProgExts', extensions)
        return True

    what_to_scan = property(get_what_to_scan, set_what_to_scan)

    #	Scanning - What to Scan
    def get_scan_network_drives(self, __section__='Default-Detection'):
        """
        Get On network drives
        """
        return self.get_setting_value(__section__, 'bNetworkScanEnabled')

    def set_scan_network_drives(self, mode, __section__='Default-Detection'):
        """
        Set On network drives
        """
        return self.set_setting_value(__section__, 'bNetworkScanEnabled', mode)

    scan_network_drives = property(get_scan_network_drives, set_scan_network_drives)

    #	Scanning - What to Scan
    def get_scan_backups(self, __section__='Default-Detection'):
        """
        Get Opened for backups
        """
        return self.get_setting_value(__section__, 'bScanBackupReads')

    def set_scan_backups(self, mode, __section__='Default-Detection'):
        """
        Set Opened for backups
        """
        return self.set_setting_value(__section__, 'bScanBackupReads', mode)

    scan_backups = property(get_scan_backups, set_scan_backups)

    #	Scanning - What to Scan
    def get_scan_archives(self, __section__='Default-Detection'):
        """
        Get Compressed archive files
        """
        return self.get_setting_value(__section__, 'bScanArchives')

    def set_scan_archives(self, mode, __section__='Default-Detection'):
        """
        Set Compressed archive files
        """
        return self.set_setting_value(__section__, 'bScanArchives', mode)

    scan_archives = property(get_scan_archives, set_scan_archives)

    #	Scanning - What to Scan
    def get_scan_mime(self, __section__='Default-Detection'):
        """
        Get Compressed MIME-encoded files
        """
        return self.get_setting_value(__section__, 'bScanMime')

    def set_scan_mime(self, mode, __section__='Default-Detection'):
        """
        Set Compressed MIME-encoded files
        """
        return self.set_setting_value(__section__, 'bScanMime', mode)

    scan_mime = property(get_scan_mime, set_scan_mime)

    #	Scanning - Additional scan options
    def get_scan_pup(self, __section__='Default-Detection'):
        """
        Get Detect unwanted programs
        """
        return self.get_setting_value(__section__, 'bApplyNVP')

    def set_scan_pup(self, mode, __section__='Default-Detection'):
        """
        Set Detect unwanted programs
        """
        return self.set_setting_value(__section__, 'bApplyNVP', mode)

    scan_pup = property(get_scan_pup, set_scan_pup)

    #	Scanning - Additional scan options
    def get_scan_unknown_threats(self, __section__='Default-Detection'):
        """
        Get Detect unknown program threats
        """
        return self.get_setting_value(__section__, 'bUnknownProgramHeuristics')

    def set_scan_unknown_threats(self, mode, __section__='Default-Detection'):
        """
        Set Detect unknown program threats
        """
        return self.set_setting_value(__section__, 'bUnknownProgramHeuristics', mode)

    scan_unknown_threats = property(get_scan_unknown_threats, set_scan_unknown_threats)

    #	Scanning - Additional scan options
    def get_scan_unknown_macro(self, __section__='Default-Detection'):
        """
        Get Detect unknown macro threats
        """
        return self.get_setting_value(__section__, 'bUnknownMacroHeuristics')

    def set_scan_unknown_macro(self, mode, __section__='Default-Detection'):
        """
        Set Detect unknown macro threats
        """
        return self.set_setting_value(__section__, 'bUnknownMacroHeuristics', mode)

    scan_unknown_macro = property(get_scan_unknown_macro, set_scan_unknown_macro)

    # ---------------------- On-Access Policy - Standard ---------------------------
    #	Actions:
    def get_action_threat_first_response(self, __section__='Default-Detection'):
        """
        Get Action - Threat detection first response
        Return the value of the current level
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        """
        return self.get_setting_value(__section__, 'uAction')

    def set_action_threat_first_response(self, action, __section__='Default-Detection'):
        """
        Set Action - Threat detection first response
        Use the following value:
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        """
        if action not in ['1', '2', '3']:
            raise ValueError('Action must be within ["1", "2", "3"].')
        return self.set_setting_value(__section__, 'uAction', action)

    action_threat_first_response = property(get_action_threat_first_response,
                                            set_action_threat_first_response)

    def get_action_threat_second_response(self, __section__='Default-Detection'):
        """
        Get Action - If first response fails:
        Secondary action must greater than the first one
        '2': Delete files
        '3': Deny access to files
        If first = '3' -> No secondary options available for this action.
        """
        return self.get_setting_value(__section__, 'uSecAction')

    def set_action_threat_second_response(self, action, __section__='Default-Detection'):
        """
        Set Action - If first response fails:
        Secondary action must greater than the first one
        '2': Delete files
        '3': Deny access to files
        If first = '3' -> No secondary options available for this action.
        """
        if action not in ['2', '3']:
            raise ValueError('Action must be within ["2", "3"].')
        first_action = int(self.get_setting_value(__section__, 'uAction'))
        if int(action) <= first_action:
            raise ValueError('Action must be greater than the first response.')
        return self.set_setting_value(__section__, 'uSecAction', action)

    action_threat_second_response = property(get_action_threat_second_response,
                                             set_action_threat_second_response)

    def get_action_pup_first_response(self, __section__='Default-Detection'):
        """
        Get Action - Unwanted program first response:
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        """
        return self.get_setting_value(__section__, 'uAction_Program')

    def set_action_pup_first_response(self, action, __section__='Default-Detection'):
        """
        Set Action - Unwanted program first response:
        '1': Clean files
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        """
        if action not in ['1', '2', '3', '4']:
            raise ValueError('Action must be within ["1", "2", "3", "4"].')
        return self.set_setting_value(__section__, 'uAction_Program', action)

    action_pup_first_response = property(get_action_pup_first_response,
                                         set_action_pup_first_response)

    def get_action_pup_second_response(self, __section__='Default-Detection'):
        """
        Get Action - If first response fails:
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        If first >= '3' -> No secondary options available for this action.
        """
        return self.get_setting_value(__section__, 'uSecAction_Program')

    def set_action_pup_second_response(self, action, __section__='Default-Detection'):
        """
        Set Action - If first response fails:
        '2': Delete files
        '3': Deny access to files
        '4': Allow access to files
        If first >= '3' -> No secondary options available for this action.
        """
        if action not in ['2', '3', '4']:
            raise ValueError('Action must be within ["2", "3", "4"].')
        first_action = int(self.get_setting_value(__section__, 'uAction_Program'))
        if int(action) <= first_action:
            raise ValueError('Action must be greater than the first response.')
        return self.set_setting_value(__section__, 'uSecAction_Program', action)

    action_pup_second_response = property(get_action_pup_second_response,
                                          set_action_pup_second_response)

    # ---------------------- On-Access Policy - Standard ---------------------------
    #   Hidden setting
    def __get_action_on_error(self, __section__='Default-Detection'):
        """
        Get Hidden setting - Action on scanning error
        Default value set to: Allow access to files
        """
        return self.get_setting_value(__section__, 'uScanErrorAction')

    def __get_action_on_timeout(self, __section__='Default-Detection'):
        """
        Get Hidden setting - Action on scanning time-out
        Default value set to: Allow access to files
        """
        return self.get_setting_value(__section__, 'uTimeOutAction')

    # ---------------------- On-Access Policy - Standard ---------------------------
    #	Exclusions - Standard
    def get_exclusion_list(self, __section__='Default-Detection_Exclusions'):
        """
        Get exclusions list
        Return a list that can be used as ProcessList object.
        """
        values = self.get_indexed_list(__section__, 'dwExclusionCount', 'ExcludedItem_{}')
        if not values:
            return None
        return [value.split('|') for value in values]

    def set_exclusion_list(self, table, __section__='Default-Detection_Exclusions'):
        """
        Set exclusions list
        Use a list or a ProcessList object as input (rows checked as in the
        console, see check_exclusion_rows)
        """
        values = ['|'.join(row) for row in check_exclusion_rows(table)]
        return self.set_indexed_list(__section__, 'dwExclusionCount', 'ExcludedItem_{}', values)

    exclusion_list = property(get_exclusion_list, set_exclusion_list)

    def get_overwrite_exclusions(self, __section__='Default-Detection_Exclusions'):
        """
        Get Exclusions - Overwrite exclusions configured on the client
        """
        return self.get_setting_value(__section__, 'bOverwriteExclusions')

    def set_overwrite_exclusions(self, mode, __section__='Default-Detection_Exclusions'):
        """
        Set Exclusions - Overwrite exclusions configured on the client
        """
        return self.set_setting_value(__section__, 'bOverwriteExclusions', mode)

    overwrite_exclusions = property(get_overwrite_exclusions, set_overwrite_exclusions)

    # ---------------------- On-Access Policy - High Risk ---------------------------
    # Process Settings:
    #	Process Type: High Risk
    def get_when_to_scan_hr(self):
        """
        Get When to scan, Reading/Writing for High Risk process.
        Read get_when_to_scan for more help.
        """
        return self.get_when_to_scan('HighRisk-Detection')

    def set_when_to_scan_hr(self, level):
        """
        Set When to scan, Reading/Writing for High Risk process.
        Read set_when_to_scan for more help.
        """
        return self.set_when_to_scan(level, 'HighRisk-Detection')

    when_to_scan_hr = property(get_when_to_scan_hr, set_when_to_scan_hr)

    #   Scanning - What to Scan - High Risk
    def get_what_to_scan_hr(self):
        """
        Get what to scan for High Risk process.
        """
        return self.get_what_to_scan('HighRisk-Detection')

    def set_what_to_scan_hr(self, level, extensions=''):
        """
        Set what to scan for High Risk process.
        """
        return self.set_what_to_scan(level, extensions, 'HighRisk-Detection')

    what_to_scan_hr = property(get_what_to_scan_hr, set_what_to_scan_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_network_drives_hr(self, __section__='Default-Detection'):
        """
        Get On network drives for High Risk process.
        """
        return self.get_scan_network_drives('HighRisk-Detection')

    def set_scan_network_drives_hr(self, mode):
        """
        Set On network drives for High Risk process.
        """
        return self.set_scan_network_drives(mode, 'HighRisk-Detection')

    scan_network_drives_hr = property(get_scan_network_drives_hr, set_scan_network_drives_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_backups_hr(self):
        """
        Get Opened for backups for High Risk process.
        """
        return self.get_scan_backups('HighRisk-Detection')

    def set_scan_backups_hr(self, mode):
        """
        Set Opened for backups for High Risk process.
        """
        return self.set_scan_backups(mode, 'HighRisk-Detection')

    scan_backups_hr = property(get_scan_backups_hr, set_scan_backups_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_archives_hr(self):
        """
        Get Compressed archive files for High Risk process.
        """
        return self.get_scan_archives('HighRisk-Detection')

    def set_scan_archives_hr(self, mode):
        """
        Set Compressed archive files for High Risk process.
        """
        return self.set_scan_archives(mode, 'HighRisk-Detection')

    scan_archives_hr = property(get_scan_archives_hr, set_scan_archives_hr)

    #	Scanning - What to Scan - High Risk
    def get_scan_mime_hr(self):
        """
        Get Compressed MIME-encoded files for High Risk process.
        """
        return self.get_scan_mime('HighRisk-Detection')

    def set_scan_mime_hr(self, mode):
        """
        Set Compressed MIME-encoded files for High Risk process.
        """
        return self.set_scan_mime(mode, 'HighRisk-Detection')

    scan_mime_hr = property(get_scan_mime_hr, set_scan_mime_hr)

    #	Scanning - Additional scan options - High Risk
    def get_scan_pup_hr(self):
        """
        Get Detect unwanted programs for High Risk process.
        """
        return self.get_scan_pup('HighRisk-Detection')

    def set_scan_pup_hr(self, mode):
        """
        Set Detect unwanted programs for High Risk process.
        """
        return self.set_scan_pup(mode, 'HighRisk-Detection')

    scan_pup_hr = property(get_scan_pup_hr, set_scan_pup_hr)

    #	Scanning - Additional scan options - High Risk
    def get_scan_unknown_threats_hr(self):
        """
        Get Detect unknown program threats for High Risk process.
        """
        return self.get_scan_unknown_threats('HighRisk-Detection')

    def set_scan_unknown_threats_hr(self, mode):
        """
        Set Detect unknown program threats for High Risk process.
        """
        return self.set_scan_unknown_threats(mode, 'HighRisk-Detection')

    scan_unknown_threats_hr = property(get_scan_unknown_threats_hr, set_scan_unknown_threats_hr)

    #	Scanning - Additional scan options - High Risk
    def get_scan_unknown_macro_hr(self):
        """
        Get Detect unknown macro threats for High Risk process.
        """
        return self.get_scan_unknown_macro('HighRisk-Detection')

    def set_scan_unknown_macro_hr(self, mode):
        """
        Set Detect unknown macro threats for High Risk process.
        """
        return self.set_scan_unknown_macro(mode, 'HighRisk-Detection')

    scan_unknown_macro_hr = property(get_scan_unknown_macro_hr, set_scan_unknown_macro_hr)

    # ---------------------- On-Access Policy - High Risk ---------------------------
    #	Actions:
    def get_action_threat_first_response_hr(self):
        """
        Get Action - Threat detection first response for High Risk process.
        """
        return self.get_action_threat_first_response('HighRisk-Detection')

    def set_action_threat_first_response_hr(self, action):
        """
        Set Action - Threat detection first response for High Risk process.
        """
        return self.set_action_threat_first_response(action, 'HighRisk-Detection')

    action_threat_first_response_hr = property(get_action_threat_first_response_hr,
                                            set_action_threat_first_response_hr)

    def get_action_threat_second_response_hr(self):
        """
        Get Action - If first response fails for High Risk process.
        """
        return self.get_action_threat_second_response('HighRisk-Detection')

    def set_action_threat_second_response_hr(self, action):
        """
        Set Action - If first response fails for High Risk process.
        """
        return self.set_action_threat_second_response(action, 'HighRisk-Detection')

    action_threat_second_response_hr = property(get_action_threat_second_response_hr,
                                             set_action_threat_second_response_hr)

    def get_action_pup_first_response_hr(self):
        """
        Get Action - Unwanted program first response for High Risk process.
        """
        return self.get_action_pup_first_response('HighRisk-Detection')

    def set_action_pup_first_response_hr(self, action):
        """
        Set Action - Unwanted program first response for High Risk process.
        """
        return self.set_action_pup_first_response(action, 'HighRisk-Detection')

    action_pup_first_response_hr = property(get_action_pup_first_response_hr,
                                         set_action_pup_first_response_hr)

    def get_action_pup_second_response_hr(self):
        """
        Get Action - If first response fails for High Risk process.
        """
        return self.get_action_pup_second_response('HighRisk-Detection')

    def set_action_pup_second_response_hr(self, action):
        """
        Set Action - If first response fails for High Risk process.
        """
        return self.set_action_pup_second_response(action, 'HighRisk-Detection')

    action_pup_second_response_hr = property(get_action_pup_second_response_hr,
                                          set_action_pup_second_response_hr)

    # ---------------------- On-Access Policy - High Risk ---------------------------
    #   Hidden setting
    def __get_action_on_error_hr(self):
        """
        Get Hidden setting - Action on scanning error for High Risk process.
        """
        return self.__get_action_on_error('HighRisk-Detection')

    def __get_action_on_timeout_hr(self):
        """
        Get Hidden setting - Action on scanning time-out for High Risk process.
        """
        return self.__get_action_on_timeout('HighRisk-Detection')

    # ---------------------- On-Access Policy - High Risk ---------------------------
    #	Exclusions - High Risk
    def get_exclusion_list_hr(self):
        """
        Get exclusions list for High Risk process.
        """
        return self.get_exclusion_list('HighRisk-Detection_Exclusions')

    def set_exclusion_list_hr(self, table):
        """
        Set exclusions list for High Risk process.
        """
        return self.set_exclusion_list(table, 'HighRisk-Detection_Exclusions')

    exclusion_list_hr = property(get_exclusion_list_hr, set_exclusion_list_hr)

    def get_overwrite_exclusions_hr(self):
        """
        Get Exclusions - Overwrite exclusions configured on the client for High-Risk process
        """
        return self.get_overwrite_exclusions('HighRisk-Detection_Exclusions')

    def set_overwrite_exclusions_hr(self, mode):
        """
        Set Exclusions - Overwrite exclusions configured on the client for High-Risk process
        """
        return self.set_overwrite_exclusions(mode, 'HighRisk-Detection_Exclusions')

    overwrite_exclusions_hr = property(get_overwrite_exclusions_hr, set_overwrite_exclusions_hr)

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    # Process Settings:
    #	Process Type: Low Risk
    def get_when_to_scan_lr(self):
        """
        Get When to scan, Reading/Writing for Low Risk process.
        Read get_when_to_scan for more help.
        """
        return self.get_when_to_scan('LowRisk-Detection')

    def set_when_to_scan_lr(self, level):
        """
        Set When to scan, Reading/Writing for Low Risk process.
        Read set_when_to_scan for more help.
        """
        return self.set_when_to_scan(level, 'LowRisk-Detection')

    when_to_scan_lr = property(get_when_to_scan_lr, set_when_to_scan_lr)

    #   Scanning - What to Scan - Low Risk
    def get_what_to_scan_lr(self):
        """
        Get what to scan for Low Risk process.
        """
        return self.get_what_to_scan('LowRisk-Detection')

    def set_what_to_scan_lr(self, level, extensions=''):
        """
        Set what to scan for Low Risk process.
        """
        return self.set_what_to_scan(level, extensions, 'LowRisk-Detection')

    what_to_scan_lr = property(get_what_to_scan_lr, set_what_to_scan_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_network_drives_lr(self, __section__='Default-Detection'):
        """
        Get On network drives for Low Risk process.
        """
        return self.get_scan_network_drives('LowRisk-Detection')

    def set_scan_network_drives_lr(self, mode):
        """
        Set On network drives for Low Risk process.
        """
        return self.set_scan_network_drives(mode, 'LowRisk-Detection')

    scan_network_drives_lr = property(get_scan_network_drives_lr, set_scan_network_drives_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_backups_lr(self):
        """
        Get Opened for backups for Low Risk process.
        """
        return self.get_scan_backups('LowRisk-Detection')

    def set_scan_backups_lr(self, mode):
        """
        Set Opened for backups for Low Risk process.
        """
        return self.set_scan_backups(mode, 'LowRisk-Detection')

    scan_backups_lr = property(get_scan_backups_lr, set_scan_backups_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_archives_lr(self):
        """
        Get Compressed archive files for Low Risk process.
        """
        return self.get_scan_archives('LowRisk-Detection')

    def set_scan_archives_lr(self, mode):
        """
        Set Compressed archive files for Low Risk process.
        """
        return self.set_scan_archives(mode, 'LowRisk-Detection')

    scan_archives_lr = property(get_scan_archives_lr, set_scan_archives_lr)

    #	Scanning - What to Scan - Low Risk
    def get_scan_mime_lr(self):
        """
        Get Compressed MIME-encoded files for Low Risk process.
        """
        return self.get_scan_mime('LowRisk-Detection')

    def set_scan_mime_lr(self, mode):
        """
        Set Compressed MIME-encoded files for Low Risk process.
        """
        return self.set_scan_mime(mode, 'LowRisk-Detection')

    scan_mime_lr = property(get_scan_mime_lr, set_scan_mime_lr)

    #	Scanning - Additional scan options - Low Risk
    def get_scan_pup_lr(self):
        """
        Get Detect unwanted programs for Low Risk process.
        """
        return self.get_scan_pup('LowRisk-Detection')

    def set_scan_pup_lr(self, mode):
        """
        Set Detect unwanted programs for Low Risk process.
        """
        return self.set_scan_pup(mode, 'LowRisk-Detection')

    scan_pup_lr = property(get_scan_pup_lr, set_scan_pup_lr)

    #	Scanning - Additional scan options - Low Risk
    def get_scan_unknown_threats_lr(self):
        """
        Get Detect unknown program threats for Low Risk process.
        """
        return self.get_scan_unknown_threats('LowRisk-Detection')

    def set_scan_unknown_threats_lr(self, mode):
        """
        Set Detect unknown program threats for Low Risk process.
        """
        return self.set_scan_unknown_threats(mode, 'LowRisk-Detection')

    scan_unknown_threats_lr = property(get_scan_unknown_threats_lr, set_scan_unknown_threats_lr)

    #	Scanning - Additional scan options - Low Risk
    def get_scan_unknown_macro_lr(self):
        """
        Get Detect unknown macro threats for Low Risk process.
        """
        return self.get_scan_unknown_macro('LowRisk-Detection')

    def set_scan_unknown_macro_lr(self, mode):
        """
        Set Detect unknown macro threats for Low Risk process.
        """
        return self.set_scan_unknown_macro(mode, 'LowRisk-Detection')

    scan_unknown_macro_lr = property(get_scan_unknown_macro_lr, set_scan_unknown_macro_lr)

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    #	Actions:
    def get_action_threat_first_response_lr(self):
        """
        Get Action - Threat detection first response for Low Risk process.
        """
        return self.get_action_threat_first_response('LowRisk-Detection')

    def set_action_threat_first_response_lr(self, action):
        """
        Set Action - Threat detection first response for Low Risk process.
        """
        return self.set_action_threat_first_response(action, 'LowRisk-Detection')

    action_threat_first_response_lr = property(get_action_threat_first_response_lr,
                                            set_action_threat_first_response_lr)

    def get_action_threat_second_response_lr(self):
        """
        Get Action - If first response fails for Low Risk process.
        """
        return self.get_action_threat_second_response('LowRisk-Detection')

    def set_action_threat_second_response_lr(self, action):
        """
        Set Action - If first response fails for Low Risk process.
        """
        return self.set_action_threat_second_response(action, 'LowRisk-Detection')

    action_threat_second_response_lr = property(get_action_threat_second_response_lr,
                                             set_action_threat_second_response_lr)

    def get_action_pup_first_response_lr(self):
        """
        Get Action - Unwanted program first response for Low Risk process.
        """
        return self.get_action_pup_first_response('LowRisk-Detection')

    def set_action_pup_first_response_lr(self, action):
        """
        Set Action - Unwanted program first response for Low Risk process.
        """
        return self.set_action_pup_first_response(action, 'LowRisk-Detection')

    action_pup_first_response_lr = property(get_action_pup_first_response_lr,
                                         set_action_pup_first_response_lr)

    def get_action_pup_second_response_lr(self):
        """
        Get Action - If first response fails for Low Risk process.
        """
        return self.get_action_pup_second_response('LowRisk-Detection')

    def set_action_pup_second_response_lr(self, action):
        """
        Set Action - If first response fails for Low Risk process.
        """
        return self.set_action_pup_second_response(action, 'LowRisk-Detection')

    action_pup_second_response_lr = property(get_action_pup_second_response_lr,
                                          set_action_pup_second_response_lr)

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    #   Hidden setting
    def __get_action_on_error_lr(self):
        """
        Get Hidden setting - Action on scanning error for Low Risk process.
        """
        return self.__get_action_on_error('LowRisk-Detection')

    def __get_action_on_timeout_lr(self):
        """
        Get Hidden setting - Action on scanning time-out for Low Risk process.
        """
        return self.__get_action_on_timeout('LowRisk-Detection')

    # ---------------------- On-Access Policy - Low Risk ---------------------------
    #	Exclusions - Low Risk
    def get_exclusion_list_lr(self):
        """
        Get exclusions list for Low Risk process.
        """
        return self.get_exclusion_list('LowRisk-Detection_Exclusions')

    def set_exclusion_list_lr(self, table):
        """
        Set exclusions list for Low Risk process.
        """
        return self.set_exclusion_list(table, 'LowRisk-Detection_Exclusions')

    exclusion_list_lr = property(get_exclusion_list_lr, set_exclusion_list_lr)

    def get_overwrite_exclusions_lr(self):
        """
        Get Exclusions - Overwrite exclusions configured on the client for Low Risk process
        """
        return self.get_overwrite_exclusions('LowRisk-Detection_Exclusions')

    def set_overwrite_exclusions_lr(self, mode):
        """
        Set Exclusions - Overwrite exclusions configured on the client for Low Risk process
        """
        return self.set_overwrite_exclusions(mode, 'LowRisk-Detection_Exclusions')

    overwrite_exclusions_lr = property(get_overwrite_exclusions_lr, set_overwrite_exclusions_lr)

    # ------------------------------ On-Access Policy ------------------------------
    # ScriptScan:
    def get_script_scan(self):
        """
        Get Enable ScriptScan
        """
        return self.get_setting_value('ScriptScan', 'scriptScanEnabled')

    def set_script_scan(self, mode):
        """
        Set Enable ScriptScan
        """
        return self.set_setting_value('ScriptScan', 'scriptScanEnabled', mode)

    script_scan = property(get_script_scan, set_script_scan)

    #	Exclude these URLs or partial URLs:
    def get_script_scan_exclusions(self):
        """
        Get Excluded URLs
        Return a list or an URLList object
        """
        return self.get_indexed_list('ScriptScanURLExclItems', 'dwScriptScanURLExclItemCount',
                                     'ScriptScanExclusionURL_{}')

    def set_script_scan_exclusions(self, excluded_urls):
        """
        Set Excluded URLs
        Use URLList object as input (2048 characters max each, no duplicate)
        """
        seen = set()
        for url in excluded_urls:
            check_length('Excluded URL', url, 2048, required=True)
            if url.strip() in seen:
                raise ValueError('Duplicate excluded URL: {!r}'.format(url))
            seen.add(url.strip())
        return self.set_indexed_list('ScriptScanURLExclItems', 'dwScriptScanURLExclItemCount',
                                     'ScriptScanExclusionURL_{}', excluded_urls)

    script_scan_exclusions = property(get_script_scan_exclusions, set_script_scan_exclusions)

    # ------------------------------ Markdown export ------------------------------
    # Console labels (ePO 5.10, ENS 10.7): see Policy.to_markdown().
    __MD_OAS_STATE = {'0': 'Disable', '1': 'Enable',
                      '2': 'Disable and unregister with Windows Security Center'}
    __MD_GTI = {'0': 'Disabled', '1': 'Very low', '2': 'Low', '3': 'Medium',
                '4': 'High', '5': 'Very high'}
    __MD_WHEN = {'0': 'Do not scan when reading from or writing to disk',
                 '1': 'When writing to disk', '2': 'When reading from disk',
                 '3': 'Let Trellix decide',
                 '4': 'Let me decide: When writing to disk',
                 '5': 'Let me decide: When reading from disk',
                 '6': 'Let me decide: When writing to and reading from disk'}
    __MD_WHAT = {'1': 'All files', '2': 'Default and specified file types',
                 '3': 'Default and specified file types (also scan for macros in all files)',
                 '4': 'Specified file types only'}
    # Resource IDs stored in place of the console default texts.
    __MD_MESSAGES = {'IDS_OAS_DEFAULT_THREAT_MESSAGE':
                     'Trellix Endpoint Security detected a threat.'}
    __MD_ACTION = {'1': 'Clean files', '2': 'Delete files', '3': 'Deny access to files',
                   '4': 'Allow access to files'}

    def __md_process_type(self, section):
        """
        Returns the Markdown of one "Process Types" tab (Standard, High Risk
        or Low Risk) from its Detection section.
        """
        check = self.md_check
        action = lambda setting: self.__MD_ACTION.get(
            self.get_setting_value(section, setting), self.get_setting_value(section, setting))
        what, extensions = self.get_what_to_scan(section)
        what_label = self.__MD_WHAT.get(what, what)
        if what in ['2', '3', '4']:
            what_label += ' ({})'.format(extensions if extensions else 'no additional file type')
        text = '#### Scanning\n\n'
        text += self.md_settings([
            ['When to scan', self.__MD_WHEN.get(self.get_when_to_scan(section))],
            ['What to scan', what_label],
            ['On network drives', check(self.get_scan_network_drives(section))],
            ['Opened for backups (Windows only)', check(self.get_scan_backups(section))],
            ['Compressed archive files', check(self.get_scan_archives(section))],
            ['Compressed MIME-encoded files', check(self.get_scan_mime(section))],
            ['Additional scan options: Detect unwanted programs',
             check(self.get_scan_pup(section))],
            ['Additional scan options: Detect unknown program threats',
             check(self.get_scan_unknown_threats(section))],
            ['Additional scan options: Detect unknown macro threats',
             check(self.get_scan_unknown_macro(section))]])
        text += '\n#### Actions\n\n'
        text += self.md_settings([
            ['Threat detection first response', action('uAction')],
            ['Threat detection - If first response fails', action('uSecAction')],
            ['Unwanted program first response', action('uAction_Program')],
            ['Unwanted program - If first response fails', action('uSecAction_Program')],
            ['On Timeout (Linux only)', action('uTimeOutAction')],
            ['On Scan Error (Linux only)', action('uScanErrorAction')]])
        text += '\n#### Exclusions\n\n'
        rows = OASExclusionList(self.get_exclusion_list(section + '_Exclusions')).md_rows()
        text += self.md_table(['Item', 'Exclude Subfolders', 'Read/Write', 'Notes'], rows,
                              numbered=True)
        text += '\n' + self.md_settings([
            ['Overwrite exclusions configured on the client',
             check(self.get_overwrite_exclusions(section + '_Exclusions'))]])
        return text

    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        check = self.md_check
        sections = []
        max_scan_time = 'Yes ({} seconds)'.format(self.get_max_scan_time()) \
            if self.get_max_scan_time_enforced() == '1' else 'No'
        sections.append(('On-Access Scan', self.md_settings([
            ['On-Access Scan', self.__MD_OAS_STATE.get(self.get_on_access_scan(),
                                                       self.get_on_access_scan())],
            ['Enable On-Access Scan on system startup (Windows only)',
             check(self.get_scan_on_startup())],
            ['Allow users to disable On-Access Scan from the Trellix system tray icon '
             '(Windows only)', check(self.get_allow_user_to_disable_oas())],
            ['Specify maximum number of seconds for each file scan', max_scan_time],
            ['Scan boot sectors (Windows only)', check(self.get_scan_boot_sectors())],
            ['Scan processes on service startup and content update (Windows only)',
             check(self.get_scan_process_startup())],
            ['Scan trusted installers (Windows only)', check(self.get_scan_trusted_installers())],
            ['Scan when copying between local folders (Windows only)',
             check(self.get_scan_copy_between_local_folders())],
            ['Scan when copying from network folders and removable drives (Windows only)',
             check(self.get_scan_copy_from_network())],
            ['Detect suspicious email attachments (Windows only)',
             check(self.get_scan_email_attachments())],
            ['Disable read/write scan of Shadow Copy volumes for SYSTEM process '
             '(improves performance) (Windows only)',
             check(self.get_setting_value('General', 'scanShadowCopyDisableStatus'))]])))
        sections.append(('Ransomware', self.md_settings([
            ['Detect unknown ransomware based on behaviour',
             check(self.get_detect_unknown_ransomware())],
            ['Create ransomware bait files on file system',
             check(self.get_ransomware_bait_files())]])))
        gti_level = self.get_gti_level()
        sections.append(('Trellix GTI', self.md_settings([
            ['Enable Trellix GTI', 'No' if gti_level in [None, '0'] else 'Yes'],
            ['Sensitivity level', self.__MD_GTI.get(gti_level, gti_level)]])))
        sections.append(('Antimalware Scan Interface (Windows only)', self.md_settings([
            ['Enable AMSI (provides enhanced script scanning)', check(self.get_scan_amsi())],
            ['Enable Observe mode (Events are generated but actions are not enforced)',
             check(self.get_scan_amsi_observe_mode())]])))
        sections.append(('Threat Detection User Messaging (Windows only)', self.md_settings([
            ['Display the On-Access Scan window to users when a threat is detected',
             check(self.get_show_alert())],
            ['Message', self.__MD_MESSAGES.get(self.get_alert_message(),
                                               self.get_alert_message())]])))
        standard_only = self.get_use_standard_settings_only() == '1'
        text = self.md_settings([[
            'Process Settings', 'Use Standard settings for all processes' if standard_only
            else 'Configure different settings for High Risk and Low Risk processes']])
        process_types = [('Standard', 'Default-Detection')]
        if not standard_only:
            text += '\nStandard settings will apply to all unlisted processes.\n\n'
            text += self.md_table(['Process', 'Process Type'], self.get_process_list() or [],
                                  numbered=True)
            process_types += [('High Risk', 'HighRisk-Detection'),
                              ('Low Risk', 'LowRisk-Detection')]
        for label, section in process_types:
            text += '\n### Process Type: {}\n\n'.format(label)
            text += self.__md_process_type(section)
        sections.append(('Process Settings', text))
        text = self.md_settings([['Enable ScriptScan', check(self.get_script_scan())]])
        text += '\n### Exclude these URLs or partial URLs\n\n'
        text += self.md_table(['URL'], [[url] for url in self.get_script_scan_exclusions() or []],
                              numbered=True)
        sections.append(('ScriptScan (Windows only)', text))
        return sections


class OASProcessList:
    """
    The OASProcessList class can be used to edit the list of process.
    All process names are associated to a risk level: Low or High.
    """

    def __init__(self, process_list=None):
        self.proc_list = process_list if process_list is not None else []

    def __repr__(self):
        return '<OASProcessList which contains {} process(s)>'.format(len(self.proc_list))

    def add(self, process_name, process_type):
        """
        Add a process name of process type within the process list.
        :process_name: The name of the process.
        :process_type: 'Low Risk' or 'High Risk' value.
        """
        success = False
        if process_type not in ['Low Risk', 'High Risk']:
            raise ValueError('Process Type unknown. Value must be "Low Risk" or "High Risk".')
        if not self.contains(process_name):
            row = []
            row.append(process_name)
            row.append(process_type)
            self.proc_list.append(row)
            success = True
        return success

    def add_low_risk(self, process_name):
        """
        Add a low risk process name within the process list.
        :process_name: The name of the process.
        """
        return self.add(process_name, 'Low Risk')

    def add_high_risk(self, process_name):
        """
        Add a high risk process name within the process list.
        :process_name: The name of the process.
        """
        return self.add(process_name, 'High Risk')

    def remove(self, process_name):
        """
        Remove a process name of the process list.
        :process_name: The name of the process.
        """
        table = [row for row in self.proc_list if row[0] != process_name]
        self.proc_list = table
        return True

    def contains(self, process_name):
        """
        Return True if the process list contains a process name.
        :process_name: The name of the process.
        """
        search = [row[0] for row in self.proc_list if row[0] == process_name]
        return len(search) >= 1

    def contains_low_risk(self, process_name):
        """
        Return True if the process list contains a low risk process name.
        :process_name: The name of the process.
        """
        search = [row[0] for row in self.proc_list
                  if row[0] == process_name and row[1] == 'Low Risk']
        return len(search) >= 1

    def contains_high_risk(self, process_name):
        """
        Return True if the process list contains a high risk process name.
        :process_name: The name of the process.
        """
        search = [row[0] for row in self.proc_list
                  if row[0] == process_name and row[1] == 'High Risk']
        return len(search) >= 1

class OASExclusionList(ExclusionList):
    pass

class OASURLList:
    """
    The OASURLList class can be used to edit the list of excluded URL.
    """

    def __init__(self, excluded_urls=None):
        self.url_list = excluded_urls if excluded_urls is not None else []

    def __repr__(self):
        return '<OASURLList which contains {} exclusion(s)>'.format(len(self.url_list))

    def add(self, url):
        """
        Add an url in the excluded url list.
        :url: The URL to be added.
        """
        success = False
        if not self.contains(url):
            self.url_list.append(url)
            success = True
        return success

    def remove(self, url):
        """
        Remove an url of the excluded url list.
        :url: The URL to be removed.
        """
        self.url_list.remove(url)
        return True

    def contains(self, url):
        """
        Return True if the excluded url list contains an url.
        :url: The URL to look for.
        """
        search = [row for row in self.url_list if row == url]
        return len(search) >= 1
