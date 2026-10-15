# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESTPPolicyOptions.
"""

from ...policies import Policy
from ...validators import check_int, check_length

# Prefixes of the Quarantine folder (prefixSelect of the Options page).
QUARANTINE_PREFIXES = ['<SYSTEM_DRIVE>', '<SYSTEM_ROOT>', '<SYSTEM_DIR>', '<TEMP_DIR>',
                       '<PROGRAM_FILES_DIR>', '<PROGRAM_FILES_COMMON_DIR>',
                       '<SOFTWARE_INSTALLED_DIR>']


def check_quarantine_folder(folder):
    """
    Raise ValueError if the console refuses a Quarantine folder
    (validateQuarantineFilePath of the Options page): a Linux path starting
    with /; a prefix of QUARANTINE_PREFIXES, a backslash and a folder of 190
    characters without : / * " < > | ?; or a path of 190 characters
    starting with a drive (C:, ?:, *:) or **, then a backslash, without
    / " < > ? : | after it nor double backslash.
    """
    if not isinstance(folder, str) or not folder.strip():
        raise ValueError('The quarantine folder is required.')
    if folder.startswith('/'):
        return folder
    prefix, _, rest = folder.partition('\\')
    if prefix in QUARANTINE_PREFIXES:
        check_length('Quarantine folder', rest, 190, required=True)
        valid = not any(char in rest for char in ':/*"<>|?')
    else:
        check_length('Quarantine folder', folder, 190)
        start = 3 if folder[:2] == '**' or (len(folder) > 1 and folder[1] == ':' and
                                             (folder[0].isascii() and folder[0].isalpha() or
                                              folder[0] in '*?')) else 0
        valid = start == 3 and folder[2:3] == '\\' and '\\\\' not in folder[2:] and \
            not any(char in folder[3:] for char in '/"<>?:|')
    if not valid:
        raise ValueError('Invalid quarantine folder: {!r}'.format(folder))
    return folder

class ESTPPolicyOptions(Policy):
    """
    The ESTPPolicyOptions class can be used to edit the Endpoint Security
    Threat Prevention policy: Options (checked against the ePO 5.10 console).
    """

    MD_PRODUCT = 'Endpoint Security Threat Prevention'
    MD_CATEGORY = 'Options'

    def __init__(self, policy_from_estppolicies=None):
        super(ESTPPolicyOptions, self).__init__(policy_from_estppolicies)
        if policy_from_estppolicies is not None:
            if self.get_type() != 'EAM_CommonScan_Policies':
                raise ValueError('Wrong policy! Policy type must be "EAM_CommonScan_Policies".')

    def __repr__(self):
        return 'ESTPPolicyOptions()'

    # ------------------------------ Options Policy ------------------------------
    # Quarantine Manager (Windows & Linux only):
    #   Quarantine folder (e.g. "<SYSTEM_DRIVE>\Quarantine")
    def get_quarantine_folder(self):
        """
        Get the Quarantine folder
        """
        return self.get_setting_value('QuarantineManager', 'szQuarantineDirectory')

    def set_quarantine_folder(self, folder):
        """
        Set the Quarantine folder, e.g. "<SYSTEM_DRIVE>\\Quarantine" (see
        check_quarantine_folder)
        """
        check_quarantine_folder(folder)
        return self.set_setting_value('QuarantineManager', 'szQuarantineDirectory', folder)

    quarantine_folder = property(get_quarantine_folder, set_quarantine_folder)

    #   Specify the maximum number of days to keep quarantine data (Windows only)
    def get_quarantine_age(self):
        """
        Get the maximum number of days to keep quarantine data
        """
        value = self.get_setting_value('QuarantineManager', 'dwQuarantineAge')
        return int(value) if value is not None else None

    def set_quarantine_age(self, int_days):
        """
        Set the maximum number of days to keep quarantine data: 1-999, or 0
        to keep it (the console stores 0 when the option is unchecked)
        """
        if str(int_days).strip() != '0':
            int_days = check_int('Maximum number of days to keep quarantine data', int_days, 1, 999)
        return self.set_setting_value('QuarantineManager', 'dwQuarantineAge', str(int_days))

    quarantine_age = property(get_quarantine_age, set_quarantine_age)

    # ------------------------------ Options Policy ------------------------------
    # Detection Exclusion (Windows only):
    #   Columns: Detection Name or Hash, Description
    def get_detection_exclusions(self):
        """
        Get the Detection Exclusion list: a list of [detection name or hash,
        description].
        """
        rows = self.get_indexed_table('SpyExclItems', 'dwSpywareExclCount',
                                      ['SpywareItem', 'DescriptionSpywareItem'])
        if rows is None:
            return None
        return [[row['SpywareItem'], row['DescriptionSpywareItem'] or ''] for row in rows]

    def set_detection_exclusions(self, table):
        """
        Set the Detection Exclusion list from a list of [detection name or
        hash, description].
        """
        names = set()
        for name, description in table:
            check_length('Detection name or hash', name, 259, required=True)
            check_length('Description', description, 256)
            if name.strip() in names:
                raise ValueError('Duplicate detection exclusion: {!r}'.format(name))
            names.add(name.strip())
        rows = [{'SpywareItem': name, 'DescriptionSpywareItem': description}
                for name, description in table]
        return self.set_indexed_table('SpyExclItems', 'dwSpywareExclCount',
                                      ['SpywareItem', 'DescriptionSpywareItem'], rows)

    detection_exclusions = property(get_detection_exclusions, set_detection_exclusions)

    #   Overwrite exclusions configured on the client
    def get_overwrite_detection_exclusions(self):
        """
        Get Overwrite exclusions configured on the client
        """
        return self.get_setting_value('General', 'overwriteClientDetectionExclusions')

    def set_overwrite_detection_exclusions(self, mode):
        """
        Set Overwrite exclusions configured on the client
        """
        return self.set_setting_value('General', 'overwriteClientDetectionExclusions', mode)

    overwrite_detection_exclusions = property(get_overwrite_detection_exclusions,
                                              set_overwrite_detection_exclusions)

    # ------------------------------ Options Policy ------------------------------
    # Potentially Unwanted Program Detections (Windows only):
    #   Columns: File name, Description - stored as "file name:description"
    def get_pup_detections(self):
        """
        Get the user-defined unwanted programs: a list of [file name, description].
        """
        values = self.get_indexed_list('DetectionItems', 'dwDetectionItemCount',
                                       'UserDefinedDetection_{}')
        if values is None:
            return None
        return [value.split(':', 1) if ':' in value else [value, ''] for value in values]

    def set_pup_detections(self, table):
        """
        Set the user-defined unwanted programs from a list of [file name, description].
        """
        for name, description in table:
            check_length('File name', name.strip(), 259, required=True)
            if any(char in name for char in '/\\*?"|<>:'):
                raise ValueError('Invalid unwanted program file name (none of / \\ * ? " | < > :): '
                                 '{!r}'.format(name))
            check_length('Description', description, 256)
        values = ['{}:{}'.format(name, description) for name, description in table]
        return self.set_indexed_list('DetectionItems', 'dwDetectionItemCount',
                                     'UserDefinedDetection_{}', values)

    pup_detections = property(get_pup_detections, set_pup_detections)

    # ------------------------------ Options Policy ------------------------------
    # Proactive Data Analysis (Windows & Linux only):
    #   Send anonymous diagnostic and usage data to Trellix: Trellix GTI feedback
    def get_gti_feedback(self):
        """
        Get Trellix GTI feedback
        """
        return self.get_setting_value('DataAnalysis', 'bGTIFeedback')

    def set_gti_feedback(self, mode):
        """
        Set Trellix GTI feedback
        """
        return self.set_setting_value('DataAnalysis', 'bGTIFeedback', mode)

    gti_feedback = property(get_gti_feedback, set_gti_feedback)

    #   Send anonymous diagnostic and usage data to Trellix: Safety Pulse (Windows only)
    def get_safety_pulse(self):
        """
        Get Safety Pulse
        """
        return self.get_setting_value('DataAnalysis', 'bSafetyPulse')

    def set_safety_pulse(self, mode):
        """
        Set Safety Pulse
        """
        return self.set_setting_value('DataAnalysis', 'bSafetyPulse', mode)

    safety_pulse = property(get_safety_pulse, set_safety_pulse)

    #   Check AMCore Content before installation: AMCore Content Reputation (Windows only)
    def get_amcore_reputation(self):
        """
        Get AMCore Content Reputation
        """
        return self.get_setting_value('DataAnalysis', 'bDATReputation')

    def set_amcore_reputation(self, mode):
        """
        Set AMCore Content Reputation
        """
        return self.set_setting_value('DataAnalysis', 'bDATReputation', mode)

    amcore_reputation = property(get_amcore_reputation, set_amcore_reputation)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        check = self.md_check
        sections = []
        age = self.get_quarantine_age()
        sections.append(('Quarantine Manager (Windows & Linux only)', self.md_settings([
            ['Quarantine folder', self.get_quarantine_folder()],
            ['Specify the maximum number of days to keep quarantine data (Windows only)',
             None if age is None else ('Yes ({} days)'.format(age) if age > 0 else 'No')]])))
        text = self.md_table(['Detection Name or Hash', 'Description'],
                             self.get_detection_exclusions() or [], numbered=True)
        text += '\n' + self.md_settings([
            ['Overwrite exclusions configured on the client',
             check(self.get_overwrite_detection_exclusions())]])
        sections.append(('Detection Exclusion (Windows only)', text))
        text = 'Specify custom potentially unwanted programs to detect. The Description ' \
               'appears as the detection name when a detection occurs.\n\n'
        text += self.md_table(['File name', 'Description'], self.get_pup_detections() or [],
                              numbered=True)
        sections.append(('Potentially Unwanted Program Detections (Windows only)', text))
        sections.append(('Proactive Data Analysis (Windows & Linux only)', self.md_settings([
            ['Send anonymous diagnostic and usage data to Trellix: Trellix GTI feedback',
             check(self.get_gti_feedback())],
            ['Send anonymous diagnostic and usage data to Trellix: Safety Pulse (Windows only)',
             check(self.get_safety_pulse())],
            ['Check AMCore Content before installation: AMCore Content Reputation '
             '(Windows only)', check(self.get_amcore_reputation())]])))
        return sections
