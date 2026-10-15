# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes EDRFPolicyDetection (Trellix EDR with
Forensics: Detection - Real-Time Indicator Detection) and
EDRFRegistryExclusion.

Storage learnt from test policies changed in the ePO 5.10 console
(extensions XCLIENT_META 2.1.2.270 and 50.3.0.900):

- "Update indicators every" is shown in minutes and stored in seconds
  (mxa/intel/rsrc/refresh, 60 when missing: the console adds 60 at the
  first save, although the default policy of the extension 50.3 says 1800);
  mxa/eventor/match_interval is not shown by the console.
- The exclusion lists are stored as typed (no backslash doubling, no quote
  escaping), the console replacing line breaks by "|".
- "Exclude Registry Keys" is a JSON document,
  mxa/eventor/registry_key_exclusion_filter =
  {"reg_key_filter":[{"hive":"LocalMachine","path":"SOFTWARE\\\\Vendor",
  "values":["Version","InstallPath"]}, ...]} (rows in the order they were
  added; empty in a new policy). The console fields accept 260 characters
  for the key path and for the value names (comma separated).
- Since the extension 50.3 the exclusion lists and the registry key
  exclusions are split in 3072 character parts by the ePO server (see
  EDRFPolicy).
"""

import json

from .policy import EDRFPolicy, CHECK, NUMBER, LIST


class EDRFRegistryExclusion():
    """
    A registry key excluded from Real-Time Indicator Detection.

    :param: hive: 'LocalMachine', 'CurrentControlSet', 'Users' or 'ClassesRoot'.
    :param: path: Key path (required), e.g. 'SOFTWARE\\Vendor\\Agent'.
    :param: values: Optional list of value names.
    """
    HIVES = ['LocalMachine', 'CurrentControlSet', 'Users', 'ClassesRoot']
    MAX_LENGTH = 260               # maxlength of the console fields

    def __init__(self, hive, path, values=None):
        self.hive = hive
        self.path = path
        self.values = list(values or [])

    def __repr__(self):
        return 'EDRFRegistryExclusion({!r}, {!r}, values={!r})'.format(
            self.hive, self.path, self.values)

    def __eq__(self, other):
        return isinstance(other, EDRFRegistryExclusion) and self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, item):
        values = item.get('values') or []
        if isinstance(values, str):
            values = [value.strip() for value in values.split(',') if value.strip()]
        return cls(item.get('hive', ''), item.get('path', ''), values)

    def to_dict(self):
        return {'hive': self.hive, 'path': self.path, 'values': list(self.values)}

    def check(self):
        """
        Raise ValueError if the console would refuse the exclusion.
        """
        if self.hive not in self.HIVES:
            raise ValueError('The hive must be within {}.'.format(self.HIVES))
        if not self.path:
            raise ValueError('A registry key exclusion needs a key path.')
        if len(self.path) > self.MAX_LENGTH or len(','.join(self.values)) > self.MAX_LENGTH:
            raise ValueError('Key path and value names: {} characters max each.'.format(
                self.MAX_LENGTH))
        EDRFPolicy.check_bmp(self.path)
        for value in self.values:
            if not value or ',' in value:
                raise ValueError('A value name cannot be empty or contain ",": {!r}'.format(value))


class EDRFPolicyDetection(EDRFPolicy):
    """
    The EDRFPolicyDetection class can be used to edit the Trellix EDR with
    Forensics policy: Detection.
    """
    MD_CATEGORY = 'Detection'
    TYPE = 'Detection'
    REGISTRY_SETTING = 'mxa/eventor/registry_key_exclusion_filter'

    OPTIONS = {
        'detection': ('mxa/container/Eventor/enabled', 'Enable Real-Time Indicator Detection',
                      CHECK),
        'update_interval': ('mxa/intel/rsrc/refresh', 'Update indicators every (minutes)', NUMBER,
                            1, 1440, 60),
        'udp_events': ('mxa/eventor/udp_send_events', 'Capture UDP Events', CHECK),
        'network_events': ('mxa/eventor/network_evts_enabled', 'Capture Network Connection Events',
                           CHECK),
        'dns_events': ('mxa/eventor/dns_evts_enabled', 'Capture DNS Events', CHECK),
        'url_events': ('mxa/eventor/url_evts_enabled', 'Capture URL Events', CHECK),
        'path_exclusions': ('mxa/eventor/excludedPaths',
                            'Exclude file(s) or folder(s) from Real-Time indicator Detection',
                            LIST, False),
        'process_exclusions': ('mxa/eventor/excludedProcessNames',
                               'Exclude process(es) by full path from Real-Time indicator '
                               'Detection', LIST, False),
    }
    DEFAULTS = {'mxa/intel/rsrc/refresh': '60', REGISTRY_SETTING: ''}
    LIST_SEPARATORS = r'[;|\n]'
    CHUNKED = ('mxa/eventor/excludedPaths', 'mxa/eventor/excludedProcessNames', REGISTRY_SETTING)

    # ------------------------------ Registry key exclusions ------------------------------
    def get_registry_exclusions(self):
        """
        Get the registry keys excluded from Real-Time indicator Detection
        (list of EDRFRegistryExclusion).
        """
        value = self._get(self.REGISTRY_SETTING)
        if not value:
            return []
        return [EDRFRegistryExclusion.from_dict(item)
                for item in json.loads(value).get('reg_key_filter', [])]

    def set_registry_exclusions(self, exclusions):
        """
        Set the registry keys excluded from Real-Time indicator Detection
        (list of EDRFRegistryExclusion).
        """
        for exclusion in exclusions:
            exclusion.check()
        return self._set(self.REGISTRY_SETTING, json.dumps(
            {'reg_key_filter': [exclusion.to_dict() for exclusion in exclusions]},
            separators=(',', ':'), ensure_ascii=False))

    registry_exclusions = property(get_registry_exclusions, set_registry_exclusions)

    def add_registry_exclusion(self, exclusion):
        """
        Add a registry key exclusion (Add button of the console).
        """
        return self.set_registry_exclusions(self.get_registry_exclusions() + [exclusion])

    def remove_registry_exclusion(self, hive, path):
        """
        Remove the registry key exclusions of a hive and a key path.
        """
        exclusions = self.get_registry_exclusions()
        kept = [item for item in exclusions if (item.hive, item.path) != (hive, path)]
        if len(kept) == len(exclusions):
            raise ValueError('No registry key exclusion {}\\{}.'.format(hive, path))
        return self.set_registry_exclusions(kept)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples
        (see Policy.to_markdown).
        """
        text = self.md_settings(self.md_rows(['detection', 'update_interval']))
        text += '\n### Events\n\n' + self.md_settings(self.md_rows(
            ['udp_events', 'network_events', 'dns_events', 'url_events']))
        text += '\n### Exclusions\n\n' + self.md_list('path_exclusions')
        text += '\n' + self.md_list('process_exclusions')
        text += '\nExclude Registry Keys from Real-Time indicator Detection:\n\n' + self.md_table(
            ['Key path', 'Optional Value(s)', 'Hive'],
            [[item.path, ', '.join(item.values), item.hive]
             for item in self.get_registry_exclusions()], numbered=True)
        return [('Real-Time Indicator Detection', text)]
