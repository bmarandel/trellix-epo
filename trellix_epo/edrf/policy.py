# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EDRFPolicy, the base class of the Trellix EDR with
Forensics policy classes (ePO product XCLIENT_META, extension 50.3.0;
policies of the extension 2.1.2 are read too).

Storage learnt from test policies changed in the ePO 5.10 console and from
the extension code (see the module documentation of each policy class for
the details):

- One Section per policy, named after the policy type (General, Streaming,
  Detection, Investigation, Remediation); settings named after the client
  configuration keys (e.g. "mxa/process/cpu_limit").
- Checkboxes are stored as 'true' / 'false' (the classes read and write
  '1' / '0', like the other classes of the library).
- Settings missing from a policy (older extension versions) are shown by the
  console with the extension defaults and added at the next save; the
  classes do the same (DEFAULTS).
- Text lists (exclusions) are semicolon separated. Depending on the policy
  type and the field, the console doubles the backslashes (Windows paths)
  and the ePO server escapes the double quotes (\\" instead of ") before
  saving; the classes decode and encode them the same way, so that a list
  reads ['C:\\\\Tools\\\\app.exe'] and is stored as the console stores it.
- The ePO server keeps 3072 characters per setting (longer values are
  truncated, even by an import). Since the extension 50.3 the exclusion
  lists and the containment page settings (CHUNKED) are split by the
  server: "name" holds the first 3072 characters, "name_1", "name_2"... the
  next ones, each part ending at the last semicolon that fits (or cut at
  3072 characters when there is none); their double quotes are no longer
  escaped. The classes read and write the parts the same way and refuse
  any other value longer than 3072 characters once stored.
- Passwords (uninstall, uncontainment) are hashed with a random salt and
  the S3 bucket keys are encrypted by the ePO server: the library never
  defines them (see the README).
"""

import re

from ..policies import Policy
from ..validators import MAX_SETTING_LENGTH

CHECK, NUMBER, SELECT, TEXT, LIST = 'check', 'number', 'select', 'text', 'list'



class EDRFPolicy(Policy):
    """
    Base class of the Trellix EDR with Forensics policies.

    Each subclass describes its settings in OPTIONS, a dict
    {name: (setting, console label, kind, *parameters)}:

    - CHECK: a checkbox, read and written as '1' / '0'.
    - NUMBER: (min, max[, factor]): a number checked as in the console;
      factor 60 = shown in minutes by the console, stored in seconds.
    - SELECT: ({value: console label}): a drop-down list.
    - TEXT: (max length): a text (max length = maxlength of the console
      field).
    - LIST: (windows): a semicolon separated list (a text area), read and
      written as a Python list; windows=True for Windows paths. A list
      holds MAX_LIST_LENGTH characters at most (maxlength of the console
      text areas).

    Use get_option() / set_option() (and get_list() / set_list() /
    add_to_list() / remove_from_list() for the lists).
    """
    MD_PRODUCT = 'Trellix EDR with Forensics'
    TYPE = ''
    OPTIONS = {}
    DEFAULTS = {}
    # Encoding of the text settings, as done by the console and the ePO server.
    ESCAPE_QUOTES = False          # " stored as \"
    DOUBLE_BACKSLASHES = ()        # settings whose backslashes are doubled
    LIST_SEPARATORS = r'[;\n]'     # separators found when reading a list
    MAX_LIST_LENGTH = 200000       # maxlength of the console text areas
    # Settings split in 3072 character parts by the ePO server (extension 50.3).
    CHUNKED = ()
    # The console page reads the settings with JSON.parse('...'): a double
    # quote stored unescaped (CHUNKED settings) stops it from opening the policy.
    QUOTES_BREAK_CHUNKS = False
    # Checkboxes that need a secret (defined in the console only): name -> setting.
    SECRETS = {}

    def __init__(self, policy_from_edrfpolicies=None):
        super(EDRFPolicy, self).__init__(policy_from_edrfpolicies)
        if policy_from_edrfpolicies is not None and self.get_type() != self.TYPE:
            raise ValueError('Wrong policy! Policy type must be "{}".'.format(self.TYPE))

    # ------------------------------ Storage helpers ------------------------------
    def _decode(self, setting, value):
        if value is None:
            return None
        if self.ESCAPE_QUOTES and (setting not in self.CHUNKED or self.QUOTES_BREAK_CHUNKS):
            value = value.replace('\\"', '"')
        if setting in self.DOUBLE_BACKSLASHES:
            value = value.replace('\\\\', '\\')
        return value

    def _encode(self, setting, value):
        value = str(value)
        if setting in self.DOUBLE_BACKSLASHES:
            value = value.replace('\\', '\\\\')
        if setting in self.CHUNKED:
            if self.QUOTES_BREAK_CHUNKS and '"' in value:
                raise ValueError('" is not supported in {} (the console cannot open the policy '
                                 'any more): {!r}'.format(setting, value))
        elif self.ESCAPE_QUOTES:
            value = value.replace('"', '\\"')
        if setting not in self.CHUNKED and len(value) > MAX_SETTING_LENGTH:
            raise ValueError('{}: {} characters max once stored (the ePO server truncates the '
                             'rest).'.format(setting, MAX_SETTING_LENGTH))
        return value

    def _get_stored(self, setting):
        """
        Returns the stored value of a setting, its parts joined (CHUNKED
        settings), or None if the setting is missing.
        """
        value = self.get_setting_value(self.TYPE, setting)
        if value is None or setting not in self.CHUNKED:
            return value
        index = 1
        while True:
            part = self.get_setting_value(self.TYPE, '{}_{}'.format(setting, index))
            if part is None:
                return value
            value += part
            index += 1

    def _set_stored(self, setting, value):
        """
        Set the stored value of a setting, split in parts as the ePO server
        does for the CHUNKED settings.
        """
        if setting not in self.CHUNKED:
            return self.set_setting_value(self.TYPE, setting, value, True)
        section = self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(self.TYPE))
        index = 1
        while True:
            part = section.find('Setting[@name="{}_{}"]'.format(setting, index))
            if part is None:
                break
            section.remove(part)
            index += 1
        parts = self.split_chunks(value)
        result = self.set_setting_value(self.TYPE, setting, parts[0], True)
        for index, part in enumerate(parts[1:], 1):
            self.set_setting_value(self.TYPE, '{}_{}'.format(setting, index), part, True)
        return result

    @staticmethod
    def split_chunks(value, size=MAX_SETTING_LENGTH):
        """
        Split a value as the ePO server does (PolicyCreationHelper of the
        extension 50.3): parts of at most size characters, each one ending
        at the last semicolon that fits (cut at size characters if none).
        """
        parts = []
        while len(value) > size:
            index = value.rfind(';', 0, size) + 1 or size
            parts.append(value[:index])
            value = value[index:]
        return parts + [value]

    def _get(self, setting):
        """
        Returns the decoded value of a setting, or its console default if
        the setting is missing (None if there is no default).
        """
        value = self._get_stored(setting)
        if value is None:
            value = self.DEFAULTS.get(setting)
        return self._decode(setting, value)

    def _set(self, setting, value):
        """
        Set a setting (created if missing, as the console does).
        """
        return self._set_stored(setting, self._encode(setting, value))

    @staticmethod
    def _to_mode(value):
        return None if value is None else ('1' if value == 'true' else '0')

    @staticmethod
    def _from_mode(mode):
        if str(mode) in ('1', 'True', 'true'):
            return 'true'
        if str(mode) in ('0', 'False', 'false'):
            return 'false'
        raise ValueError('The state must be "1" or "0".')

    @staticmethod
    def check_bmp(value):
        """
        Raise ValueError if a value has characters out of the Unicode Basic
        Multilingual Plane (refused by the console in the exclusion lists).
        """
        if any(ord(char) > 0xFFFF for char in str(value)):
            raise ValueError('Make sure that only BMP characters are used in folders and '
                             'filenames: {!r}'.format(value))

    # ------------------------------ Generic options ------------------------------
    @classmethod
    def options(cls, kind=None):
        """
        Returns the options as a dict {name: console label}, all of them or
        those of one kind (CHECK, NUMBER, SELECT, TEXT or LIST).
        """
        return {name: spec[1] for name, spec in cls.OPTIONS.items()
                if kind is None or spec[2] == kind}

    def get_option(self, name):
        """
        Get an option: '1' / '0' for a checkbox, an int for a number (in the
        console unit), the stored value for a drop-down list or a text, a
        list for a list. See options().
        """
        setting, _, kind = self.OPTIONS[name][:3]
        if kind == LIST:
            return self.get_list(name)
        value = self._get(setting)
        if kind == CHECK:
            return self._to_mode(value)
        if kind == NUMBER:
            if value in (None, ''):
                return None
            factor = self.OPTIONS[name][5] if len(self.OPTIONS[name]) > 5 else 1
            return int(value) // factor
        return value

    def set_option(self, name, value):
        """
        Set an option, checked as in the console (see get_option).
        """
        setting, label, kind = self.OPTIONS[name][:3]
        if kind == LIST:
            return self.set_list(name, value)
        if kind == CHECK:
            mode = self._from_mode(value)
            secret = self.SECRETS.get(name)
            if mode == 'true' and secret and not self.get_setting_value(self.TYPE, secret):
                raise ValueError('{}: the secret it needs can only be defined in the ePO console.'
                                 .format(label))
            return self._set(setting, mode)
        if kind == NUMBER:
            low, high = self.OPTIONS[name][3:5]
            factor = self.OPTIONS[name][5] if len(self.OPTIONS[name]) > 5 else 1
            if not re.fullmatch(r'\d+', str(value)) or not low <= int(value) <= high:
                raise ValueError('{}: enter a number between {} and {}.'.format(label, low, high))
            return self._set(setting, int(value) * factor)
        if kind == SELECT:
            if str(value) not in self.OPTIONS[name][3]:
                raise ValueError('{} must be within {}.'.format(label, list(self.OPTIONS[name][3])))
            return self._set(setting, value)
        if len(str(value)) > self.OPTIONS[name][3]:
            raise ValueError('{}: {} characters max.'.format(label, self.OPTIONS[name][3]))
        self.check_bmp(value)
        return self._set(setting, value)

    # ------------------------------ Lists ------------------------------
    def get_list(self, name):
        """
        Get a list option (e.g. exclusions) as a list of strings.
        """
        setting, _, kind = self.OPTIONS[name][:3]
        if kind != LIST:
            raise ValueError('"{}" is not a list option.'.format(name))
        value = self._get(setting) or ''
        return [item.strip() for item in re.split(self.LIST_SEPARATORS, value) if item.strip()]

    def set_list(self, name, items):
        """
        Set a list option, checked as in the console (semicolon separated,
        MAX_LIST_LENGTH characters max, BMP characters only; Windows paths
        cannot contain a double backslash).
        """
        setting, label, kind = self.OPTIONS[name][:3]
        if kind != LIST:
            raise ValueError('"{}" is not a list option.'.format(name))
        items = [str(item).strip() for item in items]
        for item in items:
            self.check_bmp(item)
            if not item or ';' in item or '\n' in item:
                raise ValueError('{}: an item cannot be empty or contain ";": {!r}'.format(
                    label, item))
            if self.OPTIONS[name][3] and '\\\\' in item:
                raise ValueError('Windows path or process exclusions can not contain \\\\: {!r}'
                                 .format(item))
        value = ';'.join(items)
        # Keep the trailing semicolon of the stored lists that have one (extension defaults).
        if items and (self._get_stored(setting) or '').endswith(';'):
            value += ';'
        if len(value) > self.MAX_LIST_LENGTH:
            raise ValueError('{}: {} characters max.'.format(label, self.MAX_LIST_LENGTH))
        return self._set(setting, value)

    def add_to_list(self, name, items):
        """
        Add items to a list option (items already in the list are skipped).
        """
        current = self.get_list(name)
        return self.set_list(name, current + [item for item in items if item not in current])

    def remove_from_list(self, name, items):
        """
        Remove items from a list option.
        """
        return self.set_list(name, [item for item in self.get_list(name) if item not in items])

    # ------------------------------ Markdown export ------------------------------
    def md_option(self, name):
        """
        Returns a [console label, value] row for md_settings().
        """
        _, label, kind = self.OPTIONS[name][:3]
        value = self.get_option(name)
        if kind == CHECK:
            value = self.md_check(value)
        elif kind == SELECT:
            value = self.OPTIONS[name][3].get(value, value)
        elif kind == LIST:
            value = '; '.join(self.get_list(name))
        return [label, value]

    def md_rows(self, names):
        """
        Returns the md_settings() rows of several options.
        """
        return [self.md_option(name) for name in names]

    def md_list(self, name):
        """
        Returns a list option as a numbered table (or *None*).
        """
        return self.md_table([self.OPTIONS[name][1]], [[item] for item in self.get_list(name)],
                             numbered=True)
