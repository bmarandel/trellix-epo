# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESWCPolicy, the common part of the Endpoint
Security Web Control policies, and RatingActions.

Storage learnt from test policies changed in the ePO 5.10 console:

- Each section has a szPolicyStamp setting that the console sets to the
  save time (milliseconds since 1970) when it saves the section; the
  library does the same for the sections it changes.
- Rating actions (Red / Yellow / Unrated sites or file downloads) are one
  number: a flag per rating, Allow = 1, Warn = 2, Block = 4, the Yellow
  flag in bits 0-2, the Red flag in bits 3-5 and the Unrated flag in bits
  6-8 (e.g. 98 = Red Block, Yellow Warn, Unrated Allow).
"""

import time

from ...policies import Policy


class RatingActions():
    """
    The actions of the Red, Yellow and Unrated ratings (console selects
    Allow / Warn / Block): ALLOW '0', WARN '1' or BLOCK '2'.
    """
    ALLOW, WARN, BLOCK = '0', '1', '2'
    LABELS = {ALLOW: 'Allow', WARN: 'Warn', BLOCK: 'Block'}
    __FLAGS = {ALLOW: 1, WARN: 2, BLOCK: 4}
    __SHIFTS = {'yellow': 0, 'red': 3, 'unrated': 6}

    def __init__(self, red, yellow, unrated):
        for action in (red, yellow, unrated):
            if str(action) not in self.LABELS:
                raise ValueError('A rating action must be "0" (Allow), "1" (Warn) or "2" (Block).')
        self.red, self.yellow, self.unrated = str(red), str(yellow), str(unrated)

    def __repr__(self):
        return 'RatingActions(red={!r}, yellow={!r}, unrated={!r})'.format(
            self.red, self.yellow, self.unrated)

    def __eq__(self, other):
        return isinstance(other, RatingActions) and self.to_value() == other.to_value()

    @classmethod
    def from_value(cls, value):
        """
        Decode the stored number (e.g. '98').
        """
        number = int(value)
        actions = {}
        for rating, shift in cls.__SHIFTS.items():
            flag = (number >> shift) & 7
            actions[rating] = next((action for action, bit in cls.__FLAGS.items()
                                    if bit == flag), cls.ALLOW)
        return cls(**actions)

    def to_value(self):
        """
        Encode the actions as stored by the console.
        """
        return str(sum(self.__FLAGS[getattr(self, rating)] << shift
                       for rating, shift in self.__SHIFTS.items()))

    def labels(self):
        """
        Returns the console labels [Red, Yellow, Unrated].
        """
        return [self.LABELS[self.red], self.LABELS[self.yellow], self.LABELS[self.unrated]]


class ESWCPolicy(Policy):
    """
    Common part of the Endpoint Security Web Control policy classes.
    """
    TYPE = ''
    MD_PRODUCT = 'Endpoint Security Web Control'

    def __init__(self, policy_from_eswcpolicies=None):
        super(ESWCPolicy, self).__init__(policy_from_eswcpolicies)
        if policy_from_eswcpolicies is not None and self.get_type() != self.TYPE:
            raise ValueError('Wrong policy! Policy type must be "{}".'.format(self.TYPE))

    def __repr__(self):
        return '{}()'.format(type(self).__name__)

    def _section(self, section):
        return self.root.find('./EPOPolicySettings/Section[@name="{}"]'.format(section))

    def _get(self, section, setting):
        return self.get_setting_value(section, setting)

    def _stamp(self, section):
        """
        Set szPolicyStamp of a section to the current time, as the console
        does when it saves the section.
        """
        if self.get_setting_value(section, 'szPolicyStamp') is not None:
            self.set_setting_value(section, 'szPolicyStamp', str(int(time.time() * 1000)))

    def _set(self, section, setting, value, force=False):
        success = self.set_setting_value(section, setting, str(value), force)
        if success:
            self._stamp(section)
        return success

    def _set_checkbox(self, section, setting, mode):
        if str(mode) not in ['0', '1']:
            raise ValueError('The state must be "1" or "0".')
        return self._set(section, setting, mode)

    def _get_list(self, section, count, template):
        return self.get_indexed_list(section, count, template) or []

    def _set_list(self, section, count, template, values):
        success = self.set_indexed_list(section, count, template, [str(v) for v in values])
        if success:
            self._stamp(section)
        return success

    def _get_rating(self, section, setting):
        value = self._get(section, setting)
        return RatingActions.from_value(value) if value else None

    def _set_rating(self, section, setting, actions):
        if not isinstance(actions, RatingActions):
            raise ValueError('Rating actions must be a RatingActions object.')
        return self._set(section, setting, actions.to_value())

    def _md_rating(self, actions):
        """
        Returns the Red / Yellow / Unrated table of rating actions.
        """
        if actions is None:
            return '*None*\n'
        return self.md_table(['Red', 'Yellow', 'Unrated'], [actions.labels()])
