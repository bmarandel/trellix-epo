# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
Helpers of the Markdown export of the McAfee (Trellix) Agent policies.

The agent policies often store a setting twice: in the section read by the
ePO console form (e.g. AgentListenServer, AgentLogging, whose setting names
are the ids of the console fields) and in a "service" section (e.g.
HttpServerService, LoggerService). Both are equal in policies saved by the
console, but not always in imported ones: the value shown by the console
(checked on the ePO 5.10 lab, e.g. "Enable Relay Communication" unchecked
with AgentListenServer.IsRelayClientEnabled 0 and RelayService.EnableClient 1)
is the one of the console section, so it is read first.
"""

MD_PRODUCT = 'Trellix Agent'


def first_value(policy, *pairs):
    """
    Returns the value of the first (section, setting) pair found in the
    policy, None if none is.
    """
    for section, setting in pairs:
        value = policy.get_setting_value(section, setting)
        if value is not None:
            return value
    return None


def minutes(seconds):
    """
    Returns a number of seconds (string) as minutes, None if missing.
    """
    if seconds is None or seconds == '':
        return None
    value = int(seconds)
    return str(value // 60) if value % 60 == 0 else '{:g}'.format(value / 60)


def labelled(value, labels):
    """
    Returns the console label of a coded value (the value itself if unknown).
    """
    return None if value is None else labels.get(value, value)
