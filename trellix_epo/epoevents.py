# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOEvents, the event operations of EPOClient
(epo.events): read the rows of a query on the Audit Log, threat events,
client events or Compliance History as objects (see the events module), and
purge these logs (and the Server Task Log) by age or by query, with a dry
run first.

    events = epo.events.read('Threat Events in the Last 2 Weeks')     # [ThreatEvent...]
    epo.events.purge_threat_events(6, 'months', dry_run=True)          # rows it would delete
    epo.events.purge_audit_log(6, 'months')                            # rows deleted

The library doesn't rebuild the queries of the console (use the queries
Trellix provides, or a squid.Query): it reads their rows and purges.

Every purge takes an explicit age (1 or more) and unit: without an age,
core.purgeAuditLog and tasklog.purge purge everything.

Server behaviours (checked on ePO 5.10 Update 7 with a 50 years age):
core.purgeAuditLog and tasklog.purge answer true or false (false: nothing
purged), commonevent.purgeEvents and purgeProductEvents the number of rows
purged, epo.purgeComplianceHistory true even when nothing is purged; the
units are not case sensitive; epo.purgeComplianceHistory takes "age"
(the help writes queryId="age=<n>", refused: "Command line is missing age
parameter"). Every Web API call writes Audit Log entries: the rows deleted
are counted on the rows older than the age. dry_run=True counts
the rows the purge would delete (the rows older than the age, by the date
of DATE_COLUMNS: months of 30 days and years of 365 days, so an estimate
near the limit) or the rows of the query, and deletes nothing; a real purge
returns the number of rows deleted (counted before and after).

The Trellix best practices (Product Guide 5.10, "Create a purge events
server task"): purge the Audit Log, the client events and the Server Task
Log after 6 months, and the threat events every day (per your retention
policy), with a server task (Menu > Automation > Server Tasks) rather than
by hand.
"""

from .events import events_from_rows
from .squid import Query, older_than

# Units of the purge commands.
UNITS = ('days', 'weeks', 'months', 'years')
DAYS = {'days': 1, 'weeks': 7, 'months': 30, 'years': 365}

# The logs: table, date column of the age, a column with few values to
# count the rows (SQUID can't count without a group).
LOGS = {
    'audit': ('OrionAuditLog', 'StartTime', 'Success'),
    'threat': ('EPOEvents', 'ReceivedUTC', 'ThreatSeverity'),
    'client': ('EPOProductEvents', 'ReceivedUTC', 'TVDSeverity'),
    'compliance': ('EpoComplianceHistory', 'TheTimestamp', 'TaskName'),
    'tasklog': ('OrionTaskLogTask', 'StartDate', 'Status'),
}


def check_age(age, unit):
    """
    Checks the age of a purge: a whole number of 1 or more, in days, weeks,
    months or years.

    Valid / invalid:

    >>> check_age(6, 'Months')
    (6, 'months')
    >>> check_age(0, 'days')
    Traceback (most recent call last):
    ...
    ValueError: The purge age must be a whole number of 1 or more: 0.
    """
    if isinstance(age, bool) or not isinstance(age, int) or age < 1:
        raise ValueError('The purge age must be a whole number of 1 or more: {!r}.'.format(age))
    unit = str(unit).lower()
    if unit not in UNITS:
        raise ValueError('The purge unit must be one of {}: {!r}.'.format(', '.join(UNITS), unit))
    return age, unit


class EPOEvents():
    """
    The event and purge operations of an EPOClient (epo.events).
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo
        self._descriptions = None

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPOEvents of {!r}>'.format(self.epo)

    # ------------------------------ Reading ------------------------------
    def read(self, query, database=None):
        """
        Runs a query on the Audit Log, threat events, client events or
        Compliance History and returns its rows as objects (AuditEntry,
        ThreatEvent, ClientEvent, ComplianceRecord); for a query without the
        event description column, the descriptions are added from
        descriptions().

        Example: epo.events.read('Threat Events in the Last 2 Weeks').

        :param: query: A saved query (name, id or SavedQuery) or a squid.Query.
        :raise: ValueError: A summary query (counts), or another table.
        """
        items = events_from_rows(self.epo.queries.run(query, database))
        if any(getattr(item, 'event_id', None) is not None and item.description is None
               for item in items):
            descriptions = self.descriptions()
            for item in items:
                if getattr(item, 'event_id', None) is not None and item.description is None:
                    item.description = descriptions.get(item.event_id)
        return items

    def descriptions(self, language='0409'):
        """
        Returns the event descriptions: {event ID: description} (the
        EPOEventFilterDesc table, read once; the server can't filter it by
        language: all the languages are read, about 12000 rows).

        Example: epo.events.descriptions()[1095] gives 'Access Protection
        rule violation detected and NOT blocked'.

        :param: language: The language code (0409 English, 040c French...).
        """
        if self._descriptions is None:
            self._descriptions = self.epo.query(Query('EPOEventFilterDesc').select(
                'EventId', 'Name', 'Language'))
        return {row['EPOEventFilterDesc.EventId']: row['EPOEventFilterDesc.Name']
                for row in self._descriptions if row['EPOEventFilterDesc.Language'] == language}

    # ------------------------------ Purges ------------------------------
    def count_older(self, log, age, unit):
        """
        Returns the number of rows of a log older than the age (by its date
        column, months of 30 days and years of 365 days).

        Example: epo.events.count_older('audit', 6, 'months').

        :param: log: audit, threat, client, compliance or tasklog.
        """
        age, unit = check_age(age, unit)
        table, date, group = LOGS[log]
        rows = self.epo.query(Query(table).select(group).where(
            older_than(date, days=age * DAYS[unit])).group(group).count())
        return sum(row['count'] for row in rows)

    def _purge(self, log, command, age, unit, dry_run, params):
        """
        Purges a log by age: counts the rows older than the age, then (not
        dry_run) runs the command and returns the rows deleted.
        """
        age, unit = check_age(age, unit)
        before = self.count_older(log, age, unit)
        if dry_run:
            return before
        self.epo.call(command, **params)
        # The rows older than the age, not the totals: every Web API call
        # writes Audit Log entries (the total grows during the purge).
        return before - self.count_older(log, age, unit)

    def _purge_by_query(self, log, command, query, dry_run):
        """
        Purges the rows of a saved table query of the log: checks the query
        targets the table and gives events (not counts), then (not dry_run)
        runs the command; returns the rows of the query before the purge.
        """
        table = LOGS[log][0]
        saved = self.epo.queries.require(query)
        if saved.target != table:
            raise ValueError('Query {} is on {}, not {}.'.format(saved.name, saved.target, table))
        rows = len(self.read(saved))
        if not dry_run:
            self.epo.call(command, queryId=saved.id, purgeType=2)
        return rows

    def purge_audit_log(self, age, unit, dry_run=False):
        """
        Purges the Audit Log entries older than the age (core.purgeAuditLog,
        Purge of the Audit Log page).

        Example: epo.events.purge_audit_log(6, 'months', dry_run=True).

        :return: The rows the purge deletes (dry_run) or deleted.
        """
        age, unit = check_age(age, unit)
        return self._purge('audit', 'core.purgeAuditLog', age, unit, dry_run,
                           {'age': age, 'unit': unit})

    def purge_task_log(self, age, unit, dry_run=False):
        """
        Purges the Server Task Log entries older than the age (tasklog.purge).

        Example: epo.events.purge_task_log(6, 'months').
        """
        age, unit = check_age(age, unit)
        return self._purge('tasklog', 'tasklog.purge', age, unit, dry_run,
                           {'age': age, 'unit': unit})

    def purge_threat_events(self, age=None, unit=None, query=None, dry_run=False):
        """
        Purges threat events older than the age, or the events of a saved
        table query on threat events (commonevent.purgeEvents, Purge of the
        Threat Event Log).

        Example: epo.events.purge_threat_events(3, 'months', dry_run=True).

        :param: query: A saved query (name, id or SavedQuery) instead of age.
        """
        return self._events('threat', 'commonevent.purgeEvents', age, unit, query, dry_run)

    def purge_client_events(self, age=None, unit=None, query=None, dry_run=False):
        """
        Purges client events older than the age, or the events of a saved
        table query on client events (commonevent.purgeProductEvents).

        Example: epo.events.purge_client_events(6, 'months').
        """
        return self._events('client', 'commonevent.purgeProductEvents', age, unit, query, dry_run)

    def _events(self, log, command, age, unit, query, dry_run):
        """
        Purges threat or client events by age (purgeType 1) or by query
        (purgeType 2).
        """
        if (query is None) == (age is None):
            raise ValueError('Give an age (with its unit) or a query.')
        if query is not None:
            return self._purge_by_query(log, command, query, dry_run)
        age, unit = check_age(age, unit)
        return self._purge(log, command, age, unit, dry_run,
                           {'age': age, 'unit': unit.capitalize(), 'purgeType': 1})

    def purge_compliance_history(self, age, unit, dry_run=False):
        """
        Purges the Compliance History records older than the age
        (epo.purgeComplianceHistory).

        Example: epo.events.purge_compliance_history(1, 'years').
        """
        age, unit = check_age(age, unit)
        return self._purge('compliance', 'epo.purgeComplianceHistory', age, unit, dry_run,
                           {'age': age, 'unit': unit.capitalize()})
