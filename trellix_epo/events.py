# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the ePO Audit Log entries, threat events, client events
and compliance records as objects, without a server: one object per row of
the OrionAuditLog, EPOEvents, EPOProductEvents and EpoComplianceHistory
tables, as a query returns them (a saved query of Queries & Reports or a
squid.Query, see epo.queries), with the console labels of the values.

>>> event = ThreatEvent.from_row({'EPOEvents.ThreatEventID': 20720,
...     'EPOEvents.ThreatSeverity': 3, 'EPOEvents.TargetHostName': 'PC01',
...     'EPOEvents.ThreatActionTaken': 'execute.deny', 'EPOEvents.ThreatCategory': 'ac.app.block',
...     'EPOEventFilterDesc.Name': 'Execution Denied'})
>>> event, event.severity_label, event.action_label, event.category_label
(<ThreatEvent 20720 Execution Denied on PC01>, 'Error', 'Execute denied', 'Application Blocked')

The library doesn't rebuild the queries of the console: run the queries
Trellix provides (or yours) with epo.queries.run() and read their rows with
events_from_rows(). The purges are in the epoevents module (epo.events).

The labels of the values come from the console query builder (filter step,
ePO 5.10 Update 7 with ENS 26.8, Solidcore 8.4.5, ATP, TIE and EDR): the
Web API only gives the codes. The event descriptions are in the
EPOEventFilterDesc table (a query on EPOEvents or EPOProductEvents with the
column EPOEventFilterDesc.Name gives them in the language of the user).
"""

import datetime

from .policies import Policy

# Threat Severity of the threat events (EPOEvents.ThreatSeverity), syslog
# levels: the lower the number, the more severe (the console labels "lt"
# "Greater than" and "gt" "Less than" for this column).
THREAT_SEVERITIES = {0: 'Emergency', 1: 'Alert', 2: 'Critical', 3: 'Error', 4: 'Warning',
                     5: 'Notice', 6: 'Information', 7: 'Debug'}

# Severity of the client events (EPOProductEvents.TVDSeverity): another scale.
CLIENT_SEVERITIES = {0: 'Informational', 1: 'Warning', 2: 'Minor', 3: 'Major', 4: 'Critical'}

# Priority of the Audit Log entries (OrionAuditLog.Priority); 0 is used by
# the server without a console label.
AUDIT_PRIORITIES = {1: 'High', 2: 'Medium', 3: 'Low'}

# Action Taken of the threat events (EPOEvents.ThreatActionTaken).
ACTIONS = {
    'jticlient.allowed': 'Adaptive Threat Protection Allowed',
    'jticlient.blocked': 'Adaptive Threat Protection Blocked',
    'jticlient.repaired': 'Adaptive Threat Protection Cleaned',
    'jticlient.contain': 'Adaptive Threat Protection Contained',
    'jticlient.uncontain': 'Adaptive Threat Protection Released From Containment',
    'jticlient.would.allowed': 'Adaptive Threat Protection Would Allow',
    'jticlient.would.blocked': 'Adaptive Threat Protection Would Block',
    'jticlient.would.repaired': 'Adaptive Threat Protection Would Clean',
    'jticlient.would.contain': 'Adaptive Threat Protection Would Contain',
    'jticlient.would.uncontain': 'Adaptive Threat Protection Would Release From Containment',
    'IDS_ACTION_ADDED_REQ': 'Added requester', 'IDS_THREAT_ACTION_ALLOW': 'Allow',
    'IDS_ALERT_ACT_TAK_ALLOW': 'Allow access', 'IDS_ALERT_ACT_TAK_BLO': 'Block',
    'blocked': 'Blocked', 'IDS_ALERT_ACT_TAK_CLE': 'Clean', 'cleaned': 'Cleaned',
    'IDS_ACTION_CONTAINED': 'Contained', 'IDS_ALERT_ACT_TAK_CONT': 'Continue scanning',
    'IDS_ALERT_ACT_TAK_DEL': 'Delete', 'IDS_ALERT_ACT_TAK_WBD': 'Delete pending',
    'deleted': 'Deleted', 'IDS_ALERT_ACT_TAK_DEN': 'Deny access', 'deny execute': 'deny execute',
    'deny read': 'deny read', 'deny write': 'deny write', 'execute.deny': 'Execute denied',
    'IDS_ALERT_ACT_TAK_MOV': 'Move', 'moved': 'Moved', 'none': 'None',
    'IDS_THREAT_ACTN_OBSRVD': 'Observed', 'IDS_ALERT_ACT_TAK_PRO': 'Prompt user',
    'read.denied': 'Read denied', 'IDS_ACTION_UNCONTAINED': 'Released from containment',
    'removed': 'Removed', 'IDS_ACTION_REM_REQ': 'Removed requester',
    'IDS_THREAT_ACTION_WARN': 'Warned', 'IDS_ACTION_WOULD_BLOCK': 'Would block',
    'IDS_ACTION_WOULD_CLEAN': 'Would clean', 'IDS_ACTION_WOULD_DELETE': 'Would delete',
    'execute.woulddeny': 'Would deny executing', 'write.denied': 'Write denied',
}

# Event Category of the threat events (EPOEvents.ThreatCategory): the code
# is a path (ac.app.block is under ac.app, under ac); hip.file is shown as
# "Access Protection" by the console.
EVENT_CATEGORIES = {
    'ac': 'Application Control', 'ac.app': 'Application Monitoring',
    'ac.app.block': 'Application Blocked', 'ac.pkg': 'Package Monitoring',
    'ac.pkg.block': 'Package Blocked', 'av': 'Malware', 'av.detect': 'Malware detected',
    'av.detect.heuristics': 'Malware detected using heuristics',
    'av.promptTimeout': 'Prompt - Timed Out', 'av.promptUnavailable': 'Prompt - Unavailable',
    'av.promptUser': 'Prompt - User Response', 'av.reputation': 'Reputation',
    'cc': 'Change Control', 'cc.app': 'Application Change Monitoring',
    'cc.file': 'File Monitoring', 'cc.file.block': 'File Access Blocked',
    'cc.registry': 'Registry Monitoring', 'cc.registry.block': 'Registry Access Blocked',
    'cc.user': 'User Change Monitoring', 'fw': 'Firewall', 'fw.app.hook': 'Firewall application hook',
    'fw.detect': 'Firewall detected', 'fw.intrusion': 'Intrusion detected', 'hip': 'Host intrusion',
    'hip.app': 'Application monitoring', 'hip.app.block': 'Application block',
    'hip.bo': 'Host intrusion buffer overflow', 'hip.file': 'Access Protection',
    'hip.process': "'Process' class or access", 'hip.registry': "'Registry' class or access",
    'mail': 'Email', 'mail.filter': 'Email filtered', 'mail.phish': 'Email phishing detected',
    'mail.spam': 'Email spam', 'mvedr.update.update': 'Update', 'nip': 'Network intrusion',
    'nip.detect': 'Network intrusion detected', 'ops': 'Operational',
    'ops.clilock': 'Client interface lockout', 'ops.fw.detect': 'Traffic detected',
    'ops.fw.timedgroup': 'Timed groups', 'ops.fw.traffic': 'Traffic allowed',
    'ops.informational.event': 'Informational event', 'ops.install': 'Install',
    'ops.quar.restore': 'Quarantined item restored', 'ops.scan': 'Scan',
    'ops.scan.cancel': 'Scan canceled', 'ops.scan.end': 'Scan ended', 'ops.scan.error': 'Scan failed',
    'ops.scan.start': 'Scan started', 'ops.scor': 'Solidcore Operations',
    'ops.scor.error': 'Solidcore Operational Errors', 'ops.service': 'Service',
    'ops.service.cancel': 'Service canceled', 'ops.service.end': 'Service ended',
    'ops.service.error': 'Service failed', 'ops.service.start': 'Service started',
    'ops.task': 'Task', 'ops.task.cancel': 'Task canceled', 'ops.task.deferred': 'Task deferred',
    'ops.task.end': 'Task ended', 'ops.task.error': 'Task failed', 'ops.task.start': 'Task started',
    'ops.uninstall': 'Uninstall', 'ops.update': 'Update', 'ops.update.cancel': 'Update canceled',
    'ops.update.end': 'Update ended', 'ops.update.error': 'Update failed',
    'ops.update.start': 'Update started', 'policy': 'Policy',
    'policy.quarantine': 'Policy quarantine', 'tiem.AccessProtection.info': 'Access Protection',
    'wp.detect.download': 'Malicious file download', 'wp.detect.url': 'Malicious site navigation',
}

# Column of the event description joined to the event tables.
DESCRIPTION = 'EPOEventFilterDesc.Name'


def _date(text):
    """
    Returns the datetime of a date of the Web API, or None.

    >>> _date('2026-10-17T23:18:29+02:00').hour, _date(None)
    (23, None)
    """
    return datetime.datetime.fromisoformat(text) if text else None


def _text(value):
    """
    Returns a value as Markdown table text: '' for None, the date as
    "YYYY-MM-DD hh:mm:ss".

    >>> _text(None), _text(_date('2026-10-17T23:18:29+02:00'))
    ('', '2026-10-17 23:18:29')
    """
    if value is None:
        return ''
    if isinstance(value, datetime.datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    return str(value)


class _Row():
    """
    Base of the row objects: COLUMNS maps the attributes to the columns of
    the table (TABLE), LABELS gives the console label of the attributes.
    """

    TABLE = ''
    COLUMNS = {}
    DATES = ()
    LABELS = {}

    def __init__(self, **values):
        """
        :param: values: The attributes (keys of COLUMNS).
        """
        unknown = set(values) - set(self.COLUMNS) - {'description'}
        if unknown:
            raise ValueError('Unknown attributes: {}.'.format(', '.join(sorted(unknown))))
        for attribute in self.COLUMNS:
            setattr(self, attribute, values.get(attribute))
        self.description = values.get('description')
        self.raw = {}

    @classmethod
    def from_row(cls, row):
        """
        Returns the object of a query row ({"Table.Column": value}); the
        columns missing from the row are None.
        """
        values = {attribute: row.get('{}.{}'.format(cls.TABLE, column))
                  for attribute, column in cls.COLUMNS.items()}
        for attribute in cls.DATES:
            values[attribute] = _date(values[attribute])
        values['description'] = row.get(DESCRIPTION)
        item = cls(**values)
        item.raw = row
        return item

    def value(self, attribute):
        """
        Returns an attribute as the console shows it (labels of the codes,
        dates as text).
        """
        label = getattr(self, attribute + '_label', None)
        return _text(label if label is not None else getattr(self, attribute))


def _table(items, columns, title):
    """
    Returns row objects as a Markdown table of the attributes given, with
    the console labels.
    """
    if not items:
        return '# {}\n\n*None*\n'.format(Policy.md_heading(title))
    labels = type(items[0]).LABELS
    lines = ['# ' + Policy.md_heading(title), '',
             '| ' + ' | '.join(labels.get(column, column) for column in columns) + ' |',
             '|' + '---|' * len(columns)]
    for item in items:
        lines.append('| ' + ' | '.join(Policy.md_escape(item.value(column))
                                       for column in columns) + ' |')
    return '\n'.join(lines)


class AuditEntry(_Row):
    """
    An entry of the Audit Log (Menu > User Management > Audit Log): who did
    what, when, and whether it succeeded.

    >>> AuditEntry.from_row({'OrionAuditLog.UserName': 'admin', 'OrionAuditLog.Priority': 3,
    ...     'OrionAuditLog.CmdName': 'Logon Attempt', 'OrionAuditLog.Success': True,
    ...     'OrionAuditLog.StartTime': '2026-10-17T23:18:29+02:00'})
    <AuditEntry 2026-10-17 23:18:29 admin: Logon Attempt (Successful)>
    """

    TABLE = 'OrionAuditLog'
    COLUMNS = {'user': 'UserName', 'priority': 'Priority', 'action': 'CmdName',
               'details': 'Message', 'success': 'Success', 'start': 'StartTime',
               'end': 'EndTime'}
    DATES = ('start', 'end')
    LABELS = {'user': 'User Name', 'priority': 'Priority', 'action': 'Action',
              'details': 'Details', 'success': 'Status', 'start': 'Start Time',
              'end': 'Completion Time'}

    def __repr__(self):
        """
        Shows the start, the user, the action and the status.
        """
        return '<AuditEntry {} {}: {} ({})>'.format(_text(self.start), self.user, self.action,
                                                   self.success_label)

    @property
    def priority_label(self):
        """
        The Priority as the console shows it (High, Medium, Low).

        >>> AuditEntry(priority=1).priority_label
        'High'
        """
        return AUDIT_PRIORITIES.get(self.priority, None if self.priority is None
                                    else str(self.priority))

    @property
    def success_label(self):
        """
        The Status as the console shows it (Successful or Failed).

        >>> AuditEntry(success=False).success_label
        'Failed'
        """
        return None if self.success is None else 'Successful' if self.success else 'Failed'


def audit_to_markdown(entries, title='Audit Log',
                      columns=('start', 'user', 'priority', 'action', 'success', 'details')):
    """
    Returns Audit Log entries as a Markdown table (console labels).

    >>> print(audit_to_markdown([AuditEntry(user='admin', action='Logon Attempt', success=True)],
    ...                         columns=('user', 'action', 'success')))
    # Audit Log
    <BLANKLINE>
    | User Name | Action | Status |
    |---|---|---|
    | admin | Logon Attempt | Successful |
    """
    return _table(entries, columns, title)


class ThreatEvent(_Row):
    """
    A threat event (Menu > Reporting > Threat Event Log): what product
    detected what on which system, the event description, severity,
    category and action taken.

    >>> ThreatEvent(event_id=1095, target_host='PC01').event_id
    1095
    """

    TABLE = 'EPOEvents'
    COLUMNS = {
        'server': 'ServerID', 'received': 'ReceivedUTC', 'generated': 'DetectedUTC',
        'event_time': 'EventTimeLocal', 'agent_guid': 'AgentGUID', 'product_id': 'Analyzer',
        'product': 'AnalyzerName', 'product_version': 'AnalyzerVersion',
        'product_host': 'AnalyzerHostName', 'product_ip': 'AnalyzerIPV6',
        'product_mac': 'AnalyzerMAC', 'dat_version': 'AnalyzerDATVersion',
        'engine_version': 'AnalyzerEngineVersion', 'source_host': 'SourceHostName',
        'source_ip': 'SourceIPV6', 'source_mac': 'SourceMAC', 'source_user': 'SourceUserName',
        'source_process': 'SourceProcessName', 'source_url': 'SourceURL',
        'target_host': 'TargetHostName', 'target_ip': 'TargetIPV6', 'target_mac': 'TargetMAC',
        'target_user': 'TargetUserName', 'target_port': 'TargetPort',
        'target_protocol': 'TargetProtocol', 'target_process': 'TargetProcessName',
        'target_file': 'TargetFileName', 'category': 'ThreatCategory', 'event_id': 'ThreatEventID',
        'severity': 'ThreatSeverity', 'threat_name': 'ThreatName', 'threat_type': 'ThreatType',
        'action': 'ThreatActionTaken', 'handled': 'ThreatHandled',
        'detection_method': 'AnalyzerDetectionMethod'}
    DATES = ('received', 'generated', 'event_time')
    LABELS = {
        'server': 'Server ID', 'received': 'Event Received Time', 'generated': 'Event Generated Time',
        'event_time': 'Preferred Event Time', 'agent_guid': 'Trellix Agent GUID',
        'product_id': 'Detecting Prod ID (deprecated)', 'product': 'Detecting Product Name',
        'product_version': 'Detecting Product Version',
        'product_host': 'Detecting Product Host Name', 'product_ip': 'Detecting Product IP address',
        'product_mac': 'Detecting Product MAC Address', 'dat_version': 'DAT Version',
        'engine_version': 'Engine Version', 'source_host': 'Threat Source Host Name',
        'source_ip': 'Threat Source IP address', 'source_mac': 'Threat Source MAC Address',
        'source_user': 'Threat Source User Name', 'source_process': 'Threat Source Process Name',
        'source_url': 'Threat Source URL', 'target_host': 'Threat Target Host Name',
        'target_ip': 'Threat Target IP address', 'target_mac': 'Threat Target MAC Address',
        'target_user': 'Threat Target User Name', 'target_port': 'Threat Target Port Number',
        'target_protocol': 'Threat Target Network Protocol',
        'target_process': 'Threat Target Process Name', 'target_file': 'Threat Target File Path',
        'category': 'Event Category', 'event_id': 'Event ID', 'severity': 'Threat Severity',
        'threat_name': 'Threat Name', 'threat_type': 'Threat Type', 'action': 'Action Taken',
        'handled': 'Threat Handled', 'detection_method': 'Analyzer Detection Method',
        'description': 'Event Description'}

    def __repr__(self):
        """
        Shows the event ID, its description and the target system.
        """
        return '<ThreatEvent {} {}on {}>'.format(
            self.event_id, self.description + ' ' if self.description else '', self.target_host)

    @property
    def severity_label(self):
        """
        The Threat Severity as the console shows it (Emergency ... Debug).

        >>> ThreatEvent(severity=2).severity_label
        'Critical'
        """
        return THREAT_SEVERITIES.get(self.severity, None if self.severity is None
                                     else str(self.severity))

    @property
    def action_label(self):
        """
        The Action Taken as the console shows it.

        >>> ThreatEvent(action='IDS_ACTION_WOULD_BLOCK').action_label
        'Would block'
        """
        return ACTIONS.get(self.action, self.action)

    @property
    def category_label(self):
        """
        The Event Category as the console shows it.

        >>> ThreatEvent(category='hip.file').category_label
        'Access Protection'
        """
        return EVENT_CATEGORIES.get(self.category, self.category)


def threat_events_to_markdown(events, title='Threat Events',
                              columns=('generated', 'target_host', 'product', 'event_id',
                                       'description', 'severity', 'action', 'threat_name')):
    """
    Returns threat events as a Markdown table (console labels).

    >>> print(threat_events_to_markdown([ThreatEvent(event_id=20720, severity=3,
    ...     description='Execution Denied')], columns=('event_id', 'description', 'severity')))
    # Threat Events
    <BLANKLINE>
    | Event ID | Event Description | Threat Severity |
    |---|---|---|
    | 20720 | Execution Denied | Error |
    """
    return _table(events, columns, title)


class ClientEvent(_Row):
    """
    A client event (Client Events queries): updates and deployments of the
    products on the systems, with their result.

    >>> ClientEvent(event_id=2402, severity=4, host='PC01')
    <ClientEvent 2402 on PC01>
    """

    TABLE = 'EPOProductEvents'
    COLUMNS = {'agent_guid': 'AgentGUID', 'event_id': 'TVDEventID', 'severity': 'TVDSeverity',
               'received': 'ReceivedUTC', 'generated': 'DetectedUTC', 'host': 'HostName',
               'user': 'UserName', 'ip': 'IPV6', 'version': 'version', 'hotfix': 'SPHotFix',
               'extra_dats': 'ExtraDATNames', 'event_type': 'Type', 'error': 'Error',
               'locale': 'Locale', 'site': 'SiteName', 'initiator_id': 'InitiatorID',
               'initiator_type': 'InitiatorType'}
    DATES = ('received', 'generated')
    LABELS = {'agent_guid': 'Trellix Agent GUID', 'event_id': 'Event ID', 'severity': 'Severity',
              'received': 'Event Received Time', 'generated': 'Event Generated Time',
              'host': 'Host Name', 'user': 'User Name', 'ip': 'IP address', 'version': 'Version',
              'hotfix': 'SP hotfix', 'extra_dats': 'Extra DAT Names', 'event_type': 'Event Type',
              'error': 'Error Code', 'locale': 'Locale', 'site': 'Site Name',
              'initiator_id': 'Initiator ID', 'initiator_type': 'Initiator Type',
              'description': 'Event Description'}

    def __repr__(self):
        """
        Shows the event ID, its description and the system.
        """
        return '<ClientEvent {} {}on {}>'.format(
            self.event_id, self.description + ' ' if self.description else '', self.host)

    @property
    def severity_label(self):
        """
        The Severity as the console shows it (Informational ... Critical).

        >>> ClientEvent(severity=4).severity_label
        'Critical'
        """
        return CLIENT_SEVERITIES.get(self.severity, None if self.severity is None
                                     else str(self.severity))


def client_events_to_markdown(events, title='Client Events',
                              columns=('generated', 'host', 'event_id', 'description', 'severity',
                                       'event_type', 'version', 'error')):
    """
    Returns client events as a Markdown table (console labels).

    >>> print(client_events_to_markdown([ClientEvent(event_id=2401, severity=0)],
    ...                                 columns=('event_id', 'severity')))
    # Client Events
    <BLANKLINE>
    | Event ID | Severity |
    |---|---|
    | 2401 | Informational |
    """
    return _table(events, columns, title)


class ComplianceRecord(_Row):
    """
    A record of the Compliance History (counts of compliant and
    noncompliant items found by a compliance query run by a server task).

    >>> ComplianceRecord(query='Trellix Agent Compliance Summary', compliant=2, items=2)
    <ComplianceRecord Trellix Agent Compliance Summary: 2/2 compliant>
    """

    TABLE = 'EpoComplianceHistory'
    COLUMNS = {'query': 'ChartName', 'task': 'TaskName', 'items': 'CountComputers',
               'noncompliant': 'CountNonCompliant', 'percent_noncompliant': 'PercentNonCompliant',
               'percent_compliant': 'PercentCompliant', 'time': 'TheTimestamp',
               'compliant': 'CountCompliant'}
    DATES = ('time',)
    LABELS = {'query': 'Query Used to Generate Compliance', 'task':
              'Server Task Used to Generate Compliance', 'items': 'Count Of Items',
              'noncompliant': 'Count Of Noncompliant Items',
              'percent_noncompliant': 'Percent Noncompliant',
              'percent_compliant': 'Percent Compliant', 'time': 'Compliance Check Time',
              'compliant': 'Count Of Compliant Items'}

    def __repr__(self):
        """
        Shows the query and the compliant items.
        """
        return '<ComplianceRecord {}: {}/{} compliant>'.format(self.query, self.compliant,
                                                              self.items)


# Row classes by table, for events_from_rows().
ROW_CLASSES = {cls.TABLE: cls for cls in (AuditEntry, ThreatEvent, ClientEvent, ComplianceRecord)}


def events_from_rows(rows):
    """
    Returns the objects of the rows of a query on the Audit Log, threat
    events, client events or Compliance History (the table is read from the
    column names), e.g. epo.queries.run('Threat Events in the Last 2 Weeks').
    The rows of a summary query (a "count" column, or aggregated columns as
    "EpoComplianceHistory.PercentCompliant.avg") are not events: ValueError.

    >>> events_from_rows([{'OrionAuditLog.UserName': 'admin',
    ...                    'OrionAuditLog.CmdName': 'Logon Attempt'}])[0].action
    'Logon Attempt'

    >>> events_from_rows([{'OrionAuditLog.UserName': 'admin', 'OrionAuditLog.Success': False}])
    [<AuditEntry  admin: None (Failed)>]
    >>> events_from_rows([])
    []
    """
    if not rows:
        return []
    # A summary query gives a "count" column or aggregated columns
    # ("Table.Column.avg", "Table.Column.week"...).
    if 'count' in rows[0] or any(key.count('.') > 1 for key in rows[0]):
        raise ValueError('The rows of a summary query (counts, aggregates) are not events.')
    tables = {key.split('.', 1)[0] for key in rows[0] if '.' in key} - {'EPOEventFilterDesc'}
    found = [ROW_CLASSES[table] for table in tables if table in ROW_CLASSES]
    if len(found) != 1:
        raise ValueError('Not the rows of one of the tables {}: {}.'.format(
            ', '.join(ROW_CLASSES), ', '.join(sorted(tables))))
    return [found[0].from_row(row) for row in rows]
