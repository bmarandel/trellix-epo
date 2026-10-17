"""
Audit Log, events and purges (trellix_epo.events, trellix_epo.epoevents),
without a server.

Fixtures of the ePO 5.10 Update 7 lab: events_threat.json (10 latest threat
events with every column and the event description), events_audit.json (10
Audit Log entries of the admin user), events_client.json (10 client events
with their description), events_compliance.json (5 Compliance History
records), events_compliance_summary.json (rows of the saved query "Trellix
Agent Compliance History": aggregated columns).
"""

import doctest
import json
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import events as module
from trellix_epo import epoevents as operations
from trellix_epo import (EPOClient, AuditEntry, ThreatEvent, ClientEvent, events_from_rows,
                         audit_to_markdown, threat_events_to_markdown, client_events_to_markdown)
from trellix_epo.epoevents import check_age

FIXTURES = Path(__file__).parent / 'fixtures'


def fixture(name):
    """
    Returns the rows of a fixture.
    """
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))


def ok(value):
    """
    Returns the answer of the server for a value (JSON encoded).
    """
    return 'OK:\r\n' + (value if isinstance(value, str) else json.dumps(value))


def counts(*numbers):
    """
    Returns the answer of a grouped count query: one group per number.
    """
    return ok([{'X.group': index, 'count': number} for index, number in enumerate(numbers)])


class FakeServer(EPOClient):
    """
    EPOClient whose server is a list of answers; the requests are kept in
    self.requests as (command, form fields).
    """

    def __init__(self, *answers):
        """
        :param: answers: The raw answers of the server, in order.
        """
        super(FakeServer, self).__init__('https://epo.example.com:8443', 'admin', 'secret')
        self.answers = list(answers)
        self.requests = []

    def _send(self, request):
        """
        Records the request and returns the next answer.
        """
        command = urllib.parse.urlsplit(request.full_url).path.split('/remote/')[1]
        self.requests.append((command, dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))))
        return self.answers.pop(0)


def test_docstring_examples():
    assert doctest.testmod(module).attempted >= 18 and doctest.testmod(module).failed == 0
    assert doctest.testmod(operations).failed == 0


def test_threat_events():
    events = events_from_rows(fixture('events_threat.json'))
    assert len(events) == 10 and all(isinstance(event, ThreatEvent) for event in events)
    event = events[0]
    assert event.description and event.event_id and event.target_host
    assert event.severity_label in module.THREAT_SEVERITIES.values()
    assert event.received.tzinfo is not None and event.generated <= event.received
    assert event.category_label == module.EVENT_CATEGORIES.get(event.category, event.category)
    text = threat_events_to_markdown(events)
    assert text.splitlines()[2] == ('| Event Generated Time | Threat Target Host Name | '
                                    'Detecting Product Name | Event ID | Event Description | '
                                    'Threat Severity | Action Taken | Threat Name |')
    assert text.count('\n') == 3 + 10


def test_audit_entries():
    entries = events_from_rows(fixture('events_audit.json'))
    assert all(isinstance(entry, AuditEntry) and entry.user == 'admin' for entry in entries)
    entry = entries[0]
    assert entry.priority_label in ('High', 'Medium', 'Low') and entry.success_label
    assert repr(entry).startswith('<AuditEntry 20')
    text = audit_to_markdown(entries)
    assert text.splitlines()[2] == ('| Start Time | User Name | Priority | Action | Status | '
                                    'Details |')


def test_client_events():
    events = events_from_rows(fixture('events_client.json'))
    assert all(isinstance(event, ClientEvent) for event in events)
    assert {event.severity_label for event in events} <= set(module.CLIENT_SEVERITIES.values())
    assert events[0].description
    assert '| Event Generated Time | Host Name | Event ID | Event Description | Severity |' in \
        client_events_to_markdown(events)


def test_compliance_and_summaries():
    records = events_from_rows(fixture('events_compliance.json'))
    assert records[0].items == records[0].compliant + records[0].noncompliant
    # A saved summary query gives aggregated columns: not events.
    with pytest.raises(ValueError, match='summary query'):
        events_from_rows(fixture('events_compliance_summary.json'))
    with pytest.raises(ValueError, match='summary query'):
        events_from_rows([{'EPOEvents.ThreatSeverity': 3, 'count': 12}])
    with pytest.raises(ValueError, match='Not the rows of one of the tables'):
        events_from_rows([{'EPOLeafNode.NodeName': 'PC01'}])
    assert events_from_rows([]) == []


def test_labels():
    assert ThreatEvent(severity=0).severity_label == 'Emergency'
    assert ThreatEvent(severity=9).severity_label == '9'
    assert ThreatEvent(action='jticlient.would.blocked').action_label == \
        'Adaptive Threat Protection Would Block'
    assert ThreatEvent(action='unknown.action').action_label == 'unknown.action'
    assert AuditEntry(priority=0).priority_label == '0'
    with pytest.raises(ValueError, match='Unknown attributes: color'):
        ThreatEvent(color='red')


def test_read_adds_the_descriptions():
    rows = [{key: value for key, value in row.items() if key != 'EPOEventFilterDesc.Name'}
            for row in fixture('events_threat.json')]
    descriptions = [{'EPOEventFilterDesc.EventId': row['EPOEvents.ThreatEventID'],
                     'EPOEventFilterDesc.Name': row['EPOEventFilterDesc.Name'],
                     'EPOEventFilterDesc.Language': language}
                    for row in fixture('events_threat.json') for language in ('0409', '040c')]
    epo = FakeServer(ok(rows), ok(descriptions))
    from trellix_epo import Query
    events = epo.events.read(Query('EPOEvents'))
    assert [event.description for event in events] == [
        row['EPOEventFilterDesc.Name'] for row in fixture('events_threat.json')]
    assert epo.requests[1][1]['target'] == 'EPOEventFilterDesc'


def test_check_age():
    assert check_age(6, 'Months') == (6, 'months')
    for age in (0, -1, 1.5, '6', None, True):
        with pytest.raises(ValueError, match='whole number of 1 or more'):
            check_age(age, 'days')
    with pytest.raises(ValueError, match='unit must be one of'):
        check_age(1, 'hours')


def test_dry_run_counts_only():
    epo = FakeServer(counts(30000, 10116))
    assert epo.events.purge_audit_log(6, 'months', dry_run=True) == 40116
    command, fields = epo.requests[0]
    assert command == 'core.executeQuery' and fields['target'] == 'OrionAuditLog'
    assert fields['where'] == '(olderThan OrionAuditLog.StartTime 15552000000)'
    assert fields['group'] == '(group OrionAuditLog.Success)'
    assert len(epo.requests) == 1


def test_purge_returns_the_rows_deleted():
    # Rows older than the age, the purge (answers of the lab), the rows older
    # than the age again: not the totals, which the Audit Log entries of the
    # calls themselves change.
    epo = FakeServer(counts(9788), ok('9788'), counts(0))
    assert epo.events.purge_threat_events(6, 'months') == 9788
    assert epo.requests[1] == ('commonevent.purgeEvents', {
        'age': '6', 'unit': 'Months', 'purgeType': '1'})
    epo = FakeServer(counts(4542), ok('true'), counts(0))
    assert epo.events.purge_task_log(6, 'months') == 4542
    assert epo.requests[1] == ('tasklog.purge', {'age': '6', 'unit': 'months'})
    epo = FakeServer(counts(0), ok('false'), counts(0))
    assert epo.events.purge_audit_log(50, 'years') == 0
    epo = FakeServer(counts(50), ok('true'), counts(0))
    epo.events.purge_compliance_history(6, 'months')
    assert epo.requests[1] == ('epo.purgeComplianceHistory', {'age': '6', 'unit': 'Months'})


def test_purge_by_query():
    saved = [{'id': 300, 'name': 'Old detections', 'target': 'EPOEvents', 'groupName': 'Mine'},
             {'id': 41, 'name': 'Inactive Agents', 'target': 'EPOLeafNode', 'groupName': 'Agents'}]
    rows = fixture('events_threat.json')[:3]
    epo = FakeServer(ok(saved), ok(rows), ok('true'))
    assert epo.events.purge_threat_events(query='Old detections') == 3
    assert epo.requests[-1] == ('commonevent.purgeEvents', {'queryId': '300', 'purgeType': '2'})
    epo = FakeServer(ok(saved))
    with pytest.raises(ValueError, match='Query Inactive Agents is on EPOLeafNode, not EPOEvents'):
        epo.events.purge_threat_events(query='Inactive Agents')
    with pytest.raises(ValueError, match='Give an age'):
        epo.events.purge_client_events()
    with pytest.raises(ValueError, match='Give an age'):
        epo.events.purge_client_events(1, 'days', query='Old detections')
