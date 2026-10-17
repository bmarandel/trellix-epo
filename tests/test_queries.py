"""
SQUID queries and saved queries (trellix_epo.squid, trellix_epo.epoqueries),
without a server.

Fixtures of the ePO 5.10 Update 7 lab: saved_queries.json is
core.listQueries (361 queries), query_inactive_agents.json and
query_inactive_agents_verbose.txt the run of the saved query 41 "Inactive
Agents" (JSON and :output=verbose), query_databases.json core.listDatabases.
"""

import doctest
import json
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import squid as module
from trellix_epo import epoqueries as operations
from trellix_epo import EPOClient
from trellix_epo.squid import (Query, Condition, Logic, SavedQuery, and_, contains, eq, is_blank, ne,
                               newer_than, not_, older_than, or_, rows_to_markdown,
                               saved_queries_to_markdown, starts_with)

FIXTURES = Path(__file__).parent / 'fixtures'
SAVED = (FIXTURES / 'saved_queries.json').read_text(encoding='utf-8')
INACTIVE = (FIXTURES / 'query_inactive_agents.json').read_text(encoding='utf-8')
VERBOSE = (FIXTURES / 'query_inactive_agents_verbose.txt').read_text(encoding='utf-8')
DATABASES = (FIXTURES / 'query_databases.json').read_text(encoding='utf-8')


def ok(text):
    """
    Returns the answer of the server for a text.
    """
    return 'OK:\r\n' + text


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
        Records the request (with the :output of the URL) and returns the next answer.
        """
        url = urllib.parse.urlsplit(request.full_url)
        fields = dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))
        fields.update(urllib.parse.parse_qsl(url.query))
        self.requests.append((url.path.split('/remote/')[1], fields))
        return self.answers.pop(0)


def test_docstring_examples():
    result = doctest.testmod(module)
    assert result.attempted >= 30 and result.failed == 0
    assert doctest.testmod(operations).failed == 0


def test_query_builder():
    query = (Query('EPOLeafNode').select('NodeName', 'EPOComputerProperties.OSType')
             .where(eq('ManagedState', 1), or_(contains('EPOComputerProperties.OSType', 'Server'),
                                               starts_with('NodeName', 'W')))
             .where(not_(is_blank('EPOComputerProperties.UserProperty1')))
             .order('NodeName').order('LastUpdate', desc=True).top(5).join('EPOProductProperties'))
    assert query.params() == {
        'target': 'EPOLeafNode',
        'select': '(select (top 5) EPOLeafNode.NodeName EPOComputerProperties.OSType)',
        'where': '(and (eq EPOLeafNode.ManagedState 1) (or (contains EPOComputerProperties.OSType '
                 '"Server") (startsWith EPOLeafNode.NodeName "W")) (not (isBlank '
                 'EPOComputerProperties.UserProperty1)))',
        'order': '(order (asc EPOLeafNode.NodeName) (desc EPOLeafNode.LastUpdate))',
        'joinTables': 'EPOProductProperties'}
    assert Query('EPOLeafNode').params() == {'target': 'EPOLeafNode'}
    assert Query('TieServerSchema.certificate_rep_summary', database='TIE').params() == {
        'target': 'TieServerSchema.certificate_rep_summary', 'database': 'TIE'}
    assert Query('TieServerSchema.x').select('a').params()['select'] == '(select x.a)'


def test_conditions():
    assert ne('A.B', 'x"y').squid() == '(ne A.B "x\\"y")'
    assert newer_than('A.B', days=0.5).squid() == '(newerThan A.B 43200000)'
    assert eq('A.B', False).squid() == '(eq A.B 0)'
    assert Condition('hasTag', 'EPOLeafNode.AppliedTags', 7).squid() == \
        '(hasTag EPOLeafNode.AppliedTags 7)'
    with pytest.raises(ValueError, match='Give days or milliseconds'):
        older_than('A.B')
    with pytest.raises(ValueError, match='not takes one condition'):
        Logic('not', eq('A', 1), eq('B', 2))
    with pytest.raises(ValueError, match='and takes at least one condition'):
        and_()


def test_run_a_query():
    epo = FakeServer(ok('[{"EPOLeafNode.NodeName": "PC01"}]'))
    query = Query('EPOLeafNode').select('NodeName').where(eq('ManagedState', 1))
    assert epo.queries.run(query) == [{'EPOLeafNode.NodeName': 'PC01'}]
    assert epo.requests[0] == ('core.executeQuery', {
        'target': 'EPOLeafNode', 'select': '(select EPOLeafNode.NodeName)',
        'where': '(eq EPOLeafNode.ManagedState 1)', ':output': 'json'})
    # epo.query() takes a Query too.
    epo = FakeServer(ok('[]'))
    assert epo.query(query) == [] and epo.requests[0][1]['target'] == 'EPOLeafNode'


def test_saved_queries():
    epo = FakeServer(*[ok(SAVED)] * 4)
    queries = epo.queries.list()
    assert len(queries) == 361
    inactive = epo.queries.get('Inactive Agents')
    assert (inactive.id, inactive.group, inactive.target) == (41, 'Agent Management', 'EPOLeafNode')
    assert inactive.condition.startswith('(Last Communication Is not within the last 1 Months')
    assert len(epo.queries.list(group='agent management')) == 12
    assert {query.database_type for query in epo.queries.list('TIE')} >= {'TieServerSchema'}
    with pytest.raises(ValueError, match='Unknown query: Nope'):
        FakeServer(ok(SAVED)).queries.require('Nope')


def test_run_a_saved_query_and_labels():
    epo = FakeServer(ok(SAVED), ok(INACTIVE))
    rows = epo.queries.run('Inactive Agents')
    assert epo.requests[1] == ('core.executeQuery', {'queryId': '41', ':output': 'json'})
    assert [row['EPOLeafNode.NodeName'] for row in rows] == ['ubuntud01', 'W2022CORE']
    epo = FakeServer(ok(INACTIVE), ok(VERBOSE))
    labels = epo.queries.labels(SavedQuery(41, 'Inactive Agents'))
    assert labels == {'EPOLeafNode.NodeName': 'System Name',
                      'EPOComputerProperties.IPV6': 'IP address',
                      'EPOComputerProperties.UserName': 'User Name',
                      'EPOLeafNode.LastUpdate': 'Last Communication'}
    assert epo.requests[1][1][':output'] == 'verbose'
    text = rows_to_markdown(rows, labels, 'Inactive Agents')
    assert text.splitlines()[2] == '| System Name | IP address | User Name | Last Communication |'
    # A Query is read with (top 1) for its labels; no row gives no label.
    epo = FakeServer(ok('[]'), ok(''))
    assert epo.queries.labels(Query('EPOLeafNode').select('NodeName')) == {}
    assert epo.requests[0][1]['select'] == '(select (top 1) EPOLeafNode.NodeName)'


def test_databases_and_markdown():
    assert FakeServer(ok(DATABASES)).queries.databases() == {
        'ePO': '', 'TIE Server 192.168.100.21': 'TieServerSchema'}
    queries = [SavedQuery.from_json(item) for item in json.loads(SAVED)]
    text = saved_queries_to_markdown(queries)
    assert text.count('\n') == 3 + 361
    assert '| Agent Management | Inactive Agents | 41 | EPOLeafNode |' in text
    assert rows_to_markdown([], title='Empty').endswith('|---|')
