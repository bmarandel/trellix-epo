"""
Server tasks and Server Task Log (trellix_epo.servertasks,
trellix_epo.eposervertasks), without a server.

Fixtures of the ePO 5.10 Update 7 lab: server_tasks.json is
scheduler.listAllServerTasks (30 tasks), server_task.json
scheduler.getServerTask "Update Main Repository", task_log.json the 20
latest rows of OrionTaskLogTask, task_history.json, task_subtasks.json and
task_messages.json the tasklog.* answers for the lab runs (36354 TIE Server
Monitoring completed, 36355 Download Software Product List cancelled, 36357
Synchronize Shared Policies run while disabled), running_tasks.json
scheduler.listRunningServerTasks during 36355, task_sources.json
tasklog.listTaskSources.
"""

import doctest
import json
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import servertasks as module
from trellix_epo import eposervertasks as operations
from trellix_epo import (EPOClient, ServerTask, TaskLogEntry, server_tasks_to_markdown,
                         task_log_to_markdown)
from trellix_epo.epo import EPOError
from trellix_epo.servertasks import COMPLETED, ENDED, IN_PROGRESS, PENDING_TERMINATION

FIXTURES = Path(__file__).parent / 'fixtures'


def fixture(name):
    """
    Returns the text of a fixture.
    """
    return (FIXTURES / name).read_text(encoding='utf-8')


def ok(text):
    """
    Returns the answer of the server for a JSON text.
    """
    return 'OK:\r\n' + text


def row(log_id, status, name='Download Software Product List', duration=38623):
    """
    Returns an OrionTaskLogTask row.
    """
    return ok(json.dumps([{'OrionTaskLogTask.Id': log_id, 'OrionTaskLogTask.Name': name,
                           'OrionTaskLogTask.StartDate': '2026-10-17T16:23:24+02:00',
                           'OrionTaskLogTask.EndDate': '2026-10-17T16:24:02+02:00',
                           'OrionTaskLogTask.UserName': 'admin', 'OrionTaskLogTask.Status': status,
                           'OrionTaskLogTask.TaskSource': 'scheduler',
                           'OrionTaskLogTask.Duration': duration}]))


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
        self.server_tasks._sleep = lambda seconds: None

    def _send(self, request):
        """
        Records the request and returns the next answer.
        """
        command = urllib.parse.urlsplit(request.full_url).path.split('/remote/')[1]
        self.requests.append((command, dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))))
        return self.answers.pop(0)


def test_docstring_examples():
    result = doctest.testmod(module)
    assert result.attempted >= 20 and result.failed == 0
    assert doctest.testmod(operations).failed == 0


def test_list_and_get():
    epo = FakeServer(ok(fixture('server_tasks.json')), ok(fixture('server_task.json')),
                     'Error 0 :\r\nThere are no tasks named "Claude Nope"')
    tasks = epo.server_tasks.list()
    assert len(tasks) == 30
    update = [task for task in tasks if task.id == 27][0]
    assert update.enabled and update.next_run.isoformat() == '2026-10-17T19:10:00+02:00'
    assert update.end_date is None
    disabled = [task for task in tasks if not task.enabled]
    assert disabled and all(task.next_run is None for task in disabled)
    # getServerTask gives "true" as a text.
    task = epo.server_tasks.get('Update Main Repository')
    assert task.enabled is True and task.id == 27
    assert epo.server_tasks.get('Claude Nope') is None
    assert epo.requests[1] == ('scheduler.getServerTask', {'taskName': 'Update Main Repository'})


def test_enable_and_disable():
    disabled = json.dumps(dict(json.loads(fixture('server_task.json')), enabled='false',
                               nextRunTime='None'))
    epo = FakeServer(ok(fixture('server_task.json')), ok('true'), ok(disabled))
    task = epo.server_tasks.disable('Update Main Repository')
    assert not task.enabled and task.next_run is None
    assert epo.requests[1] == ('scheduler.updateServerTask', {'taskId': '27', 'status': 'disabled'})
    # The status is not the one set after the call.
    epo = FakeServer(ok(fixture('server_task.json')), ok('true'), ok(fixture('server_task.json')))
    with pytest.raises(EPOError, match='is not disabled after the call'):
        epo.server_tasks.disable(27)
    epo = FakeServer('Error 0 :\r\nThere are no tasks named "Nope"')
    with pytest.raises(ValueError, match='Unknown server task: Nope'):
        epo.server_tasks.enable('Nope')


def test_run_and_wait():
    messages, subtasks = fixture('task_messages.json'), fixture('task_subtasks.json')
    epo = FakeServer(ok(fixture('server_task.json')), ok('36355'),
                     row(36355, IN_PROGRESS), row(36355, PENDING_TERMINATION), row(36355, ENDED),
                     row(36355, ENDED), ok(subtasks), ok(messages))
    entry = epo.server_tasks.run('Update Main Repository', wait=True, interval=1)
    assert epo.requests[1] == ('scheduler.runServerTask', {'taskId': '27'})
    assert entry.id == 36355 and entry.status_label == 'Ended' and entry.finished
    assert not entry.succeeded and entry.duration == 38623
    assert [item.name for item in entry.subtasks] == ['Update Product Compatibility List']
    assert entry.subtasks[0].status == COMPLETED and entry.subtasks[0].id is None
    assert entry.messages[0].text == 'Download Software Product List'
    # Without wait: the entry just started.
    epo = FakeServer(ok(fixture('server_task.json')), ok('36356'), row(36356, IN_PROGRESS))
    assert epo.server_tasks.run(27).status_label == 'In Progress'


def test_wait_timeout():
    epo = FakeServer(*[row(36355, IN_PROGRESS)] * 4)
    with pytest.raises(TimeoutError, match='Task log 36355 is still In Progress after 3 s'):
        epo.server_tasks.wait(36355, timeout=3, interval=1)


def test_cancel():
    epo = FakeServer(ok('true'), row(36355, PENDING_TERMINATION))
    assert epo.server_tasks.cancel(36355).status_label == 'Pending Termination'
    assert epo.requests[0] == ('scheduler.cancelServerTask', {'taskLogId': '36355'})
    epo = FakeServer('Error 0 :\r\nNo running task with taskLogId "36,355" was found')
    with pytest.raises(EPOError, match='No running task'):
        epo.server_tasks.cancel(36355)


def test_running():
    tasks = FakeServer(ok(fixture('running_tasks.json'))).server_tasks.running()
    assert [(task.log_id, task.name, task.progress) for task in tasks] == [
        (36355, 'Download Software Product List', 0)]
    assert tasks[0].start_date.isoformat() == '2026-10-17T16:23:24'


def test_log_latest_first():
    epo = FakeServer(ok(fixture('task_log.json')))
    entries = epo.server_tasks.log(limit=20)
    assert len(entries) == 20
    starts = [entry.start_date for entry in entries]
    assert starts == sorted(starts, reverse=True)
    command, fields = epo.requests[0]
    assert command == 'core.executeQuery' and fields['target'] == 'OrionTaskLogTask'
    assert fields['select'].startswith('(select (top 20) OrionTaskLogTask.Id ')
    assert fields['order'] == '(order (desc OrionTaskLogTask.StartDate))' and 'where' not in fields
    statuses = {entry.status_label for entry in entries}
    assert statuses <= {'Completed', 'Failed', 'Ended'}


def test_log_filters():
    epo = FakeServer(ok('[]'), ok('[]'))
    epo.server_tasks.log(task='Update Main Repository', source='scheduler', status='Failed',
                         days=7, limit=5)
    assert epo.requests[0][1]['where'] == (
        '(and (eq OrionTaskLogTask.Name "Update Main Repository") '
        '(eq OrionTaskLogTask.TaskSource "scheduler") (eq OrionTaskLogTask.Status 1) '
        '(newerThan OrionTaskLogTask.StartDate 604800000))')
    epo.server_tasks.log(status=2)
    assert epo.requests[1][1]['where'] == '(eq OrionTaskLogTask.Status 2)'
    with pytest.raises(ValueError, match='Unknown status'):
        epo.server_tasks.log(status='Paused')


def test_history_labels():
    entries = [TaskLogEntry.from_json(item) for item in json.loads(fixture('task_history.json'))]
    assert {entry.id: entry.status_label for entry in entries} == {
        36354: 'Completed', 36355: 'Ended', 36357: 'Completed'}
    assert entries[0].duration_text == 'Less than a minute'


def test_sources():
    sources = FakeServer(ok(fixture('task_sources.json'))).server_tasks.sources()
    assert sources['scheduler'] == 'Server Task' and len(sources) == 16


def test_markdown():
    tasks = [ServerTask.from_json(item) for item in json.loads(fixture('server_tasks.json'))]
    text = server_tasks_to_markdown(tasks)
    assert text.count('\n') == 3 + 30
    assert '| Update Main Repository | Enabled | 2026-10-17 19:10 | This default task' in text
    entries = FakeServer(ok(fixture('task_log.json'))).server_tasks.log(limit=20)
    table = task_log_to_markdown(entries)
    assert table.splitlines()[2] == ('| Start Date | Name | Status | Duration | Source | '
                                     'User Name | Task Log ID |')
    entry = TaskLogEntry(36355, 'Download Software Product List', status=ENDED,
                         messages=[], subtasks=[TaskLogEntry.from_json(item) for item in
                                                json.loads(fixture('task_subtasks.json'))])
    assert '## Subtasks' in entry.to_markdown()
