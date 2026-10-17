# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the ePO server tasks and the Server Task Log as
objects, without a server: ServerTask (scheduler.listAllServerTasks),
TaskLogEntry (a run of a task: tasklog.listTaskHistory, tasklog.listSubtasks
or the OrionTaskLogTask table), TaskMessage (tasklog.listMessages) and
RunningTask (scheduler.listRunningServerTasks).

>>> task = ServerTask.from_json({'id': 27, 'name': 'Update Main Repository',
...     'enabled': 'true', 'valid': True, 'startDate': '2024-09-11T00:00:01+02:00',
...     'endDate': 'None', 'nextRunTime': '2026-10-17T19:10:00+02:00'})
>>> task, task.enabled, task.end_date
(<ServerTask 27 Update Main Repository (enabled)>, True, None)
>>> entry = TaskLogEntry.from_row({'OrionTaskLogTask.Id': 36355,
...     'OrionTaskLogTask.Name': 'Download Software Product List',
...     'OrionTaskLogTask.Status': 2, 'OrionTaskLogTask.Duration': 38623})
>>> entry.status_label, entry.finished, entry.succeeded
('Ended', True, False)

The operations on a server (epo.server_tasks: list, run and wait, enable,
disable, cancel, log) are in the eposervertasks module.
"""

import datetime

from .policies import Policy

# Status of a task log entry (OrionTaskLogTask.Status) -> label of the
# Server Task Log; tasklog.listTaskHistory gives the label ("In Progress
# (0%)" with the progress). Checked on ePO 5.10 Update 7: Ended is a
# cancelled task.
COMPLETED = 0
FAILED = 1
ENDED = 2
PENDING_TERMINATION = 6
IN_PROGRESS = 10
STATUSES = {COMPLETED: 'Completed', FAILED: 'Failed', ENDED: 'Ended',
            PENDING_TERMINATION: 'Pending Termination', IN_PROGRESS: 'In Progress'}

# Statuses of a task that has stopped.
FINISHED = frozenset([COMPLETED, FAILED, ENDED])


def _date(text):
    """
    Returns the datetime of a date of the Web API (ISO with time zone), None
    for "None" or empty.

    >>> _date('2026-10-17T19:10:00+02:00').hour, _date('None')
    (19, None)
    """
    if not text or text == 'None':
        return None
    return datetime.datetime.fromisoformat(text)


def _running_date(text):
    """
    Returns the datetime of scheduler.listRunningServerTasks, which gives
    the date as the console in US English ("10/17/26 4:23:22 PM", time of
    the server, no time zone), or None when it is written otherwise.

    >>> _running_date('10/17/26 4:23:22 PM').isoformat()
    '2026-10-17T16:23:22'
    >>> _running_date('17/10/2026') is None
    True
    """
    try:
        return datetime.datetime.strptime(text or '', '%m/%d/%y %I:%M:%S %p')
    except ValueError:
        return None


def status_code(label):
    """
    Returns the status code of a label of tasklog.listTaskHistory, or None
    for a label not known.

    >>> status_code('Completed'), status_code('In Progress (0%)'), status_code('Nope')
    (0, 10, None)
    """
    for code, text in STATUSES.items():
        if label == text or (label or '').startswith(text + ' ('):
            return code
    return None


def _duration(milliseconds):
    """
    Returns a duration as text: seconds below 2 minutes, else minutes.

    >>> _duration(38623), _duration(170), _duration(600000), _duration(None)
    ('38.6 s', '0.2 s', '10 min', '')
    """
    if milliseconds is None:
        return ''
    if milliseconds < 120000:
        return '{:.1f} s'.format(milliseconds / 1000)
    return '{} min'.format(round(milliseconds / 60000))


class ServerTask():
    """
    A server task of the Server Tasks page (Menu > Automation > Server
    Tasks): id, name, description, schedule status and next run. The Web
    API gives no schedule or action: they are set in the console.

    >>> ServerTask(19, 'Download Software Product List', enabled=False)
    <ServerTask 19 Download Software Product List (disabled)>
    """

    def __init__(self, id, name, description='', enabled=True, valid=True, start_date=None,
                 end_date=None, next_run=None):
        """
        :param: id: The task id.
        :param: name: The task name.
        :param: description: The description.
        :param: enabled: The schedule is enabled (Schedule Status).
        :param: valid: The task is valid (its actions can run).
        :param: start_date: The start of the schedule (datetime).
        :param: end_date: The end of the schedule (datetime, None when none).
        :param: next_run: The next run (datetime, None when disabled).
        """
        self.id = id
        self.name = name
        self.description = description
        self.enabled = enabled
        self.valid = valid
        self.start_date = start_date
        self.end_date = end_date
        self.next_run = next_run

    @classmethod
    def from_json(cls, data):
        """
        Returns the task of scheduler.listAllServerTasks or
        scheduler.getServerTask (enabled is true/false in the list, "true"/
        "false" in getServerTask).
        """
        return cls(data['id'], data['name'], data.get('description') or '',
                   str(data.get('enabled')).lower() == 'true',
                   str(data.get('valid')).lower() == 'true', _date(data.get('startDate')),
                   _date(data.get('endDate')), _date(data.get('nextRunTime')))

    def __repr__(self):
        """
        Shows the id, the name and the schedule status.
        """
        return '<ServerTask {} {} ({})>'.format(self.id, self.name,
                                                'enabled' if self.enabled else 'disabled')

    def md_row(self):
        """
        Returns the columns of the Server Tasks page: Name, Schedule Status,
        Next Run, Description.

        >>> ServerTask(19, 'Download Software Product List', enabled=False).md_row()
        ['Download Software Product List', 'Disabled', '', '']
        """
        next_run = self.next_run.strftime('%Y-%m-%d %H:%M') if self.next_run else ''
        return [Policy.md_escape(value) for value in (
            self.name, 'Enabled' if self.enabled else 'Disabled', next_run, self.description)]


def server_tasks_to_markdown(tasks, title='Server Tasks'):
    """
    Returns the server tasks as a Markdown table sorted by name, as the
    Server Tasks page.

    >>> print(server_tasks_to_markdown([ServerTask(19, 'Download Software Product List',
    ...                                            enabled=False)]))
    # Server Tasks
    <BLANKLINE>
    | Name | Schedule Status | Next Run | Description |
    |---|---|---|---|
    | Download Software Product List | Disabled |  |  |
    """
    lines = ['# ' + Policy.md_heading(title), '', '| Name | Schedule Status | Next Run | Description |',
             '|---|---|---|---|']
    for task in sorted(tasks, key=lambda item: item.name.lower()):
        lines.append('| ' + ' | '.join(task.md_row()) + ' |')
    return '\n'.join(lines)


class TaskMessage():
    """
    A message of a task log entry (tasklog.listMessages).

    >>> TaskMessage.from_json({'date': '2026-10-17T16:24:05+02:00',
    ...     'message': 'No Registered Servers participating in Policy sharing'})
    <TaskMessage 2026-10-17 16:24:05: No Registered Servers participating in Policy sharing>
    """

    def __init__(self, date, text):
        """
        :param: date: The date (datetime).
        :param: text: The message.
        """
        self.date = date
        self.text = text

    @classmethod
    def from_json(cls, data):
        """
        Returns the message of a line of tasklog.listMessages.
        """
        return cls(_date(data.get('date')), data.get('message') or '')

    def __repr__(self):
        """
        Shows the date and the message.
        """
        date = self.date.strftime('%Y-%m-%d %H:%M:%S') if self.date else ''
        return '<TaskMessage {}: {}>'.format(date, self.text)


class TaskLogEntry():
    """
    A run of a task in the Server Task Log: a server task, a client task run
    now, an internal task... with its status, its subtasks and messages.

    >>> TaskLogEntry(36354, 'TIE Server Monitoring', status=COMPLETED, duration=170)
    <TaskLogEntry 36354 TIE Server Monitoring: Completed>
    """

    def __init__(self, id, name, start_date=None, end_date=None, user='', status=None,
                 source='', duration=None, duration_text='', subtasks=None, messages=None):
        """
        :param: id: The task log id (taskLogId; None for a subtask).
        :param: name: The task name.
        :param: start_date: The start (datetime).
        :param: end_date: The end (datetime).
        :param: user: The user who ran the task (User Name).
        :param: status: The status code (STATUSES).
        :param: source: The task source (scheduler, Internal Task...).
        :param: duration: The duration in milliseconds (OrionTaskLogTask).
        :param: duration_text: The duration as tasklog.listTaskHistory
                               gives it ("Less than a minute").
        :param: subtasks: The subtasks (TaskLogEntry), when read.
        :param: messages: The messages (TaskMessage), when read.
        """
        self.id = id
        self.name = name
        self.start_date = start_date
        self.end_date = end_date
        self.user = user
        self.status = status
        self.source = source
        self.duration = duration
        self.duration_text = duration_text
        self.subtasks = subtasks
        self.messages = messages

    @classmethod
    def from_json(cls, data):
        """
        Returns the entry of a line of tasklog.listTaskHistory or
        tasklog.listSubtasks (no id for a subtask).

        >>> TaskLogEntry.from_json({'id': '36355', 'name': 'Download Software Product List',
        ...     'status': 'In Progress (0%)', 'taskSource': 'scheduler'}).status_label
        'In Progress'
        """
        log_id = data.get('id')
        return cls(int(log_id) if log_id is not None else None, data.get('name') or '',
                   _date(data.get('startDate')), _date(data.get('endDate')),
                   data.get('userName') or '', status_code(data.get('status')),
                   data.get('taskSource') or '', duration_text=data.get('duration') or '')

    @classmethod
    def from_row(cls, data):
        """
        Returns the entry of a row of the OrionTaskLogTask table (or
        OrionTaskLogSubtask).
        """
        values = {key.split('.', 1)[1]: value for key, value in data.items()}
        return cls(values.get('Id'), values.get('Name') or '', _date(values.get('StartDate')),
                   _date(values.get('EndDate')), values.get('UserName') or '',
                   values.get('Status'), values.get('TaskSource') or '', values.get('Duration'))

    def __repr__(self):
        """
        Shows the id, the name and the status.
        """
        return '<TaskLogEntry {} {}: {}>'.format(self.id, self.name, self.status_label)

    @property
    def status_label(self):
        """
        The status as the Server Task Log shows it.

        >>> TaskLogEntry(1, 'A', status=FAILED).status_label
        'Failed'
        """
        return STATUSES.get(self.status, str(self.status))

    @property
    def finished(self):
        """
        True when the task has stopped (Completed, Failed or Ended).

        >>> TaskLogEntry(1, 'A', status=PENDING_TERMINATION).finished
        False
        """
        return self.status in FINISHED

    @property
    def succeeded(self):
        """
        True when the task completed.

        >>> TaskLogEntry(1, 'A', status=COMPLETED).succeeded
        True
        """
        return self.status == COMPLETED

    def md_row(self):
        """
        Returns the columns of the Server Task Log: Start Date, Name,
        Status, Duration, Source, User Name, Task Log ID.

        >>> TaskLogEntry(36354, 'TIE Server Monitoring', status=COMPLETED, duration=170,
        ...              source='scheduler', user='admin').md_row()
        ['', 'TIE Server Monitoring', 'Completed', '0.2 s', 'scheduler', 'admin', '36354']
        """
        start = self.start_date.strftime('%Y-%m-%d %H:%M:%S') if self.start_date else ''
        return [Policy.md_escape(value) for value in (
            start, self.name, self.status_label, _duration(self.duration) or self.duration_text,
            self.source, self.user, '' if self.id is None else str(self.id))]

    def to_markdown(self):
        """
        Returns the entry as Markdown: its columns, its subtasks and its
        messages (when read).

        >>> print(TaskLogEntry(1, 'A', status=FAILED, messages=[TaskMessage(None, 'No LDAP')]
        ...                    ).to_markdown())
        # A
        <BLANKLINE>
        | Start Date | Name | Status | Duration | Source | User Name | Task Log ID |
        |---|---|---|---|---|---|---|
        |  | A | Failed |  |  |  | 1 |
        <BLANKLINE>
        ## Messages
        <BLANKLINE>
        - No LDAP
        """
        lines = [task_log_to_markdown([self], self.name, sort=False)]
        if self.subtasks:
            lines += ['', task_log_to_markdown(self.subtasks, 'Subtasks', sort=False).replace(
                '# ', '## ', 1)]
        if self.messages:
            lines += ['', '## Messages', '']
            lines += ['- ' + Policy.md_escape(message.text) for message in self.messages]
        return '\n'.join(lines)


def task_log_to_markdown(entries, title='Server Task Log', sort=True):
    """
    Returns task log entries as a Markdown table with the columns of the
    Server Task Log, the latest first.

    >>> print(task_log_to_markdown([TaskLogEntry(36354, 'TIE Server Monitoring',
    ...                                          status=COMPLETED)]))
    # Server Task Log
    <BLANKLINE>
    | Start Date | Name | Status | Duration | Source | User Name | Task Log ID |
    |---|---|---|---|---|---|---|
    |  | TIE Server Monitoring | Completed |  |  |  | 36354 |
    """
    if sort:
        entries = sorted(entries, key=lambda item: (item.start_date is not None, item.start_date),
                         reverse=True)
    lines = ['# ' + Policy.md_heading(title), '',
             '| Start Date | Name | Status | Duration | Source | User Name | Task Log ID |',
             '|---|---|---|---|---|---|---|']
    for entry in entries:
        lines.append('| ' + ' | '.join(entry.md_row()) + ' |')
    return '\n'.join(lines)


class RunningTask():
    """
    A running task (scheduler.listRunningServerTasks): its task log id,
    name, start and progress as the server gives them (the progress may be
    wrong: "200 %" seen on the lab).

    >>> RunningTask.from_json({'taskLogId': 36355, 'taskName': 'Download Software Product List',
    ...     'startDate': '10/17/26 4:23:24 PM', 'percentComplete': '0 %'})
    <RunningTask 36355 Download Software Product List (0 %)>
    """

    def __init__(self, log_id, name, start_date=None, progress=None):
        """
        :param: log_id: The task log id.
        :param: name: The task name.
        :param: start_date: The start (datetime of the server, no time zone).
        :param: progress: The percentComplete number.
        """
        self.log_id = log_id
        self.name = name
        self.start_date = start_date
        self.progress = progress

    @classmethod
    def from_json(cls, data):
        """
        Returns the running task of a line of scheduler.listRunningServerTasks.
        """
        progress = str(data.get('percentComplete') or '').replace('%', '').strip()
        return cls(data.get('taskLogId'), data.get('taskName') or '',
                   _running_date(data.get('startDate')),
                   int(progress) if progress.isdigit() else None)

    def __repr__(self):
        """
        Shows the task log id, the name and the progress.
        """
        return '<RunningTask {} {} ({} %)>'.format(self.log_id, self.name, self.progress)
