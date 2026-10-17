# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOServerTasks, the server task operations of EPOClient
(epo.server_tasks): list the server tasks, run one and wait for its end,
enable or disable its schedule, cancel a run, and read the Server Task Log
(scheduler.* and tasklog.* commands, OrionTaskLogTask table).

    epo.server_tasks.list()                                   # [ServerTask...]
    entry = epo.server_tasks.run('Update Main Repository', wait=True)
    entry.succeeded, entry.messages                           # TaskLogEntry
    epo.server_tasks.disable('Inactive Agent Cleanup Task')
    epo.server_tasks.log(task='Update Main Repository', limit=5)   # latest first

The Web API has no command to create, change, import, export or delete a
server task (its schedule and actions are set in the console), and the
library doesn't purge the Server Task Log (tasklog.purge with no age
purges all of it).

Server behaviours handled here (checked on ePO 5.10 Update 7 with "TIE
Server Monitoring", "Download Software Product List" and "Synchronize
Shared Policies"):
- scheduler.runServerTask answers the task log id at once; a disabled task
  runs too;
- tasklog.listTaskHistory gives at most 50 entries (maxRows by default)
  from the oldest of the period, and ignores taskId: log() reads the
  OrionTaskLogTask table instead, the latest first;
- scheduler.cancelServerTask answers true, the task then goes through
  "Pending Termination" to "Ended" (1.5 to 38 s for Download Software
  Product List, depending on its step); a task that is not running gives "No running task with taskLogId
  ...";
- scheduler.getServerTask gives enabled as "true"/"false", and an unknown
  name "There are no tasks named ...";
- scheduler.listRunningServerTasks gives the start date in US English
  ("10/17/26 4:23:22 PM") and a progress that may be wrong ("200 %").
"""

import time

from .epo import EPOError
from .servertasks import RunningTask, ServerTask, TaskLogEntry, TaskMessage, STATUSES

# Columns of the OrionTaskLogTask table read for the log.
LOG_COLUMNS = ('Id', 'Name', 'StartDate', 'EndDate', 'UserName', 'Status', 'TaskSource',
               'Duration')


def _quote(text):
    """
    Returns a text value of a SQUID condition, between quotes (a quote in
    the text is removed: the names of the log have none).

    >>> _quote('TIE Server "Monitoring"')
    '"TIE Server Monitoring"'
    """
    return '"{}"'.format(str(text).replace('"', ''))


def _where(conditions):
    """
    Returns the where clause of SQUID conditions (None when there are none).

    >>> _where([]), _where(['(eq A.B 1)']), _where(['(eq A.B 1)', '(eq A.C 2)'])
    (None, '(eq A.B 1)', '(and (eq A.B 1) (eq A.C 2))')
    """
    if not conditions:
        return None
    return conditions[0] if len(conditions) == 1 else '(and {})'.format(' '.join(conditions))


class EPOServerTasks():
    """
    The server task operations of an EPOClient (epo.server_tasks).
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo
        # Pause between two reads of a running task (replaced by the tests).
        self._sleep = time.sleep

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPOServerTasks of {!r}>'.format(self.epo)

    # ------------------------------ Server tasks ------------------------------
    def list(self):
        """
        Returns the server tasks (scheduler.listAllServerTasks).

        Example: [task.name for task in epo.server_tasks.list() if task.enabled].
        """
        return [ServerTask.from_json(item) for item in self.epo.call('scheduler.listAllServerTasks')]

    def get(self, task):
        """
        Returns a server task by name (as the console, case sensitive) or
        id, or None.

        Example: epo.server_tasks.get('Update Main Repository').
        """
        if isinstance(task, ServerTask):
            task = task.id
        params = {'taskId': task} if isinstance(task, int) else {'taskName': task}
        try:
            return ServerTask.from_json(self.epo.call('scheduler.getServerTask', **params))
        except EPOError as error:
            if 'There are no tasks named' in str(error) or 'no task' in str(error).lower():
                return None
            raise

    def require(self, task):
        """
        Returns a server task by name, id or ServerTask, or raises ValueError.

        Example: epo.server_tasks.require(27).
        """
        found = self.get(task)
        if found is None:
            raise ValueError('Unknown server task: {}.'.format(
                task.name if isinstance(task, ServerTask) else task))
        return found

    def enable(self, task):
        """
        Enables the schedule of a server task (scheduler.updateServerTask).

        Example: epo.server_tasks.enable('Inactive Agent Cleanup Task').

        :return: The task read back (next_run set by the server).
        """
        return self._update(task, 'enabled')

    def disable(self, task):
        """
        Disables the schedule of a server task (scheduler.updateServerTask);
        the task can still be run with run().

        Example: epo.server_tasks.disable('Inactive Agent Cleanup Task').

        :return: The task read back.
        """
        return self._update(task, 'disabled')

    def _update(self, task, status):
        """
        Sets the schedule status and returns the task read back.

        :raise: EPOError: The status is not the one set after the call.
        """
        found = self.require(task)
        self.epo.call('scheduler.updateServerTask', taskId=found.id, status=status)
        updated = self.require(found.id)
        if updated.enabled != (status == 'enabled'):
            raise EPOError('scheduler.updateServerTask', '{} is not {} after the call.'.format(
                found.name, status))
        return updated

    # ------------------------------ Runs ------------------------------
    def run(self, task, wait=False, timeout=600, interval=5):
        """
        Runs a server task now (scheduler.runServerTask, Run of the Server
        Tasks page), enabled or not.

        Example: entry = epo.server_tasks.run('Update Main Repository', wait=True).

        :param: task: The task name, id or ServerTask.
        :param: wait: Wait for the end of the task (see wait()).
        :return: The TaskLogEntry of the run: just started, or finished with
                 its subtasks and messages when wait.
        :raise: TimeoutError: The task is still running after timeout seconds.
        """
        found = self.require(task)
        log_id = int(self.epo.call('scheduler.runServerTask', taskId=found.id))
        if wait:
            return self.wait(log_id, timeout, interval)
        return self.entry(log_id, details=False) or TaskLogEntry(log_id, found.name)

    def wait(self, log_id, timeout=600, interval=5):
        """
        Waits for the end of a task log entry and returns it with its
        subtasks and messages.

        Example: epo.server_tasks.wait(36355, timeout=120).

        :param: log_id: The task log id.
        :param: timeout: The maximum wait in seconds.
        :param: interval: The seconds between two reads.
        :raise: TimeoutError: The task is still running after timeout seconds.
        """
        waited = 0
        while True:
            entry = self.entry(log_id, details=False)
            if entry is not None and entry.finished:
                return self.entry(log_id)
            if waited >= timeout:
                raise TimeoutError('Task log {} is still {} after {} s.'.format(
                    log_id, entry.status_label if entry else 'not logged', timeout))
            self._sleep(interval)
            waited += interval

    def cancel(self, log_id, wait=False, timeout=120, interval=5):
        """
        Cancels a running task (scheduler.cancelServerTask): the task goes
        through Pending Termination to Ended.

        Example: epo.server_tasks.cancel(36355, wait=True).

        :param: log_id: The task log id (TaskLogEntry.id, RunningTask.log_id).
        :param: wait: Wait for the end of the task.
        :return: The TaskLogEntry (finished when wait).
        :raise: EPOError: The task is not running.
        """
        self.epo.call('scheduler.cancelServerTask', taskLogId=log_id)
        if wait:
            return self.wait(log_id, timeout, interval)
        return self.entry(log_id, details=False)

    def running(self):
        """
        Returns the running tasks (scheduler.listRunningServerTasks).

        Example: [task.name for task in epo.server_tasks.running()].
        """
        return [RunningTask.from_json(item)
                for item in self.epo.call('scheduler.listRunningServerTasks')]

    # ------------------------------ Server Task Log ------------------------------
    def log(self, task=None, source=None, status=None, days=None, limit=50):
        """
        Returns entries of the Server Task Log, the latest first (the
        OrionTaskLogTask table: tasklog.listTaskHistory gives the oldest).

        Example: epo.server_tasks.log(task='Update Main Repository', status='Failed', days=7).

        :param: task: Keep the entries of a task name (or ServerTask).
        :param: source: Keep a task source (scheduler, Internal Task...).
        :param: status: Keep a status (code or label: Completed, Failed...).
        :param: days: Keep the entries started in the last days.
        :param: limit: The maximum number of entries.
        """
        conditions = []
        if task is not None:
            conditions.append('(eq OrionTaskLogTask.Name {})'.format(
                _quote(task.name if isinstance(task, ServerTask) else task)))
        if source is not None:
            conditions.append('(eq OrionTaskLogTask.TaskSource {})'.format(_quote(source)))
        if status is not None:
            code = status if isinstance(status, int) else next(
                (key for key, label in STATUSES.items() if label.lower() == status.lower()), None)
            if code is None:
                raise ValueError('Unknown status {!r}: one of {}.'.format(
                    status, ', '.join(STATUSES.values())))
            conditions.append('(eq OrionTaskLogTask.Status {})'.format(code))
        if days is not None:
            conditions.append('(newerThan OrionTaskLogTask.StartDate {})'.format(
                int(days * 86400000)))
        rows = self.epo.query('OrionTaskLogTask', '(select (top {}) {})'.format(
            int(limit), ' '.join('OrionTaskLogTask.' + column for column in LOG_COLUMNS)),
            _where(conditions), '(order (desc OrionTaskLogTask.StartDate))')
        return [TaskLogEntry.from_row(row) for row in rows]

    def entry(self, log_id, details=True):
        """
        Returns a task log entry, with its subtasks and messages when
        details, or None.

        Example: epo.server_tasks.entry(36355).messages.
        """
        rows = self.epo.query('OrionTaskLogTask', '(select {})'.format(
            ' '.join('OrionTaskLogTask.' + column for column in LOG_COLUMNS)),
            '(eq OrionTaskLogTask.Id {})'.format(int(log_id)))
        if not rows:
            return None
        entry = TaskLogEntry.from_row(rows[0])
        if details:
            entry.subtasks = [TaskLogEntry.from_json(item) for item in
                              self.epo.call('tasklog.listSubtasks', taskLogId=log_id)]
            entry.messages = [TaskMessage.from_json(item) for item in
                              self.epo.call('tasklog.listMessages', taskLogId=log_id)]
        return entry

    def sources(self):
        """
        Returns the task sources of the Server Task Log: {name: label}.

        Example: epo.server_tasks.sources()['scheduler'] == 'Server Task'.
        """
        return {item['name']: item['displayName'] for item in self.epo.call('tasklog.listTaskSources')}
