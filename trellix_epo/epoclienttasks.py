# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOClientTasks, the client task operations of
EPOClient (epo.client_tasks): find, export and import the tasks of the
Client Task Catalog, run a task on systems now, and read which tasks are
applied to which systems (clienttask.* commands, core.executeQuery on
EPOTaskAppliedTasks).

    tasks = epo.client_tasks.export('SOLIDCORE_META')         # ClientTaskList
    epo.client_tasks.import_tasks([SCRunCommandsTask('Status', ['status'])])
    epo.client_tasks.run('Status', ['W10ENTB01'])
    epo.client_tasks.applied('W10ENTB01')

Server behaviours handled here (checked on ePO 5.10 Update 7):
- the Web API has no command to create, delete, assign or schedule a
  client task: a task is created or replaced by an import, assigned and
  scheduled in the console;
- clienttask.importClientTask takes the file as uploadFile (importFileName
  is a path on the server) and answers "Imported <n> client tasks.": it
  skips without an error a task of an unknown type and a task whose name
  differs by case only from a task of the same type; import_tasks()
  raises EPOError when the count is not the number of tasks sent;
- clienttask.export without a product exports every product, but not the
  tasks of some types (ENS policy based On-Demand Scan, Trellix Agent
  Statistics...).
"""

import re

from .clienttasks import ClientTask, ClientTaskList
from .epo import EPOError


def _names(systems):
    """
    Returns the "names" parameter of clienttask.run: system names, IP
    addresses or ids, given as a list or as one text.

    >>> _names(['W10ENTB01', 4]), _names('W2022CORE')
    ('W10ENTB01,4', 'W2022CORE')
    >>> _names([])
    Traceback (most recent call last):
    ValueError: At least one system is required.
    """
    items = [systems] if isinstance(systems, (str, int)) else list(systems)
    items = [str(item).strip() for item in items if str(item).strip()]
    if not items:
        raise ValueError('At least one system is required.')
    return ','.join(items)


class EPOClientTasks():
    """
    The client task operations of an EPOClient (epo.client_tasks).
    """

    # Columns of EPOTaskAppliedTasks read by applied(), with their key in
    # the rows returned.
    APPLIED_COLUMNS = {
        'EPOLeafNode.NodeName': 'system',
        'EPOTaskAppliedTasks.NodeTxtPath': 'path',
        'EPOTaskAppliedTasks.ProductCode': 'product_id',
        'EPOTaskAppliedTasks.TaskTypeId': 'type_number',
        'EPOTaskAppliedTasks.Name': 'name',
        'EPOTaskAppliedTasks.upToDate': 'up_to_date',
    }

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPOClientTasks of {!r}>'.format(self.epo)

    def find(self, search_text=''):
        """
        Returns the client tasks whose name, product or type contains the
        text (clienttask.find): dictionaries with productId, productName,
        typeId (a number), typeName ("Trellix Agent: Product Update"),
        objectId (the task id) and objectName (the task name).
        """
        return self.epo.call('clienttask.find', searchText=search_text)

    def export(self, product_id=None):
        """
        Returns the client tasks of a product (e.g. EPOAGENTMETA,
        SOLIDCORE_META, SIR_____1000), or of every product, as a
        ClientTaskList of typed tasks (TADeploymentTask...).
        """
        text = self.epo._text('clienttask.export', productId=product_id)   # pylint: disable=protected-access
        return ClientTaskList(text.strip().encode('utf-8'))

    def get(self, name, product_id=None, type_id=None):
        """
        Returns the client task of this name (and product id and type id of
        the export when given), or None.

        :raise: EPOError: Several tasks have this name: give the product id
                          or the type id.
        """
        found = [task for task in self.export(product_id)
                 if task.name == name and type_id in (None, task.type_id)]
        if len(found) > 1:
            raise EPOError('clienttask.export', 'Several client tasks are named "{}": give the '
                           'product id or the type id.'.format(name))
        return found[0] if found else None

    def import_tasks(self, tasks, file_name='clienttasks.xml'):
        """
        Imports client tasks (clienttask.importClientTask): a new task is
        added to the Client Task Catalog, a task of the same product, type
        and name is replaced (it keeps its id and its assignments).

        :param: tasks: A ClientTaskList, a ClientTask or a list of tasks.
        :param: file_name: The file name sent with the upload.
        :return: The number of tasks imported.
        :raise: ValueError: A task breaks a rule of its console page.
        :raise: EPOError: The server imported fewer tasks than sent (unknown
                          type, or a name that differs by case only from a
                          task of the server: see ClientTaskList.check_server()).
        """
        if isinstance(tasks, ClientTask):
            tasks = [tasks]
        if not isinstance(tasks, ClientTaskList):
            items, tasks = tasks, ClientTaskList()
            for task in items:
                tasks.add(task)
        text = self.epo._text('clienttask.importClientTask',   # pylint: disable=protected-access
                              files={'uploadFile': (file_name, tasks.get_xml_content())},
                              output='terse').strip()
        match = re.search(r'Imported (\d+) client task', text)
        count = int(match.group(1)) if match else None
        if count != len(tasks):
            raise EPOError('clienttask.importClientTask',
                           '{} ({} task(s) sent): the server skips a task of an unknown type and '
                           'a task whose name differs by case only from a task of the same '
                           'type.'.format(text, len(tasks)))
        return count

    def _task_ids(self, task, product_id=None):
        """
        Returns the product id and the task id (objectId) that clienttask.run
        expects, for a task name, a ClientTask or a row of find().

        :raise: EPOError: No task, or several tasks, of this name.
        """
        if isinstance(task, dict):
            return task['productId'], task['objectId']
        if isinstance(task, ClientTask):
            name, product_id = task.name, task.product_id
        else:
            name = task
        found = [item for item in self.find(name) if item['objectName'] == name and
                 product_id in (None, item['productId']) and
                 (not isinstance(task, ClientTask) or task.is_type_name(item['typeName']))]
        if len(found) != 1:
            raise EPOError('clienttask.find', '{} client task(s) named "{}"{}.'.format(
                len(found), name, ': give the ClientTask or the find() row' if found else ''))
        return found[0]['productId'], found[0]['objectId']

    def run(self, task, systems, retry_attempts=1, retry_interval=30, abort_after=5,
            use_all_agent_handlers=False, stop_after=20, random_minutes=0, timeout_hours=48,
            product_id=None):
        """
        Runs a client task now on systems (clienttask.run, "Run Client Task
        Now" of the console), without assigning it.

        :param: task: The task name, a ClientTask or a row of find().
        :param: systems: System names, IP addresses or ids (list or text).
        :param: retry_attempts: Times the server tries to send the task.
        :param: retry_interval: Seconds between the attempts.
        :param: abort_after: Minutes before cancelling all attempts.
        :param: use_all_agent_handlers: Any Agent Handler can send the task
                                        (default: the last one the system used).
        :param: stop_after: Minutes the task is allowed to run.
        :param: random_minutes: Minutes over which the run is spread (0: now).
        :param: timeout_hours: Hours before the task is marked as timed out.
        :param: product_id: The product of the task when its name is not unique.
        :return: The server answer: "Succeeded" once the run is queued; the
                 run is then in the Server Task Log as "RunNow Task For :
                 <task name>" (checked on ePO 5.10 Update 7).
        """
        product, task_id = self._task_ids(task, product_id)
        return self.epo.call('clienttask.run', names=_names(systems), productId=product,
                             taskId=task_id, retryAttempts=retry_attempts,
                             retryIntervalInSeconds=retry_interval, abortAfterMinutes=abort_after,
                             useAllAgentHandlers=use_all_agent_handlers,
                             stopAfterMinutes=stop_after, randomMinutes=random_minutes,
                             timeoutInHours=timeout_hours)

    def applied(self, system=None, name=None):
        """
        Returns the client tasks applied to the systems (assigned to their
        group or to them; EPOTaskAppliedTasks), one dictionary per system and
        task: system, path (System Tree path of the system), product_id,
        type_number (typeId of find()), name and up_to_date.

        :param: system: A system name to read this system only.
        :param: name: A task name to read this task only.
        """
        where = []
        if system:
            where.append('(eq EPOLeafNode.NodeName "{}")'.format(system.replace('"', '\\"')))
        if name:
            where.append('(eq EPOTaskAppliedTasks.Name "{}")'.format(name.replace('"', '\\"')))
        rows = self.epo.query(
            'EPOTaskAppliedTasks', '(select {})'.format(' '.join(self.APPLIED_COLUMNS)),
            ('(and {})'.format(' '.join(where)) if len(where) > 1 else
             where[0] if where else None))
        return [{key: row.get(column) for column, key in self.APPLIED_COLUMNS.items()}
                for row in rows]
