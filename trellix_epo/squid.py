# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the SQUID queries of ePO (the query language of
core.executeQuery and of the Queries & Reports page) as objects, without a
server: the SQUID text (squid_quote(), squid_parse()), a small query builder
(Query and the conditions) and the saved queries (SavedQuery, from
core.listQueries).

>>> query = (Query('EPOLeafNode').select('NodeName', 'EPOComputerProperties.IPAddress')
...          .where(eq('ManagedState', 1), older_than('LastUpdate', days=30))
...          .order('NodeName').top(10))
>>> query.params()['where']
'(and (eq EPOLeafNode.ManagedState 1) (olderThan EPOLeafNode.LastUpdate 2592000000))'
>>> query.params()['select']
'(select (top 10) EPOLeafNode.NodeName EPOComputerProperties.IPAddress)'

A column without a table name is a column of the target. The operations on
a server (epo.queries: run a Query or a saved query, list the saved
queries) are in the epoqueries module; the syntax, the operators and the
traps are in the trellix-epo skill (reference/squid.md). This module is the
reference of the SQUID text: tags imports it.
"""

import datetime
import re

from .policies import Policy

# Milliseconds in a day (newerThan / olderThan take milliseconds).
DAY = 86400000


# ------------------------------ SQUID text ------------------------------
def squid_quote(text):
    """
    Returns a SQUID string: in double quotes, the double quotes and the
    backslashes escaped with a backslash.

    >>> print(squid_quote('a"b\\'c'))
    "a\\"b'c"
    """
    return '"{}"'.format(text.replace('\\', '\\\\').replace('"', '\\"'))


def squid_parse(text):
    """
    Returns a SQUID expression as nested lists: an item in parentheses
    becomes a list, a quoted string a str subclass (SquidString), a word a
    str.

    >>> squid_parse('( where ( eq EPOComputerProperties.Vdi 1 ) )')
    ['where', ['eq', 'EPOComputerProperties.Vdi', '1']]
    >>> squid_parse('( eq P "a\\\\"b" )')[2]
    SquidString('a"b')
    >>> squid_parse('( eq P "x" ')
    Traceback (most recent call last):
    ValueError: Unbalanced parentheses in the SQUID expression.
    """
    tokens = re.findall(r'\(|\)|"(?:\\.|[^"\\])*"|[^\s()"]+', text)
    stack = [[]]
    for token in tokens:
        if token == '(':
            stack.append([])
        elif token == ')':
            if len(stack) < 2:
                raise ValueError('Unbalanced parentheses in the SQUID expression.')
            item = stack.pop()
            stack[-1].append(item)
        elif token.startswith('"'):
            stack[-1].append(SquidString(re.sub(r'\\(.)', r'\1', token[1:-1])))
        else:
            stack[-1].append(token)
    if len(stack) != 1 or len(stack[0]) != 1:
        raise ValueError('Unbalanced parentheses in the SQUID expression.')
    return stack[0][0]


class SquidString(str):
    """
    A quoted string of a SQUID expression (to tell "1" from 1).

    >>> SquidString('Server')
    SquidString('Server')
    """

    def __repr__(self):
        """
        Shows the class, to tell a quoted string from a word.
        """
        return 'SquidString({})'.format(str.__repr__(self))


def squid_value(value):
    """
    Returns a value of a condition as SQUID text: a number as it is, True and
    False as 1 and 0 (the boolean columns compare with numbers), a text
    quoted.

    >>> squid_value(5), squid_value(True), squid_value('W10'), squid_value(2.5)
    ('5', '1', '"W10"', '2.5')
    """
    if isinstance(value, bool):
        return '1' if value else '0'
    if isinstance(value, (int, float)):
        return str(value)
    return squid_quote(str(value))


# ------------------------------ Conditions ------------------------------
class Condition():
    """
    A condition of a where clause: an operator, a column and its values
    (e.g. eq, contains, newerThan, hasTag, descendsFrom; see the skill
    reference/squid.md for the operators of each column type).

    >>> Condition('in_subnet', 'EPOComputerProperties.IPV6', '192.168.100.0/24').squid()
    '(in_subnet EPOComputerProperties.IPV6 "192.168.100.0/24")'
    """

    def __init__(self, operator, column, *values):
        """
        :param: operator: The SQUID operator.
        :param: column: The column ("Table.Column", or "Column" of the target).
        :param: values: The values (numbers, booleans or texts).
        """
        self.operator = operator
        self.column = column
        self.values = values

    def squid(self, target=None):
        """
        Returns the condition as SQUID text, the column prefixed with the
        target when it has no table name.

        >>> eq('NodeName', 'PC01').squid('EPOLeafNode')
        '(eq EPOLeafNode.NodeName "PC01")'
        """
        return '({})'.format(' '.join([self.operator, column_name(self.column, target)] +
                                      [squid_value(value) for value in self.values]))

    def __repr__(self):
        """
        Shows the SQUID text.
        """
        return '<Condition {}>'.format(self.squid())


class Logic():
    """
    Conditions joined with and / or, or a negated condition (not).

    >>> and_(eq('A.B', 1), or_(eq('A.C', 'x'), not_(is_blank('A.D')))).squid()
    '(and (eq A.B 1) (or (eq A.C "x") (not (isBlank A.D))))'
    """

    def __init__(self, operator, *conditions):
        """
        :param: operator: and, or or not.
        :param: conditions: The Condition or Logic items (one for not).
        """
        if operator == 'not' and len(conditions) != 1:
            raise ValueError('not takes one condition.')
        if not conditions:
            raise ValueError('{} takes at least one condition.'.format(operator))
        self.operator = operator
        self.conditions = conditions

    def squid(self, target=None):
        """
        Returns the conditions as SQUID text (one condition alone for and /
        or).

        >>> and_(eq('A.B', 1)).squid()
        '(eq A.B 1)'
        """
        if self.operator != 'not' and len(self.conditions) == 1:
            return self.conditions[0].squid(target)
        return '({} {})'.format(self.operator, ' '.join(condition.squid(target)
                                                        for condition in self.conditions))

    def __repr__(self):
        """
        Shows the SQUID text.
        """
        return '<Logic {}>'.format(self.squid())


def eq(column, value):
    """
    Equals: eq('ManagedState', 1).

    >>> eq('EPOLeafNode.NodeName', 'PC01').squid()
    '(eq EPOLeafNode.NodeName "PC01")'
    """
    return Condition('eq', column, value)


def ne(column, value):
    """
    Does not equal: ne('OSType', 'Linux').

    >>> ne('A.B', 2).squid()
    '(ne A.B 2)'
    """
    return Condition('ne', column, value)


def contains(column, text):
    """
    Contains a text: contains('OSType', 'Server').

    >>> contains('A.B', 'Srv').squid()
    '(contains A.B "Srv")'
    """
    return Condition('contains', column, text)


def starts_with(column, text):
    """
    Starts with a text: starts_with('NodeName', 'SRV').

    >>> starts_with('A.B', 'SRV').squid()
    '(startsWith A.B "SRV")'
    """
    return Condition('startsWith', column, text)


def is_blank(column):
    """
    The value is blank: is_blank('UserProperty1').

    >>> is_blank('A.B').squid()
    '(isBlank A.B)'
    """
    return Condition('isBlank', column)


def _milliseconds(days, milliseconds):
    """
    Returns a duration in milliseconds from days or milliseconds.

    >>> _milliseconds(30, None), _milliseconds(None, 1000)
    (2592000000, 1000)
    """
    if (days is None) == (milliseconds is None):
        raise ValueError('Give days or milliseconds.')
    return int(days * DAY) if days is not None else int(milliseconds)


def newer_than(column, days=None, milliseconds=None):
    """
    A date in the last days (newerThan, "Is within the last").

    >>> newer_than('A.B', days=1).squid()
    '(newerThan A.B 86400000)'
    """
    return Condition('newerThan', column, _milliseconds(days, milliseconds))


def older_than(column, days=None, milliseconds=None):
    """
    A date before the last days (olderThan, "Is not within the last").

    >>> older_than('A.B', milliseconds=1000).squid()
    '(olderThan A.B 1000)'
    """
    return Condition('olderThan', column, _milliseconds(days, milliseconds))


def and_(*conditions):
    """
    All the conditions: and_(eq(...), newer_than(...)).
    """
    return Logic('and', *conditions)


def or_(*conditions):
    """
    One of the conditions: or_(eq(...), eq(...)).
    """
    return Logic('or', *conditions)


def not_(condition):
    """
    The condition is false: not_(is_blank(...)).
    """
    return Logic('not', condition)


def column_name(column, target=None):
    """
    Returns "Table.Column": the column, prefixed with the target when it has
    no table name.

    >>> column_name('NodeName', 'EPOLeafNode'), column_name('EPOTag.Name', 'EPOLeafNode')
    ('EPOLeafNode.NodeName', 'EPOTag.Name')
    """
    if '.' in column or not target:
        return column
    return '{}.{}'.format(target.split('.')[-1], column)


# ------------------------------ Query ------------------------------
class Query():
    """
    A SQUID query of core.executeQuery: target, columns, conditions, order,
    group, top, joins and database, built step by step (each method returns
    the query).

    >>> Query('EPOLeafNode').select('NodeName').where(eq('ManagedState', 1)).params()
    {'target': 'EPOLeafNode', 'select': '(select EPOLeafNode.NodeName)', 'where': '(eq EPOLeafNode.ManagedState 1)'}
    """

    def __init__(self, target, database=None):
        """
        :param: target: The table (e.g. EPOLeafNode; "TieServerSchema.x" for a
                        table of another database type).
        :param: database: The registered database (core.listDatabases), for
                          a table of another database.
        """
        self.target = target
        self.database = database
        self.columns = []
        self.conditions = []
        self.orders = []
        self.groups = []
        self.joins = []
        self.limit = None
        self.unique = False
        self.counted = False

    def __repr__(self):
        """
        Shows the target and the where clause.
        """
        return '<Query {} {}>'.format(self.target, self.params().get('where') or '')

    def select(self, *columns):
        """
        Adds columns (all the columns of the target when there are none).
        """
        self.columns += columns
        return self

    def where(self, *conditions):
        """
        Adds conditions, all required (and).
        """
        self.conditions += conditions
        return self

    def order(self, column, desc=False):
        """
        Adds a sort column.

        >>> Query('T').order('A').order('B', desc=True).params()['order']
        '(order (asc T.A) (desc T.B))'
        """
        self.orders.append((column, desc))
        return self

    def group(self, *columns):
        """
        Groups the rows by columns (with count()).
        """
        self.groups += columns
        return self

    def count(self):
        """
        Adds the row count of each group (a "count" column).

        >>> Query('T').select('OS').group('OS').count().params()['select']
        '(select T.OS (count))'
        """
        self.counted = True
        return self

    def top(self, number):
        """
        Keeps the first rows only.
        """
        self.limit = int(number)
        return self

    def distinct(self):
        """
        Removes the duplicate rows.

        >>> Query('T').select('OS').distinct().params()['select']
        '(select (distinct) T.OS)'
        """
        self.unique = True
        return self

    def join(self, *tables):
        """
        Joins tables (joinTables) to the target.
        """
        self.joins += tables
        return self

    def params(self):
        """
        Returns the parameters of core.executeQuery (target, select, where,
        order, group, joinTables, database), the empty ones left out.
        """
        params = {'target': self.target}
        options = ([] if self.limit is None else ['(top {})'.format(self.limit)]) + \
            (['(distinct)'] if self.unique else [])
        columns = [column_name(column, self.target) for column in self.columns] + \
            (['(count)'] if self.counted else [])
        if options or columns:
            params['select'] = '(select {})'.format(' '.join(options + columns))
        if self.conditions:
            params['where'] = and_(*self.conditions).squid(self.target)
        if self.orders:
            params['order'] = '(order {})'.format(' '.join(
                '({} {})'.format('desc' if desc else 'asc', column_name(column, self.target))
                for column, desc in self.orders))
        if self.groups:
            params['group'] = '(group {})'.format(
                ' '.join(column_name(column, self.target) for column in self.groups))
        if self.joins:
            params['joinTables'] = ','.join(self.joins)
        if self.database:
            params['database'] = self.database
        return params


# ------------------------------ Saved queries ------------------------------
def _date(text):
    """
    Returns the datetime of a date of core.listQueries, or None.

    >>> _date('2024-09-11T15:09:52+02:00').year
    2024
    """
    return datetime.datetime.fromisoformat(text) if text else None


class SavedQuery():
    """
    A query of Queries & Reports (core.listQueries): id, name, description,
    group, target and its condition as the console writes it. The Web API
    doesn't give its columns or its SQUID: it runs it by id.

    >>> SavedQuery.from_json({'id': 41, 'name': 'Inactive Agents', 'groupName':
    ...     'Agent Management', 'target': 'EPOLeafNode', 'databaseType': '', 'conditionSexp':
    ...     '(Last Communication Is not within the last 1 Months and Managed State Equals Managed)'})
    <SavedQuery 41 Agent Management / Inactive Agents>
    """

    def __init__(self, id, name, description='', group='', target='', database_type='',
                 condition='', owner='', created_by='', created_on=None, modified_by='',
                 modified_on=None):
        """
        :param: id: The query id.
        :param: name: The query name.
        :param: description: The description.
        :param: group: The query group (groupName).
        :param: target: The table of the query.
        :param: database_type: The database type ('' for ePO, TieServerSchema
                               for the TIE Server...).
        :param: condition: The condition as the console shows it
                           (conditionSexp, not SQUID).
        :param: owner: Who can see it (userName: Public...).
        :param: created_by, created_on, modified_by, modified_on: The history.
        """
        self.id = id
        self.name = name
        self.description = description
        self.group = group
        self.target = target
        self.database_type = database_type
        self.condition = condition
        self.owner = owner
        self.created_by = created_by
        self.created_on = created_on
        self.modified_by = modified_by
        self.modified_on = modified_on

    @classmethod
    def from_json(cls, data):
        """
        Returns the query of a line of core.listQueries.
        """
        return cls(data['id'], data['name'], data.get('description') or '',
                   (data.get('groupName') or '').strip(), data.get('target') or '',
                   data.get('databaseType') or '', data.get('conditionSexp') or '',
                   data.get('userName') or '', data.get('createdBy') or '',
                   _date(data.get('createdOn')), data.get('modifiedBy') or '',
                   _date(data.get('modifiedOn')))

    def __repr__(self):
        """
        Shows the id, the group and the name.
        """
        return '<SavedQuery {} {} / {}>'.format(self.id, self.group, self.name)

    def md_row(self):
        """
        Returns the columns of the query table: group, name, id, target,
        description.

        >>> SavedQuery(41, 'Inactive Agents', group='Agent Management',
        ...            target='EPOLeafNode').md_row()
        ['Agent Management', 'Inactive Agents', '41', 'EPOLeafNode', '']
        """
        return [Policy.md_escape(value) for value in (
            self.group, self.name, str(self.id), self.target, self.description)]


def saved_queries_to_markdown(queries, title='Queries'):
    """
    Returns saved queries as a Markdown table, by group and name.

    >>> print(saved_queries_to_markdown([SavedQuery(41, 'Inactive Agents',
    ...                                             group='Agent Management')]))
    # Queries
    <BLANKLINE>
    | Group | Name | ID | Target | Description |
    |---|---|---|---|---|
    | Agent Management | Inactive Agents | 41 |  |  |
    """
    lines = ['# ' + Policy.md_heading(title), '', '| Group | Name | ID | Target | Description |',
             '|---|---|---|---|---|']
    for query in sorted(queries, key=lambda item: (item.group.lower(), item.name.lower())):
        lines.append('| ' + ' | '.join(query.md_row()) + ' |')
    return '\n'.join(lines)


def rows_to_markdown(rows, labels=None, title='Query results'):
    """
    Returns the rows of a query as a Markdown table, with the console labels
    of the columns when given (epo.queries.labels()), else the column names.

    >>> print(rows_to_markdown([{'EPOLeafNode.NodeName': 'PC01', 'count': 2}],
    ...                        {'EPOLeafNode.NodeName': 'System Name'}))
    # Query results
    <BLANKLINE>
    | System Name | count |
    |---|---|
    | PC01 | 2 |
    """
    columns = list(rows[0]) if rows else list(labels or [])
    labels = labels or {}
    lines = ['# ' + Policy.md_heading(title), '',
             '| ' + ' | '.join(Policy.md_escape(labels.get(column, column))
                               for column in columns) + ' |',
             '|' + '---|' * max(len(columns), 1)]
    for row in rows:
        lines.append('| ' + ' | '.join(Policy.md_escape('' if row.get(column) is None
                                                        else str(row.get(column)))
                                       for column in columns) + ' |')
    return '\n'.join(lines)
