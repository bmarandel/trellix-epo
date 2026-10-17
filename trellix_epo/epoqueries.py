# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOQueries, the query operations of EPOClient
(epo.queries): run a SQUID query built with squid.Query, list the saved
queries of Queries & Reports and run them, and read the console labels of
the columns (core.executeQuery, core.listQueries, core.listDatabases).

    query = Query('EPOLeafNode').select('NodeName', 'LastUpdate').where(
        older_than('LastUpdate', days=30))
    rows = epo.queries.run(query)                    # [{column: value}...]
    print(rows_to_markdown(rows, epo.queries.labels(query)))
    epo.queries.run('Inactive Agents')               # a saved query, by name or id
    epo.queries.list(group='Agent Management')       # [SavedQuery...]

Server behaviours (checked on ePO 5.10 Update 7):
- a saved query runs by id with its own columns, grouping and sort; an
  unknown id gives "Unable to locate query with ID='99,999'";
- the queries of another database (TIE Server: TieServerSchema) fail with
  "The connection attempt failed." when that server is down;
- core.listQueries gives the condition as the console writes it
  (conditionSexp), not the SQUID: a saved query can't be changed or copied
  with the Web API (no export, import or delete command);
- :output=verbose writes each column with its console label ("Label:
  value", a blank line between rows), used by labels().
"""

import copy

from .squid import Query, SavedQuery


class EPOQueries():
    """
    The query operations of an EPOClient (epo.queries).
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo

    def __repr__(self):
        """
        Shows the server.
        """
        return '<EPOQueries of {!r}>'.format(self.epo)

    def list(self, search_text='', group=None):
        """
        Returns the saved queries the user can see (core.listQueries),
        whose name or description contains the text (case insensitive).

        Example: epo.queries.list(group='Agent Management').

        :param: group: Keep a query group (case insensitive).
        """
        text = search_text.lower()
        return [query for query in (SavedQuery.from_json(item)
                                    for item in self.epo.call('core.listQueries'))
                if (text in query.name.lower() or text in query.description.lower()) and
                (group is None or query.group.lower() == group.lower())]

    def get(self, query):
        """
        Returns a saved query by name (case sensitive) or id, or None.

        Example: epo.queries.get('Inactive Agents').
        """
        found = [item for item in self.list()
                 if (item.id == query if isinstance(query, int) else item.name == query)]
        return found[0] if found else None

    def require(self, query):
        """
        Returns a saved query by name, id or SavedQuery, or raises ValueError.

        Example: epo.queries.require(41).
        """
        if isinstance(query, SavedQuery):
            return query
        found = self.get(query)
        if found is None:
            raise ValueError('Unknown query: {}.'.format(query))
        return found

    def run(self, query, database=None):
        """
        Runs a query and returns its rows ({"Table.Column": value}, plus
        "count" for a grouped query).

        Example: epo.queries.run(Query('EPOLeafNode').select('NodeName')),
        epo.queries.run('Inactive Agents').

        :param: query: A Query, or a saved query (name, id or SavedQuery).
        :param: database: The registered database of a saved query of
                          another database type (core.listDatabases).
        """
        if isinstance(query, Query):
            return self.epo.call('core.executeQuery', **query.params())
        saved = self.require(query)
        return self.epo.call('core.executeQuery', queryId=saved.id, database=database)

    def labels(self, query, database=None):
        """
        Returns the console labels of the columns of a query: {"Table.Column":
        label}, read from one row with :output=verbose ({} when the query
        has no row).

        Example: epo.queries.labels(query) gives {'EPOLeafNode.NodeName':
        'System Name', ...}.
        """
        if isinstance(query, Query):
            # One row is enough to read the labels.
            probe = copy.copy(query)
            probe.limit = 1
            params = probe.params()
            rows = self.epo.call('core.executeQuery', **params)
            text = self.epo.call('core.executeQuery', output='verbose', **params)
        else:
            saved = self.require(query)
            rows = self.epo.call('core.executeQuery', queryId=saved.id, database=database)[:1]
            text = self.epo.call('core.executeQuery', queryId=saved.id, database=database,
                                 output='verbose')
        if not rows:
            return {}
        # The rows are separated by a blank line (CRLF line ends).
        first = text.replace('\r\n', '\n').strip().split('\n\n')[0].splitlines()
        labels = [line.split(':', 1)[0].strip() for line in first if ':' in line]
        return dict(zip(rows[0], labels)) if len(labels) == len(rows[0]) else {}

    def databases(self):
        """
        Returns the registered databases: {name: database type} ('' for the
        ePO database).

        Example: epo.queries.databases() gives {'ePO': '', 'TIE Server ...':
        'TieServerSchema'}.
        """
        return {item['name']: item.get('databaseType') or ''
                for item in self.epo.call('core.listDatabases')}
