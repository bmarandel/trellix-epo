# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOClient, a client of the ePolicy Orchestrator Web API
(https://<server>:8443/remote/<command>), written with the Python standard
library only, so that policies can be exported, edited with the policy
classes and imported back without another package.

- EPOClient.call() runs any Web API command (core.help, system.find,
  core.executeQuery...) and returns its answer (JSON decoded when the
  command gives JSON); an ePO error raises EPOError.
- Policies: find_policies(), export_policies() (returns the policy class of
  the product, e.g. ESTPPolicies for ENDP_AM_1000), import_policies().
- Solidcore Rule Groups: find_rule_groups(), export_rule_group(),
  import_rule_groups(), rename_rule_group() (scor.rulegroup.* commands).
- Tags and tag groups: epo.tags (EPOTags, see the epotags module).
- Client tasks: epo.client_tasks (EPOClientTasks, see the epoclienttasks
  module).
- Main Repository and repositories: epo.repository (EPORepository, see the
  eporepository module).
- System Tree: epo.systems (EPOSystems) and epo.groups (EPOGroups), see
  the eposystemtree module.
- Policy Catalog and assignments: epo.policies (EPOPolicies, see the
  epopolicies module); export_policies() and import_policies() are kept
  here as shortcuts.
- Server tasks and Server Task Log: epo.server_tasks (EPOServerTasks, see
  the eposervertasks module).

The password is kept in memory only: the library never writes it.
EPOClient.from_environment() reads EPO_URL, EPO_USER and EPO_PASSWORD.

Server behaviours handled here (checked on ePO 5.10 Update 7):
- the answer starts with "OK:" or "Error <n> :" on its first line;
- ":output=json" is ignored by some commands (policy.export gives the XML,
  the scor.* commands give text or XML);
- the scor.* commands report their errors in an "OK:" answer as
  {"success": false, "errorCode": n, "message": ...};
- a wrong user or password gives an HTTP 401 without an ePO answer.
"""

import base64
import html
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid

from .policies import Policies
from .ta.tapolicies import TAPolicies
from .es.tp.estppolicies import ESTPPolicies
from .es.fw.esfwpolicies import ESFWPolicies
from .es.sp import ESSPPolicies
from .es.cm import ESCommonPolicies
from .es.atp import ESATPPolicies
from .es.wc import ESWCPolicies
from .sc.scpolicies import SCPolicies
from .sc.rulegroups import SCRuleGroups
from .sir import SIRPolicies
from .edrf import EDRFPolicies


class EPOError(Exception):
    """
    An error returned by the ePO server: an "Error <n> :" answer, a scor.*
    answer with "success": false, or an HTTP error (code = HTTP status).

    >>> str(EPOError('policy.export', "Invalid ProductID 'NOPE'", 0))
    "policy.export: Invalid ProductID 'NOPE'"
    """

    def __init__(self, command, message, code=None):
        """
        :param: command: The command that failed, e.g. 'policy.export'.
        :param: message: The server message.
        :param: code: The ePO error number (0, 1...), the HTTP status, or None.
        """
        self.command = command
        self.code = code
        self.message = message
        super(EPOError, self).__init__('{}: {}'.format(command, message))


class EPOClient():
    """
    Client of the ePolicy Orchestrator Web API.

        epo = EPOClient('https://epo.example.com:8443', 'admin', password)
        policies = epo.export_policies('ENDP_AM_1000')    # ESTPPolicies
        epo.import_policies(policies, force=True)
    """

    # Policy classes per product id of policy.export / policy.importPolicy
    # (the Firewall export is asked with ENDP_FW_META, its XML says
    # ENDP_FW_META_FW).
    PRODUCTS = {
        'EPOAGENTMETA': TAPolicies,
        'ENDP_GS_1000': ESCommonPolicies,
        'ENDP_AM_1000': ESTPPolicies,
        'ENDP_FW_META': ESFWPolicies,
        'TIEClientMETA': ESATPPolicies,
        'ENDP_WP_1000': ESWCPolicies,
        'VSESTOMD1300': ESSPPolicies,
        'SOLIDCORE_META': SCPolicies,
        'SIR_____1000': SIRPolicies,
        'XCLIENT_META': EDRFPolicies,
    }

    # Solidcore Rule Group types and platforms, as expected by scor.rulegroup.*
    # (the platform is WIN or UNIX, not WINDOWS).
    RULE_GROUP_TYPES = {SCRuleGroups.APPLICATION_CONTROL: 'APPLICATION_CONTROL',
                        SCRuleGroups.CHANGE_CONTROL: 'CHANGE_CONTROL',
                        SCRuleGroups.INTEGRITY_MONITOR: 'INTEGRITY_MONITOR'}
    RULE_GROUP_PLATFORMS = (SCRuleGroups.WINDOWS, SCRuleGroups.UNIX)

    def __init__(self, url, user, password, verify=True, timeout=120):
        """
        Prepares the connection; nothing is sent to the server before the
        first command.

        :param: url: The ePO server URL, e.g. https://epo.example.com:8443.
        :param: user: The ePO user name.
        :param: password: The ePO password (kept in memory only).
        :param: verify: True to check the server certificate with the system
                        CA, the path of a CA file (PEM), or False to skip the
                        check (lab servers with a self-signed certificate only).
        :param: timeout: Timeout of a request, in seconds.
        :raise: ValueError: The URL or the user is missing.

        >>> EPOClient('https://epo.example.com:8443/', 'admin', 'secret')
        <EPOClient https://epo.example.com:8443 (admin)>
        >>> EPOClient('', 'admin', 'secret')
        Traceback (most recent call last):
        ValueError: The ePO server URL and user are required.
        """
        if not url or not user:
            raise ValueError('The ePO server URL and user are required.')
        self.url = url.rstrip('/')
        self.user = user
        self.timeout = timeout
        self._tags = None
        self._client_tasks = None
        self._repository = None
        self._systems = None
        self._groups = None
        self._policies = None
        self._server_tasks = None
        # Only the HTTP Basic header is kept, sent with every command (the Web
        # API has no session).
        self.__authorization = 'Basic ' + base64.b64encode(
            '{}:{}'.format(user, password).encode('utf-8')).decode('ascii')
        if verify is False:
            self.__context = ssl._create_unverified_context()   # pylint: disable=protected-access
        elif isinstance(verify, str):
            self.__context = ssl.create_default_context(cafile=verify)
        else:
            self.__context = ssl.create_default_context()

    @property
    def tags(self):
        """
        The tag operations (EPOTags): epo.tags.create(), epo.tags.apply(),
        epo.tags.groups.create()... see the epotags module.
        """
        if self._tags is None:
            # Imported here: epotags imports this module.
            from .epotags import EPOTags
            self._tags = EPOTags(self)
        return self._tags

    @property
    def client_tasks(self):
        """
        The client task operations (EPOClientTasks): epo.client_tasks.export(),
        epo.client_tasks.import_tasks(), epo.client_tasks.run()... see the
        epoclienttasks module.
        """
        if self._client_tasks is None:
            # Imported here: epoclienttasks imports this module.
            from .epoclienttasks import EPOClientTasks
            self._client_tasks = EPOClientTasks(self)
        return self._client_tasks

    @property
    def repository(self):
        """
        The repository operations (EPORepository): epo.repository.packages(),
        epo.repository.check_in(), epo.repository.pull()... see the
        eporepository module.
        """
        if self._repository is None:
            # Imported here: eporepository imports this module.
            from .eporepository import EPORepository
            self._repository = EPORepository(self)
        return self._repository

    @property
    def systems(self):
        """
        The system operations (EPOSystems): epo.systems.find(),
        epo.systems.add(), epo.systems.move(), epo.systems.set_properties()...
        see the eposystemtree module.
        """
        if self._systems is None:
            # Imported here: eposystemtree imports this module.
            from .eposystemtree import EPOSystems
            self._systems = EPOSystems(self)
        return self._systems

    @property
    def groups(self):
        """
        The System Tree group operations (EPOGroups): epo.groups.list(),
        epo.groups.systems(), epo.groups.create()... see the eposystemtree
        module.
        """
        if self._groups is None:
            # Imported here: eposystemtree imports this module.
            from .eposystemtree import EPOGroups
            self._groups = EPOGroups(self)
        return self._groups

    @property
    def policies(self):
        """
        The Policy Catalog operations (EPOPolicies): epo.policies.find(),
        epo.policies.assign(), epo.policies.reset(), epo.policies.assignments()...
        see the epopolicies module.
        """
        if self._policies is None:
            # Imported here: epopolicies imports this module.
            from .epopolicies import EPOPolicies
            self._policies = EPOPolicies(self)
        return self._policies

    @property
    def server_tasks(self):
        """
        The server task operations (EPOServerTasks): epo.server_tasks.list(),
        epo.server_tasks.run(), epo.server_tasks.log()... see the
        eposervertasks module.
        """
        if self._server_tasks is None:
            # Imported here: eposervertasks imports this module.
            from .eposervertasks import EPOServerTasks
            self._server_tasks = EPOServerTasks(self)
        return self._server_tasks

    def __repr__(self):
        """
        Shows the server and the user, never the password.
        """
        return '<EPOClient {} ({})>'.format(self.url, self.user)

    @classmethod
    def from_environment(cls, verify=True, timeout=120):
        """
        Returns a client set with the EPO_URL, EPO_USER and EPO_PASSWORD
        environment variables (verify and timeout as in EPOClient()).

        :raise: ValueError: One of the variables is not set, e.g.
                            "The EPO_PASSWORD environment variable is not set."
        """
        try:
            return cls(os.environ['EPO_URL'], os.environ['EPO_USER'], os.environ['EPO_PASSWORD'],
                       verify=verify, timeout=timeout)
        except KeyError as error:
            raise ValueError('The {} environment variable is not set.'.format(error.args[0]))

    # ------------------------------ Requests ------------------------------
    @staticmethod
    def _fields(args, params):
        """
        Returns the form fields of a command: the positional parameters
        become param1, param2..., True/False become true/false and the
        parameters set to None are left out.

        >>> EPOClient._fields(('WIN', 'APPLICATION_CONTROL'), {'ruleGroupName': 'Docker'})
        {'param1': 'WIN', 'param2': 'APPLICATION_CONTROL', 'ruleGroupName': 'Docker'}
        >>> EPOClient._fields((), {'force': True, 'where': None})
        {'force': 'true'}
        """
        fields = {'param{}'.format(index): value for index, value in enumerate(args, 1)}
        fields.update(params)
        return {name: (str(value).lower() if isinstance(value, bool) else value)
                for name, value in fields.items() if value is not None}

    @staticmethod
    def _multipart(fields, files, boundary=None):
        """
        Returns the body and the Content-Type of a multipart/form-data
        request that uploads files (policy.importPolicy, scor.rulegroup.import).

        :param: fields: The form fields, {name: value}.
        :param: files: The files, {parameter: (file name, bytes)}.
        :param: boundary: The part separator (a random one by default).

        >>> body, content_type = EPOClient._multipart({'force': 'true'},
        ...                                           {'file': ('p.xml', b'<x/>')}, 'B')
        >>> content_type
        'multipart/form-data; boundary=B'
        >>> body.split(b'\\r\\n')[:8]   # doctest: +NORMALIZE_WHITESPACE
        [b'--B', b'Content-Disposition: form-data; name="force"', b'', b'true',
         b'--B', b'Content-Disposition: form-data; name="file"; filename="p.xml"',
         b'Content-Type: application/octet-stream', b'']
        """
        boundary = boundary or uuid.uuid4().hex
        body = b''
        for name, value in fields.items():
            body += ('--{}\r\nContent-Disposition: form-data; name="{}"\r\n\r\n{}\r\n'.format(
                boundary, name, value)).encode('utf-8')
        for name, (file_name, content) in files.items():
            body += ('--{}\r\nContent-Disposition: form-data; name="{}"; filename="{}"\r\n'
                     'Content-Type: application/octet-stream\r\n\r\n'.format(
                         boundary, name, file_name)).encode('utf-8')
            body += content + b'\r\n'
        body += '--{}--\r\n'.format(boundary).encode('utf-8')
        return body, 'multipart/form-data; boundary={}'.format(boundary)

    @staticmethod
    def _parse_answer(command, answer, output):
        """
        Returns the content of a Web API answer: the decoded JSON when output
        is 'json' and the content is JSON, else the text after the status line.

        :raise: EPOError: An "Error <n> :" answer, or a scor.* answer with
                          "success": false.

        >>> EPOClient._parse_answer('policy.find', 'OK:\\r\\n[{"objectId": 129}]', 'json')
        [{'objectId': 129}]
        >>> EPOClient._parse_answer('scor.rulegroup.find', 'OK:\\r\\nDocker\\r\\n', 'json')
        'Docker\\r\\n'
        >>> EPOClient._parse_answer('nope.cmd', 'Error 1 :\\r\\nNo such command: nope.cmd', 'json')
        Traceback (most recent call last):
        trellix_epo.epo.EPOError: nope.cmd: No such command: nope.cmd
        >>> EPOClient._parse_answer('scor.rulegroup.find', 'OK:\\r\\n{"success": false, '
        ...                         '"errorCode": 1, "message": "Use WIN or UNIX."}', 'json')
        Traceback (most recent call last):
        trellix_epo.epo.EPOError: scor.rulegroup.find: Use WIN or UNIX.
        """
        status, _, text = answer.partition('\n')
        status = status.strip()
        if status != 'OK:':
            # "Error 1 :" -> code 1
            code = status[len('Error'):].strip(' :') if status.startswith('Error') else None
            raise EPOError(command, text.strip() or status,
                           int(code) if code and code.isdigit() else code)
        if output != 'json':
            return text
        try:
            data = json.loads(text)
        except ValueError:
            # Commands that ignore ":output=json" (policy.export, scor.*).
            return text
        if isinstance(data, dict) and data.get('success') is False and 'errorCode' in data:
            raise EPOError(command, data.get('message'), data.get('errorCode'))
        return data

    def _send(self, request):
        """
        Sends a request and returns the answer text, also for an HTTP error
        that carries an ePO answer ("OK:" or "Error..."). Tests replace this
        method to run without a server.

        :raise: EPOError: An HTTP error without an ePO answer, e.g. a wrong
                          password (code 401).
        """
        try:
            with urllib.request.urlopen(request, context=self.__context,
                                        timeout=self.timeout) as answer:
                return answer.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as error:
            text = error.read().decode('utf-8', 'replace')
            if text.startswith(('OK:', 'Error')):
                return text
            command = request.full_url.split('/remote/')[-1].split('?')[0]
            raise EPOError(command, 'HTTP {} {}'.format(error.code, error.reason), error.code)

    def call(self, command, /, *args, files=None, output='json', **params):
        """
        Runs a Web API command and returns its answer.

        :param: command: The command name, e.g. 'system.find'.
        :param: args: Positional parameters (param1, param2...).
        :param: files: Files to upload, {parameter: (file name, bytes)}.
        :param: output: 'json' (default: the JSON answer is decoded, the
                        other answers are returned as text), 'terse',
                        'verbose' or 'xml' (text).
        :param: params: Named parameters (True/False are sent as true/false,
                        None is left out).
        :return: The decoded JSON, or the answer text.
        :raise: EPOError: The server returned an error.

        Examples: call('system.find', 'W2022', searchNameOnly=True),
        call('core.help', command='policy.find', output='terse').
        """
        fields = self._fields(args, params)
        url = '{}/remote/{}?{}'.format(self.url, command,
                                       urllib.parse.urlencode({':output': output}))
        if files:
            body, content_type = self._multipart(fields, files)
        else:
            body = urllib.parse.urlencode(fields).encode('utf-8')
            content_type = 'application/x-www-form-urlencoded'
        request = urllib.request.Request(url, data=body, method='POST')
        request.add_header('Content-Type', content_type)
        request.add_header('Authorization', self.__authorization)
        return self._parse_answer(command, self._send(request), output)

    def _text(self, command, /, *args, **params):
        """
        Runs a command whose answer is text or XML (policy.export, scor.*...)
        and returns the text; the scor.* errors are raised as EPOError like
        with call(). A scor.* success sent as JSON ({"success": true,
        "message": ...}, e.g. scor.rulegroup.import) gives its message, as
        plain text (see _scor_message()).

        :raise: EPOError: The server returned an error, or other JSON.
        """
        answer = self.call(command, *args, **params)
        if isinstance(answer, dict) and answer.get('success') is True:
            return self._scor_message(answer.get('message') or '')
        if not isinstance(answer, str):
            raise EPOError(command, 'Unexpected JSON answer: {!r}'.format(answer)[:500])
        return answer

    @staticmethod
    def _scor_message(message):
        """
        Returns the message of a scor.* JSON answer as plain text: without
        the "success::::" prefix, the HTML line breaks become spaces and the
        HTML tags and entities are removed.

        >>> EPOClient._scor_message('success::::Rule groups were imported successfully.</br></br>'
        ...     'For details, review information for the &nbsp;<b>Import Solidcore Rule Groups</b>'
        ...     '&nbsp;server task.')   # doctest: +NORMALIZE_WHITESPACE
        'Rule groups were imported successfully. For details, review information
         for the Import Solidcore Rule Groups server task.'
        """
        text = message.split('::::', 1)[-1]
        text = re.sub(r'<br\s*/?>|</br>', ' ', text, flags=re.IGNORECASE)
        text = html.unescape(re.sub(r'<[^>]+>', '', text)).replace('\xa0', ' ')
        return ' '.join(text.split())

    def help(self, command=None):
        """
        Returns the help of a command (e.g. help('policy.find')), or the list
        of the commands the user can run (core.help).
        """
        return self.call('core.help', command=command, output='terse')

    def query(self, target, select=None, where=None, order=None, group=None, joins=None):
        """
        Runs a SQUID query (core.executeQuery) and returns the rows (list of
        dictionaries keyed by "Table.Column"), e.g.
        query('EPOLeafNode', '(select EPOLeafNode.NodeName)', '(eq EPOLeafNode.ManagedState 1)')
        returns [{'EPOLeafNode.NodeName': 'W10ENTB01'}, ...].

        :param: joins: The joinTables parameter (tables to join).
        """
        return self.call('core.executeQuery', target=target, select=select, where=where,
                         order=order, group=group, joinTables=joins)

    # ------------------------------ Policies ------------------------------
    def find_policies(self, search_text=''):
        """
        Returns the policies whose name, product, type or category contains
        the text (policy.find, no wildcard): dictionaries with productId,
        typeId, objectId, objectName, featureId..., e.g.
        find_policies('SIR')[0]['objectName'] == 'Trellix Default'.
        """
        return self.call('policy.find', searchText=search_text)

    def export_policies(self, product_id):
        """
        Returns all the policies of a product: epo.policies.export(), see
        there.

        Example: epo.export_policies('ENDP_AM_1000') gives ESTPPolicies.
        """
        return self.policies.export(product_id)

    def import_policies(self, policies, force=False, file_name='policies.xml'):
        """
        Imports policies into ePO: epo.policies.import_policies(), see
        there.

        Example: epo.import_policies(policies, force=True).
        """
        return self.policies.import_policies(policies, force, file_name)

    # ------------------------------ Solidcore Rule Groups ------------------------------
    def _rule_group_args(self, platform, group_type):
        """
        Returns the first two parameters of the scor.rulegroup.* commands
        (ruleGroupOS, ruleGroupType) for a platform and a type of SCRuleGroups.

        :raise: ValueError: Unknown platform or type.

        >>> EPOClient('https://epo', 'a', 'p')._rule_group_args(SCRuleGroups.WINDOWS,
        ...                                                     SCRuleGroups.APPLICATION_CONTROL)
        ('WIN', 'APPLICATION_CONTROL')
        >>> EPOClient('https://epo', 'a', 'p')._rule_group_args('WINDOWS',
        ...                                                     SCRuleGroups.APPLICATION_CONTROL)
        Traceback (most recent call last):
        ValueError: Rule Group platform must be one of ('WIN', 'UNIX').
        """
        if platform not in self.RULE_GROUP_PLATFORMS:
            raise ValueError('Rule Group platform must be one of {}.'.format(
                self.RULE_GROUP_PLATFORMS))
        if group_type not in self.RULE_GROUP_TYPES:
            raise ValueError('Rule Group type must be one of {}.'.format(
                sorted(self.RULE_GROUP_TYPES)))
        return platform, self.RULE_GROUP_TYPES[group_type]

    def find_rule_groups(self, platform, group_type):
        """
        Returns the names of the Solidcore Rule Groups of a platform
        (SCRuleGroups.WINDOWS or UNIX) and type (SCRuleGroups.APPLICATION_CONTROL,
        CHANGE_CONTROL or INTEGRITY_MONITOR), an empty list when there is none.
        """
        try:
            text = self._text('scor.rulegroup.find', *self._rule_group_args(platform, group_type))
        except EPOError as error:
            # "No rule groups found with type: ..." comes as an error 0.
            if error.code == 0 and 'No rule groups found' in str(error.message):
                return []
            raise
        return [line.strip() for line in text.splitlines() if line.strip()]

    def rule_group_exists(self, platform, group_type, name):
        """
        Returns True if a Solidcore Rule Group of this platform and type
        exists (exact name, case included), e.g. to choose the override
        option of import_rule_groups().
        """
        return name in self.find_rule_groups(platform, group_type)

    def export_rule_group(self, platform, group_type, name):
        """
        Returns a Solidcore Rule Group (SCAWLRuleGroup, SCCCRuleGroup or
        SCFIMRuleGroup), or None if it doesn't exist.
        """
        # Without a known name the server returns the empty "Global Rules"
        # group instead of an error: check the name first.
        if not self.rule_group_exists(platform, group_type, name):
            return None
        text = self._text('scor.rulegroup.export', *self._rule_group_args(platform, group_type),
                          ruleGroupName=name)
        return SCRuleGroups(text.strip().encode('utf-8')).get_rule_group(name)

    def import_rule_groups(self, rule_groups, override=False, file_name='rulegroups.xml'):
        """
        Imports Solidcore Rule Groups (SCRuleGroups) and returns the server
        message.

        :param: override: Replace the existing Rule Groups with the same name;
                          without it, the import of an existing Rule Group fails.
        :param: file_name: The file name sent with the upload.
        :raise: EPOError: The server answered "not imported successfully".
        """
        # The answer is JSON: {"success": true, "message": "success::::Rule
        # groups were imported successfully.</br>..."} (checked on the lab).
        text = self._text('scor.rulegroup.import', override=override,
                          files={'file': (file_name, rule_groups.get_xml_content())}).strip()
        # A refused import (e.g. an existing Rule Group without override) also
        # comes with "success": true: "Rule groups were not imported successfully...".
        if 'not imported successfully' in text:
            # The message already points to the server task log.
            raise EPOError('scor.rulegroup.import', text)
        return text

    def rename_rule_group(self, platform, group_type, name, new_name):
        """
        Renames a Solidcore Rule Group and returns the server message; ePO
        also renames it in the policies that use it (a few minutes later).
        """
        return self._text('scor.rulegroup.rename', *self._rule_group_args(platform, group_type),
                          name, new_name).strip()
