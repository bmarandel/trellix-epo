# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the ePO client tasks (Client Task Catalog) as objects,
to read the file of clienttask.export and to write the file of
clienttask.importClientTask (see the epoclienttasks module for the
commands, epo.client_tasks).

Each task type the library supports has its class, with the options of the
console page and its rules (check()):

- Trellix Agent: Product Deployment (TADeploymentTask), Product Update
  (TAUpdateTask);
- System Information Reporter: File Assembly Task (File Retrieval Task
  before SIR extension 1.0.7) (SIRFileRetrievalTask);
- Solidcore: the 11 "SC:" task types (SCEnableTask, SCRunCommandsTask...).

Any other task type is kept as ClientTask, its sections and settings
unchanged.

>>> task = SCRunCommandsTask('Show status', ['status', 'config show'])
>>> tasks = ClientTaskList()
>>> tasks.add(task)
>>> b'<Setting name="cmd_2" value="config show" />' in tasks.get_xml_content()
True

A task has no schedule and no assignment in the file: the Web API has no
command to assign or schedule a client task, this is done in the console
(Assigned Client Tasks of a System Tree group). An imported task replaces
the task of the same product, type and name, and keeps its id and its
assignments (checked on ePO 5.10 Update 7).
"""

import re
import xml.etree.ElementTree as et

from .policies import Policy
from .repository import BRANCHES, LANGUAGES, PLATFORMS, Package
from .validators import check_int, check_length

# Namespace of the root element of the export.
NAMESPACE = 'mcafee-epo-task'

# Console limits of every task page (Task Name and Description).
MAX_TASK_NAME = 149
MAX_DESCRIPTION = 250

# Line end the server writes after the XML declaration and after the root
# element (the rest of the file is on one line).
_EOL = '\r\n'


def _attr(value):
    """
    Returns an attribute value escaped as the clienttask.export writes it:
    &, <, >, " as entities and the line feeds as &#xA; (the other
    characters, accents included, are written as they are).

    >>> _attr('Claude <Test> & "co"')
    'Claude &lt;Test&gt; &amp; &quot;co&quot;'
    >>> _attr('C:\\\\A\\nC:\\\\B')
    'C:\\\\A&#xA;C:\\\\B'
    """
    return (value.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;').replace('\r', '&#xD;').replace('\n', '&#xA;')
            .replace('\t', '&#x9;'))


def _sort_key(name):
    """
    Returns the sort key of a section or setting name, in the order of the
    export (the order of the ePO database: no case, "_" before the letters
    and digits).

    >>> sorted(['UpdateAll', 'Update_2', 'NumOfUpdates', 'Update_1'], key=_sort_key)
    ['NumOfUpdates', 'Update_1', 'Update_2', 'UpdateAll']
    """
    return name.lower().replace('_', '\x01')


def _yes_no(value):
    """
    Returns the "yes" / "no" of a Solidcore task setting.

    >>> _yes_no(True), _yes_no(False)
    ('yes', 'no')
    """
    return 'yes' if value else 'no'


def _one_zero(value):
    """
    Returns the "1" / "0" of a Trellix Agent or SIR task setting.

    >>> _one_zero(True), _one_zero(False)
    ('1', '0')
    """
    return '1' if value else '0'


class ClientTask():
    """
    A client task of the Client Task Catalog: its name, description,
    product, type, platforms and the settings of its sections, as the
    export writes them. The typed classes (TADeploymentTask...) add the
    options of their console page; a task of another type is read and
    written back unchanged.

    >>> task = ClientTask('Collect All', 'EPOAGENTMETA', 'Statistics',
    ...                   sections={'General': {'TaskType': 'Statistics'}})
    >>> task
    <ClientTask EPOAGENTMETA/Statistics Collect All>
    >>> task.get_setting('General', 'TaskType')
    'Statistics'
    """

    # Product id and type id of the export for the typed classes.
    PRODUCT_ID = None
    TYPE_ID = None
    # Console labels: product and task type as the Client Task Catalog
    # shows them (Client Task Types tree).
    LABELS = None
    # Former labels of the task type (an older extension of the product).
    OLD_TYPE_LABELS = ()
    # Sections and settings of a new task, as the console saves it.
    DEFAULTS = {}

    def __init__(self, name, product_id=None, type_id=None, description='', platform='',
                 sections=None, server_id='', flag='0'):
        """
        :param: name: The task name.
        :param: product_id: The product id of the export (e.g. EPOAGENTMETA),
                            given by the typed classes.
        :param: type_id: The type id of the export (e.g. Deployment), given
                         by the typed classes.
        :param: description: The task description.
        :param: platform: The platform attribute (Product Deployment only).
        :param: sections: {section: {setting: value}}; the defaults of the
                          class when None.
        :param: server_id: The ePO server of the export (the import ignores it).
        :param: flag: The taskobjectflag attribute of the export.
        """
        self.name = name
        self.product_id = product_id or self.PRODUCT_ID
        self.type_id = type_id or self.TYPE_ID
        self.description = description
        self.platform = platform
        self.server_id = server_id
        self.flag = flag
        if sections is None:
            sections = self.DEFAULTS
        self.sections = {section: dict(settings) for section, settings in sections.items()}

    def __repr__(self):
        """
        Shows the product, the type and the name.
        """
        return '<{} {}/{} {}>'.format(type(self).__name__, self.product_id, self.type_id,
                                      self.name)

    @property
    def key(self):
        """
        The key of the task for the import: (product id, type id, name). The
        import replaces the task of this key.

        >>> SCPullInventoryTask('Pull').key
        ('SOLIDCORE_META', 'Pull Inventory', 'Pull')
        """
        return self.product_id, self.type_id, self.name

    @property
    def labels(self):
        """
        The product and task type as the console shows them, or the ids of
        the export for a type the library doesn't know.

        >>> SIRFileRetrievalTask('Acquire').labels
        ('System Information Reporter', 'File Assembly Task')
        """
        return self.LABELS or (self.product_id, self.type_id)

    def is_type_name(self, type_name):
        """
        Returns True when a typeName of clienttask.find ("<product>: <task
        type>", e.g. "Solidcore 8.4.5: SC: Enable") is the type of the task:
        its label or a former one. Always True for a type the library
        doesn't know (no label to compare).

        >>> task = SIRFileRetrievalTask('Acquire')
        >>> task.is_type_name('System Information Reporter: File Retrieval Task')
        True
        >>> task.is_type_name('System Information Reporter: Other Task')
        False
        """
        if not self.LABELS:
            return True
        return any(type_name.endswith(': ' + label)
                   for label in (self.LABELS[1],) + tuple(self.OLD_TYPE_LABELS))

    # ------------------------------ Settings ------------------------------
    def get_setting(self, section, setting, default=None):
        """
        Returns the value of a setting, or default when it is missing.

        >>> SCDisableTask('D').get_setting('General_1', 'req')
        'disable'
        """
        return self.sections.get(section, {}).get(setting, default)

    def set_setting(self, section, setting, value):
        """
        Sets the value of a setting (the section is created if needed).

        >>> task = SCDisableTask('D')
        >>> task.set_setting('General_1', 'req', 'disable')
        >>> task.get_setting('General_1', 'req')
        'disable'
        """
        self.sections.setdefault(section, {})[setting] = value

    def remove_setting(self, section, setting):
        """
        Removes a setting if it exists.

        >>> task = SCBeginUpdateTask('U')
        >>> task.remove_setting('General_1', 'comment')
        >>> task.get_setting('General_1', 'comment') is None
        True
        """
        self.sections.get(section, {}).pop(setting, None)

    # ------------------------------ Checks ------------------------------
    def check(self):
        """
        Checks the task against the console rules of its page and raises
        ValueError for the first error found (the name and description for
        a type the library doesn't know).

        Valid / invalid (a name longer than the console field):

        >>> ClientTask('Collect All', 'EPOAGENTMETA', 'Statistics').check()
        >>> ClientTask('x' * 150, 'EPOAGENTMETA', 'Statistics').check()
        Traceback (most recent call last):
        ...
        ValueError: Task Name: 149 characters max (150 given).
        """
        check_length('Task Name', self.name, MAX_TASK_NAME, required=True)
        check_length('Description', self.description, MAX_DESCRIPTION)
        if not self.product_id or not self.type_id:
            raise ValueError('Task "{}": the product id and the type id are required.'.format(
                self.name))

    # ------------------------------ XML ------------------------------
    def to_xml(self):
        """
        Returns the EPOTaskObjectInstance element as the export writes it
        (sections and settings sorted as the server does).

        >>> print(SCEndUpdateTask('End').to_xml())   # doctest: +NORMALIZE_WHITESPACE
        <EPOTaskObjectInstance name="End" serverid="" productid="SOLIDCORE_META"
        typeid="Close Update Window" platform="" description="" taskobjectflag="0"><Section
        name="General_1"><Setting name="handler" value="mapl" /><Setting name="req" value="eu"
        /><Setting name="requires_response" value="yes" /></Section></EPOTaskObjectInstance>
        """
        text = ('<EPOTaskObjectInstance name="{}" serverid="{}" productid="{}" typeid="{}" '
                'platform="{}" description="{}" taskobjectflag="{}">'.format(
                    _attr(self.name), _attr(self.server_id), _attr(self.product_id),
                    _attr(self.type_id), _attr(self.platform), _attr(self.description),
                    _attr(self.flag)))
        for section in sorted(self.sections, key=_sort_key):
            text += '<Section name="{}">'.format(_attr(section))
            settings = self.sections[section]
            for setting in sorted(settings, key=_sort_key):
                text += '<Setting name="{}" value="{}" />'.format(_attr(setting),
                                                                 _attr(settings[setting]))
            text += '</Section>'
        return text + '</EPOTaskObjectInstance>'

    @staticmethod
    def from_element(element):
        """
        Returns the task of an EPOTaskObjectInstance element: an object of
        the class of its product and type (TASK_CLASSES), or a ClientTask.

        >>> element = et.fromstring('<EPOTaskObjectInstance name="P" serverid="S" '
        ...     'productid="SOLIDCORE_META" typeid="Pull Inventory" platform="" description="" '
        ...     'taskobjectflag="0"><Section name="General_1"><Setting name="req" '
        ...     'value="PullInventory" /></Section></EPOTaskObjectInstance>')
        >>> ClientTask.from_element(element)
        <SCPullInventoryTask SOLIDCORE_META/Pull Inventory P>
        """
        product_id, type_id = element.get('productid', ''), element.get('typeid', '')
        cls = TASK_CLASSES.get((product_id, type_id), ClientTask)
        task = cls.__new__(cls)
        sections = {}
        for section in element.findall('Section'):
            sections[section.get('name')] = {setting.get('name'): setting.get('value', '')
                                             for setting in section.findall('Setting')}
        ClientTask.__init__(task, element.get('name', ''), product_id, type_id,
                            description=element.get('description', ''),
                            platform=element.get('platform', ''), sections=sections,
                            server_id=element.get('serverid', ''),
                            flag=element.get('taskobjectflag', '0'))
        return task

    # ------------------------------ Markdown ------------------------------
    def md_rows(self):
        """
        Returns the options of the task for the Markdown export, as
        (label, value) pairs: the settings of each section for a type the
        library doesn't know (the typed classes give the console labels).

        >>> ClientTask('C', 'P', 'T', sections={'General': {'TaskType': 'T'}}).md_rows()
        [('General / TaskType', 'T')]
        """
        return [('{} / {}'.format(section, setting), self.sections[section][setting])
                for section in sorted(self.sections, key=_sort_key)
                for setting in sorted(self.sections[section], key=_sort_key)]

    def to_markdown(self, labels=True):
        """
        Returns the task as Markdown: a heading with its name, its product
        and type (unless labels is False: ClientTaskList.to_markdown() gives
        them as group headings), its description and a table of its options.

        >>> print(SCDisableTask('Disable', reboot=False).to_markdown())
        ### Disable
        <BLANKLINE>
        Solidcore / SC: Disable
        <BLANKLINE>
        | Option | Value |
        |---|---|
        | Reboot endpoint | No |
        """
        lines = ['### {}'.format(Policy.md_heading(self.name))]
        if labels:
            lines += ['', '{} / {}'.format(*(Policy.md_heading(label) for label in self.labels))]
        if self.description:
            lines += ['', Policy.md_escape(self.description)]
        rows = self.md_rows()
        if rows:
            lines += ['', '| Option | Value |', '|---|---|']
            lines += ['| {} | {} |'.format(Policy.md_escape(label), Policy.md_escape(value))
                      for label, value in rows]
        return '\n'.join(lines)

    @staticmethod
    def md_bool(value):
        """
        Returns Yes or No for a check box.

        >>> ClientTask.md_bool(True), ClientTask.md_bool(False)
        ('Yes', 'No')
        """
        return 'Yes' if value else 'No'


# ======================================================================================
# Trellix Agent
# ======================================================================================

# PLATFORMS, LANGUAGES and BRANCHES (shared with the Main Repository
# packages) are in the repository module.

# Console limits of the Product Deployment and Product Update pages.
MAX_COMMAND_LINE = 254
MAX_POSTPONES = 999
MAX_POSTPONE_TIMEOUT = 999
MAX_POSTPONE_TEXT = 2047


def _check_postpone(task):
    """
    Checks the "Postpone" options of a Trellix Agent task (Product
    Deployment, Product Update): 1 to 999 postpones, 1 to 999 seconds, a
    text of 2047 characters at most. The console checks them while the
    option is enabled, and saves them even when it is not.

    Valid / invalid (no postpone allowed):

    >>> _check_postpone(TAUpdateTask('U', show_progress=True, allow_postpone=True))
    >>> _check_postpone(TAUpdateTask('U', show_progress=True, allow_postpone=True,
    ...                              max_postpones=0))
    Traceback (most recent call last):
    ...
    ValueError: Maximum number of postpones allowed: enter a number between 1 and 999: 0
    """
    check_int('Maximum number of postpones allowed', task.max_postpones, 1, MAX_POSTPONES)
    check_int('Option to postpone expires after (seconds)', task.postpone_timeout, 1,
              MAX_POSTPONE_TIMEOUT)
    check_length('Display this text', task.postpone_text, MAX_POSTPONE_TEXT)


class _PostponeTask(ClientTask):
    """
    Base class of the Trellix Agent tasks with the "Postpone" options
    (UpdateOptions section): TADeploymentTask and TAUpdateTask.
    """

    @property
    def allow_postpone(self):
        """
        "Allow end users to postpone" (bAllowPostpone).

        >>> TADeploymentTask('D', allow_postpone=True).allow_postpone
        True
        """
        return self.get_setting('UpdateOptions', 'bAllowPostpone') == '1'

    @allow_postpone.setter
    def allow_postpone(self, value):
        """
        Sets "Allow end users to postpone".
        """
        self.set_setting('UpdateOptions', 'bAllowPostpone', _one_zero(value))

    @property
    def max_postpones(self):
        """
        "Maximum number of postpones allowed" (nMaxPostpones, 1 to 999).

        >>> TADeploymentTask('D').max_postpones
        1
        """
        return int(self.get_setting('UpdateOptions', 'nMaxPostpones', '1') or 0)

    @max_postpones.setter
    def max_postpones(self, value):
        """
        Sets "Maximum number of postpones allowed".
        """
        self.set_setting('UpdateOptions', 'nMaxPostpones', str(value))

    @property
    def postpone_timeout(self):
        """
        "Option to postpone expires after (seconds)" (nPostponeTimeout, 1 to 999).

        >>> TADeploymentTask('D').postpone_timeout
        20
        """
        return int(self.get_setting('UpdateOptions', 'nPostponeTimeout', '20') or 0)

    @postpone_timeout.setter
    def postpone_timeout(self, value):
        """
        Sets "Option to postpone expires after (seconds)".
        """
        self.set_setting('UpdateOptions', 'nPostponeTimeout', str(value))

    @property
    def postpone_text(self):
        """
        "Display this text" (szPostponeText, 2047 characters at most).

        >>> TADeploymentTask('D', postpone_text='Save your work').postpone_text
        'Save your work'
        """
        return self.get_setting('UpdateOptions', 'szPostponeText', '')

    @postpone_text.setter
    def postpone_text(self, value):
        """
        Sets "Display this text".
        """
        self.set_setting('UpdateOptions', 'szPostponeText', value)

    def _set_postpone(self, allow_postpone, max_postpones, postpone_timeout, postpone_text):
        """
        Sets the postpone options given to a constructor (None keeps the
        default of the console).

        >>> task = TADeploymentTask('D')
        >>> task._set_postpone(True, 3, None, None)
        >>> task.allow_postpone, task.max_postpones, task.postpone_timeout
        (True, 3, 20)
        """
        for name, value in (('allow_postpone', allow_postpone), ('max_postpones', max_postpones),
                            ('postpone_timeout', postpone_timeout),
                            ('postpone_text', postpone_text)):
            if value is not None:
                setattr(self, name, value)

    def _md_postpone(self, label):
        """
        Returns the Markdown rows of the postpone options; label is the name
        of the console box ("Postpone Deployment" or "Update in Progress").

        >>> TADeploymentTask('D')._md_postpone('Postpone Deployment')
        [('Postpone Deployment: allow end users to postpone', 'No')]
        """
        rows = [('{}: allow end users to postpone'.format(label),
                 ClientTask.md_bool(self.allow_postpone))]
        if self.allow_postpone:
            rows += [('Maximum number of postpones allowed', self.max_postpones),
                     ('Option to postpone expires after (seconds)', self.postpone_timeout),
                     ('Display this text', self.postpone_text or '-')]
        return rows


class DeploymentItem():
    """
    A line of "Products and components" of a Product Deployment task: a
    package to install or remove.

    >>> item = DeploymentItem('SIR_____1000', '1.0.3252', product_name='SystemInformationReporter')
    >>> item
    <DeploymentItem Install SIR_____1000 1.0.3252 (Current, 0409)>
    """

    ACTIONS = ('Install', 'Remove')

    def __init__(self, product_id, version, action='Install', language='0409', branch='Current',
                 command_line='', product_name=''):
        """
        :param: product_id: The package product id, e.g. SIR_____1000.
        :param: version: The package version as the task writes it
                         (BuildVersion): the product version followed by
                         the build number, e.g. 1.0.3252 for 1.0.3 build 252
                         (see from_package()).
        :param: action: Install or Remove.
        :param: language: The language code of the package (LANGUAGES):
                          0409 (English) or 0000 (Language Neutral) for most
                          packages.
        :param: branch: The repository branch: Current, Previous or Evaluation.
        :param: command_line: The "Command line" of the line (254 characters
                              at most).
        :param: product_name: The package name without spaces, as the
                              console writes it (e.g. SystemInformationReporter).
        """
        self.product_id = product_id
        self.version = version
        self.action = action
        self.language = language
        self.branch = branch
        self.command_line = command_line
        self.product_name = product_name

    def __repr__(self):
        """
        Shows the action, the package and its branch and language.
        """
        return '<DeploymentItem {} {} {} ({}, {})>'.format(self.action, self.product_id,
                                                           self.version, self.branch,
                                                           self.language)

    def __eq__(self, other):
        """
        Two lines are equal when all their options are.
        """
        return isinstance(other, DeploymentItem) and vars(self) == vars(other)

    @classmethod
    def from_package(cls, package, action='Install', command_line=''):
        """
        Returns the line of a package of the Main Repository (a Package of
        epo.repository.packages(), or a line of repository.findPackages):
        its product id, version (Package.build_version, as the console
        writes it), language, branch and name.

        >>> DeploymentItem.from_package(Package('SIR_____1000', 'System Information Reporter',
        ...                                     '1.0.3', '252', language='0409'))
        <DeploymentItem Install SIR_____1000 1.0.3252 (Current, 0409)>
        """
        if isinstance(package, dict):
            package = Package.from_json(package)
        return cls(package.product_id, package.build_version, action=action,
                   language=package.language, branch=package.branch or 'Current',
                   command_line=command_line, product_name=package.name.replace(' ', ''))

    def check(self):
        """
        Checks the line against the console rules: an action, a known
        language and branch, a command line of 254 characters at most.

        Valid / invalid (unknown branch):

        >>> DeploymentItem('SIR_____1000', '1.0.3252').check()
        >>> DeploymentItem('SIR_____1000', '1.0.3252', branch='Test').check()
        Traceback (most recent call last):
        ...
        ValueError: SIR_____1000: the branch must be one of ('Current', 'Previous', 'Evaluation').
        """
        if not self.product_id or not self.version:
            raise ValueError('A product line needs a product id and a version.')
        if self.action not in self.ACTIONS:
            raise ValueError('{}: the action must be Install or Remove.'.format(self.product_id))
        if self.language not in LANGUAGES:
            raise ValueError('{}: unknown language code {!r} (see LANGUAGES).'.format(
                self.product_id, self.language))
        if self.branch not in BRANCHES:
            raise ValueError('{}: the branch must be one of {}.'.format(self.product_id,
                                                                        BRANCHES))
        check_length('Command line', self.command_line, MAX_COMMAND_LINE)


class TADeploymentTask(_PostponeTask):
    """
    Trellix Agent: Product Deployment. Installs or removes packages of the
    repository on the systems of the selected platforms.

    >>> task = TADeploymentTask('Install SIR', [DeploymentItem('SIR_____1000', '1.0.3252')])
    >>> task.platforms, task.products
    (['Windows'], [<DeploymentItem Install SIR_____1000 1.0.3252 (Current, 0409)>])

    The server keeps the sections of the lines removed in the console (only
    the counts change): the library reads the counts and writes the lines
    again from scratch.
    """

    PRODUCT_ID = 'EPOAGENTMETA'
    TYPE_ID = 'Deployment'
    LABELS = ('Trellix Agent', 'Product Deployment')
    DEFAULTS = {
        'AutoUpdateOption': {'AutoUpdateEnabled': '0'},
        'DeploymentOptions': {'DummyPolicy': '0', 'UpdateAfterDeployment': '0'},
        'General': {'TaskType': 'Deployment'},
        'Install': {'NumInstalls': '0'},
        'SchedulerExtraData': {'RunAtEnforcementEnabled': '0'},
        'Settings': {'RunAtEnforcementEnabled': '0'},
        'Uninstall': {'NumUninstalls': '0'},
        'UpdateOptions': {'bAllowPostpone': '0', 'nMaxPostpones': '1', 'nPostponeTimeout': '20',
                          'szPostponeText': ''},
    }

    def __init__(self, name, products=None, platforms=('Windows',), description='',
                 auto_update=False, allow_postpone=None, max_postpones=None,
                 postpone_timeout=None, postpone_text=None):
        """
        :param: name: The task name.
        :param: products: The DeploymentItem lines.
        :param: platforms: The target platforms (labels of PLATFORMS);
                           Windows only for a new task in the console.
        :param: description: The task description.
        :param: auto_update: "Automatically deploy latest version of the products".
        :param: allow_postpone, max_postpones, postpone_timeout, postpone_text:
                The "Postpone Deployment" options (console defaults: not
                allowed, 1 postpone, 20 seconds, no text).
        """
        super(TADeploymentTask, self).__init__(name, description=description)
        self.platforms = list(platforms)
        self.products = list(products or [])
        self.auto_update = auto_update
        self._set_postpone(allow_postpone, max_postpones, postpone_timeout, postpone_text)

    @property
    def platforms(self):
        """
        The target platforms checked in the console (labels of PLATFORMS):
        the platforms with a code in the platform attribute. The tasks that
        the server creates when a package is checked in can have part of the
        codes of a platform (e.g. WVST|...|WINXS for Windows): the console
        checks the platform (checked on ePO 5.10 Update 7).

        >>> TADeploymentTask('D', platforms=['Linux', 'Windows']).platforms
        ['Windows', 'Linux']
        >>> task = TADeploymentTask('D')
        >>> task.platform = 'WVST|WVSTS|WNT7W|WIN8W|WIN8S|WINXW|WINXS'
        >>> task.platforms
        ['Windows']
        """
        codes = set(self.platform.split('|')) if self.platform else set()
        return [label for label, family in PLATFORMS.items()
                if set(family.split('|')) & codes]

    @platforms.setter
    def platforms(self, labels):
        """
        Sets the target platforms (labels of PLATFORMS, written in the order
        of the console).

        >>> task = TADeploymentTask('D', platforms=['Mac', 'Windows'])
        >>> task.platform.endswith('|WINXW|WINXS|MAC')
        True
        >>> task.platforms = ['Android']
        Traceback (most recent call last):
        ...
        ValueError: Unknown platform 'Android' (see PLATFORMS).
        """
        for label in labels:
            if label not in PLATFORMS:
                raise ValueError('Unknown platform {!r} (see PLATFORMS).'.format(label))
        self.platform = '|'.join(family for label, family in PLATFORMS.items() if label in labels)

    @property
    def auto_update(self):
        """
        "Automatically deploy latest version of the products" (AutoUpdateEnabled).

        >>> TADeploymentTask('D').auto_update
        False
        """
        return self.get_setting('AutoUpdateOption', 'AutoUpdateEnabled') == '1'

    @auto_update.setter
    def auto_update(self, value):
        """
        Sets "Automatically deploy latest version of the products".
        """
        self.set_setting('AutoUpdateOption', 'AutoUpdateEnabled', _one_zero(value))

    def _read_items(self, section, count, item, action):
        """
        Returns the lines of one action: the count setting of the section
        (NumInstalls, NumUninstalls) gives the number of lines, item_N the
        product ids, the "<section>\\<product id>" sections their options
        (stale lines after the count are ignored).

        >>> task = TADeploymentTask('D', [DeploymentItem('A', '1.0', action='Remove')])
        >>> task._read_items('Uninstall', 'NumUninstalls', 'Uninstall_{}', 'Remove')
        [<DeploymentItem Remove A 1.0 (Current, 0409)>]
        """
        items = []
        for index in range(1, int(self.get_setting(section, count, '0') or 0) + 1):
            product_id = self.get_setting(section, item.format(index))
            options = self.sections.get('{}\\{}'.format(section, product_id), {})
            name = options.get('ProductName') or self.get_setting(
                'ProductName', 'ProductName__{}_{}'.format(action, index), '')
            items.append(DeploymentItem(product_id, options.get('BuildVersion', ''), action,
                                        options.get('Language', '0000'),
                                        options.get('PackagePathType', 'Current'),
                                        options.get('InstallCommandLine', ''), name))
        return items

    @property
    def products(self):
        """
        The "Products and components" lines: the Install lines, then the
        Remove lines (the export doesn't keep the order of the console).

        >>> task = TADeploymentTask('D', [DeploymentItem('B', '2.0', action='Remove'),
        ...                               DeploymentItem('A', '1.0')])
        >>> [(item.action, item.product_id) for item in task.products]
        [('Install', 'A'), ('Remove', 'B')]
        """
        return (self._read_items('Install', 'NumInstalls', 'Install_{}', 'Install') +
                self._read_items('Uninstall', 'NumUninstalls', 'Uninstall_{}', 'Remove'))

    @products.setter
    def products(self, items):
        """
        Writes the lines as the console saves them: the Install and
        Uninstall sections (counts and product ids), one section per
        package, and the ProductName section when the names are known. The
        sections of the previous lines are removed.

        >>> task = TADeploymentTask('D')
        >>> task.products = [DeploymentItem('SIR_____1000', '1.0.3252',
        ...                                 product_name='SystemInformationReporter')]
        >>> task.sections['Install'], task.sections['ProductName']
        ({'Install_1': 'SIR_____1000', 'NumInstalls': '1'}, {'ProductName__Install_1': 'SystemInformationReporter'})
        """
        for section in list(self.sections):
            if section in ('Install', 'Uninstall', 'ProductName') or \
                    section.startswith(('Install\\', 'Uninstall\\')):
                del self.sections[section]
        installs = [item for item in items if item.action == 'Install']
        removes = [item for item in items if item.action != 'Install']
        names = {}
        for section, count, key, action, lines in (
                ('Install', 'NumInstalls', 'Install', 'Install', installs),
                ('Uninstall', 'NumUninstalls', 'Uninstall', 'Remove', removes)):
            self.sections[section] = {count: str(len(lines))}
            for index, item in enumerate(lines, 1):
                self.sections[section]['{}_{}'.format(key, index)] = item.product_id
                options = {'BuildVersion': item.version, 'InstallCommandLine': item.command_line,
                           'Language': item.language, 'PackagePathType': item.branch}
                if item.product_name:
                    options['ProductName'] = item.product_name
                    names['ProductName__{}_{}'.format(action, index)] = item.product_name
                self.sections['{}\\{}'.format(section, item.product_id)] = options
        if names:
            self.sections['ProductName'] = names

    def check(self):
        """
        Checks the task against the rules of the console page: a platform
        and a product at least, each package once, valid lines, the postpone
        options, and "Automatically deploy latest version" only with Install
        lines of the Current branch.

        Valid / invalid (automatic update with a Remove line):

        >>> TADeploymentTask('D', [DeploymentItem('A', '1.0')], auto_update=True).check()
        >>> TADeploymentTask('D', [DeploymentItem('A', '1.0', action='Remove')],
        ...                  auto_update=True).check()
        Traceback (most recent call last):
        ...
        ValueError: Task "D": "Automatically deploy latest version of the products" can't be used with a Remove line.
        """
        super(TADeploymentTask, self).check()
        if not self.platforms:
            raise ValueError('Task "{}": select a target platform.'.format(self.name))
        products = self.products
        if not products:
            raise ValueError('Task "{}": add a product to deploy.'.format(self.name))
        codes = [item.product_id for item in products]
        if len(set(codes)) != len(codes):
            raise ValueError('Task "{}": a package can be selected once only.'.format(self.name))
        for item in products:
            item.check()
        if self.auto_update:
            if any(item.action == 'Remove' for item in products):
                raise ValueError('Task "{}": "Automatically deploy latest version of the '
                                 'products" can\'t be used with a Remove line.'.format(self.name))
            if any(item.branch != 'Current' for item in products):
                raise ValueError('Task "{}": "Automatically deploy latest version of the '
                                 'products" needs the Current branch.'.format(self.name))
        _check_postpone(self)

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> TADeploymentTask('D', [DeploymentItem('A', '1.0')]).md_rows()[:3]
        [('Target platforms', 'Windows'), ('Auto Update', 'No'), ('Products and components', 'Install A 1.0 (English, Current)')]
        """
        lines = []
        for item in self.products:
            line = '{} {} {} ({}, {})'.format(item.action, item.product_name or item.product_id,
                                              item.version, LANGUAGES.get(item.language,
                                                                          item.language),
                                              item.branch)
            if item.command_line:
                line += ', command line: {}'.format(item.command_line)
            lines.append(line)
        rows = [('Target platforms', ', '.join(self.platforms) or self.platform or '-'),
                ('Auto Update', self.md_bool(self.auto_update)),
                ('Products and components', '\n'.join(lines) or '-')]
        return rows + self._md_postpone('Postpone Deployment')


# Package checked by the console with the Engine only: the Engine
# (VSCANENG1000) can't be selected without the DAT (VSCANDAT1000).
ENGINE_PACKAGE = 'VSCANENG1000'
DAT_PACKAGE = 'VSCANDAT1000'


class TAUpdateTask(_PostponeTask):
    """
    Trellix Agent: Product Update. Updates all the packages of the
    repository, or the selected ones (signatures, engines, patches...).

    >>> TAUpdateTask('Update All').packages is None
    True
    >>> TAUpdateTask('DAT', ['VSCANDAT1000', 'AMCORDAT2000']).packages
    ['VSCANDAT1000', 'AMCORDAT2000']
    """

    PRODUCT_ID = 'EPOAGENTMETA'
    TYPE_ID = 'Update'
    LABELS = ('Trellix Agent', 'Product Update')
    DEFAULTS = {
        'General': {'TaskType': 'Update'},
        'InetManager': {'EnabledSites': '', 'EnabledSitesNum': '0',
                        'RegenerateCacheEnabled': '0', 'szRegenerateCacheTimoutMins': '0'},
        'SelectedUpdates': {'NumOfUpdates': '0', 'UpdateAll': '1'},
        'UpdateOptions': {'bAllowPostpone': '0', 'bShowUI': '0', 'nMaxPostpones': '1',
                          'nPostponeTimeout': '20', 'szPostponeText': ''},
    }

    def __init__(self, name, packages=None, description='', show_progress=False,
                 allow_postpone=None, max_postpones=None, postpone_timeout=None,
                 postpone_text=None):
        """
        :param: name: The task name.
        :param: packages: The product ids of the selected packages
                          ("Selected packages"), or None for "All packages".
        :param: description: The task description.
        :param: show_progress: Show the "Update in Progress" dialog box
                               (Windows systems), needed to allow postponing.
        :param: allow_postpone, max_postpones, postpone_timeout, postpone_text:
                The postpone options (console defaults: not allowed, 1
                postpone, 20 seconds, no text).
        """
        super(TAUpdateTask, self).__init__(name, description=description)
        self.packages = packages
        self.show_progress = show_progress
        self._set_postpone(allow_postpone, max_postpones, postpone_timeout, postpone_text)

    @property
    def show_progress(self):
        """
        Show "Update in Progress" dialog box on managed systems (bShowUI).

        >>> TAUpdateTask('U', show_progress=True).show_progress
        True
        """
        return self.get_setting('UpdateOptions', 'bShowUI') == '1'

    @show_progress.setter
    def show_progress(self, value):
        """
        Sets "Show Update in Progress dialog box".
        """
        self.set_setting('UpdateOptions', 'bShowUI', _one_zero(value))

    @property
    def packages(self):
        """
        The product ids of the selected packages, or None for "All packages".

        >>> TAUpdateTask('U', ['AMCORDAT2000']).packages
        ['AMCORDAT2000']
        """
        if self.get_setting('SelectedUpdates', 'UpdateAll') == '1':
            return None
        count = int(self.get_setting('SelectedUpdates', 'NumOfUpdates', '0') or 0)
        return [self.get_setting('SelectedUpdates', 'Update_{}'.format(index))
                for index in range(1, count + 1)]

    @packages.setter
    def packages(self, codes):
        """
        Writes the package selection as the console saves it: UpdateAll,
        NumOfUpdates, Update_N and one "SelectedUpdates\\<product id>"
        section per package (Update=1). The previous selection is removed.

        >>> task = TAUpdateTask('U', ['VSCANDAT1000'])
        >>> task.sections['SelectedUpdates'], task.sections['SelectedUpdates\\\\VSCANDAT1000']
        ({'NumOfUpdates': '1', 'UpdateAll': '0', 'Update_1': 'VSCANDAT1000'}, {'Update': '1'})
        """
        for section in list(self.sections):
            if section.startswith('SelectedUpdates\\'):
                del self.sections[section]
        if codes is None:
            self.sections['SelectedUpdates'] = {'NumOfUpdates': '0', 'UpdateAll': '1'}
            return
        codes = list(codes)
        self.sections['SelectedUpdates'] = {'NumOfUpdates': str(len(codes)), 'UpdateAll': '0'}
        for index, code in enumerate(codes, 1):
            self.sections['SelectedUpdates']['Update_{}'.format(index)] = code
            self.sections['SelectedUpdates\\{}'.format(code)] = {'Update': '1'}

    def check(self):
        """
        Checks the task against the rules of the console page: a package at
        least when they are selected, each package once, the Engine with
        the DAT only, the postpone options, and postponing only with the
        "Update in Progress" dialog box.

        Valid / invalid (the Engine without the DAT):

        >>> TAUpdateTask('U', ['VSCANENG1000', 'VSCANDAT1000']).check()
        >>> TAUpdateTask('U', ['VSCANENG1000']).check()
        Traceback (most recent call last):
        ...
        ValueError: Task "U": the Engine (VSCANENG1000) can be selected with the DAT (VSCANDAT1000) only.
        """
        super(TAUpdateTask, self).check()
        packages = self.packages
        if packages is not None:
            if not packages:
                raise ValueError('Task "{}": select a package (or all packages).'.format(
                    self.name))
            if len(set(packages)) != len(packages):
                raise ValueError('Task "{}": a package can be selected once only.'.format(
                    self.name))
            if ENGINE_PACKAGE in packages and DAT_PACKAGE not in packages:
                raise ValueError('Task "{}": the Engine ({}) can be selected with the DAT ({}) '
                                 'only.'.format(self.name, ENGINE_PACKAGE, DAT_PACKAGE))
        if self.allow_postpone and not self.show_progress:
            raise ValueError('Task "{}": postponing needs the "Update in Progress" dialog '
                             'box.'.format(self.name))
        _check_postpone(self)

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> TAUpdateTask('U', ['VSCANDAT1000']).md_rows()
        [('Update in Progress dialog box', 'No'), ('Package selection', 'Selected packages: VSCANDAT1000')]
        """
        packages = self.packages
        rows = [('Update in Progress dialog box', self.md_bool(self.show_progress))]
        if self.show_progress:
            rows += self._md_postpone('Update in Progress')
        rows.append(('Package selection', 'All packages' if packages is None else
                     'Selected packages: ' + ', '.join(str(code) for code in packages)))
        return rows


# ======================================================================================
# System Information Reporter
# ======================================================================================

class SIRFileRetrievalTask(ClientTask):
    """
    System Information Reporter: File Assembly Task ("File Retrieval Task"
    before SIR extension 1.0.7.70, same type id and settings). Retrieves
    files or folders from the systems (one path per line).

    >>> task = SIRFileRetrievalTask('Acquire', ['C:\\\\Quarantine'], include_subfolders=True)
    >>> task.sections['SIROPTIONS']
    {'FILESFOLDERSPATH': 'C:\\\\Quarantine', 'INCLUDESUBFOLDERS': '1'}
    """

    PRODUCT_ID = 'SIR_____1000'
    TYPE_ID = 'SIRTask'
    LABELS = ('System Information Reporter', 'File Assembly Task')
    OLD_TYPE_LABELS = ('File Retrieval Task',)
    DEFAULTS = {'SIROPTIONS': {'FILESFOLDERSPATH': '', 'INCLUDESUBFOLDERS': '0'}}

    def __init__(self, name, paths=(), include_subfolders=False, description=''):
        """
        :param: name: The task name.
        :param: paths: The files and folders to retrieve, one per line in
                       the console (the console doesn't check them).
        :param: include_subfolders: "Include subfolders".
        :param: description: The task description.
        """
        super(SIRFileRetrievalTask, self).__init__(name, description=description)
        self.paths = paths
        self.include_subfolders = include_subfolders

    @property
    def paths(self):
        """
        The lines of "File(s) and/or folder(s) retrieval path", as typed in
        the console (the server keeps the blank lines and the spaces).

        >>> SIRFileRetrievalTask('A', ['C:\\\\A', '/var/log']).paths
        ['C:\\\\A', '/var/log']
        """
        text = self.get_setting('SIROPTIONS', 'FILESFOLDERSPATH', '')
        return text.split('\n') if text else []

    @paths.setter
    def paths(self, lines):
        """
        Sets the paths, one per line (written with line feeds).
        """
        self.set_setting('SIROPTIONS', 'FILESFOLDERSPATH', '\n'.join(lines))

    @property
    def include_subfolders(self):
        """
        "Include subfolders" (INCLUDESUBFOLDERS).

        >>> SIRFileRetrievalTask('A').include_subfolders
        False
        """
        return self.get_setting('SIROPTIONS', 'INCLUDESUBFOLDERS') == '1'

    @include_subfolders.setter
    def include_subfolders(self, value):
        """
        Sets "Include subfolders".
        """
        self.set_setting('SIROPTIONS', 'INCLUDESUBFOLDERS', _one_zero(value))

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> SIRFileRetrievalTask('A', ['C:\\\\A']).md_rows()
        [('File(s) and/or folder(s) retrieval path', 'C:\\\\A'), ('Include subfolders', 'No')]
        """
        return [('File(s) and/or folder(s) retrieval path', '\n'.join(self.paths) or '-'),
                ('Include subfolders', self.md_bool(self.include_subfolders))]


# ======================================================================================
# Solidcore
# ======================================================================================

# Section of every Solidcore task.
SC_SECTION = 'General_1'

# Console limits of the Solidcore task pages.
MAX_WORKFLOW_ID = 100
MAX_COMMENT = 100
MAX_COMMAND = 3000


class SCClientTask(ClientTask):
    """
    Base class of the Solidcore client tasks: one section (General_1), the
    request sent to the client (req) and its handler.
    """

    PRODUCT_ID = 'SOLIDCORE_META'

    def __init__(self, name, description=''):
        """
        :param: name: The task name.
        :param: description: The task description.
        """
        super(SCClientTask, self).__init__(name, description=description)

    def _get(self, setting, default=None):
        """
        Returns a setting of the General_1 section.

        >>> SCDisableTask('D')._get('req')
        'disable'
        """
        return self.get_setting(SC_SECTION, setting, default)

    def _set(self, setting, value):
        """
        Sets a setting of the General_1 section.

        >>> task = SCDisableTask('D')
        >>> task._set('reboot_if_required', 'no')
        >>> task._get('reboot_if_required')
        'no'
        """
        self.set_setting(SC_SECTION, setting, value)

    def _flag(self, setting):
        """
        Returns True when a yes/no setting is "yes".

        >>> SCDisableTask('D')._flag('reboot_if_required')
        True
        """
        return self._get(setting) == 'yes'

    @staticmethod
    def _check_workflow(task, workflow_id, comment):
        """
        Checks a Workflow ID and its Comments (Begin Update Mode, Observe
        Mode): 100 characters each, and no comment without a Workflow ID
        ("Cannot enter Comments without Workflow ID.").

        Valid / invalid (a comment alone):

        >>> SCClientTask._check_workflow('T', 'CR-1024', 'Patch Tuesday')
        >>> SCClientTask._check_workflow('T', '', 'Patch Tuesday')
        Traceback (most recent call last):
        ...
        ValueError: Task "T": Cannot enter Comments without Workflow ID.
        """
        check_length('Workflow ID', workflow_id, MAX_WORKFLOW_ID)
        check_length('Comments', comment, MAX_COMMENT)
        if comment and not workflow_id:
            raise ValueError('Task "{}": Cannot enter Comments without Workflow ID.'.format(task))


class SCBeginUpdateTask(SCClientTask):
    """
    Solidcore: SC: Begin Update Mode, with an optional Workflow ID and
    Comments (the changes made in the window are tagged with the Workflow ID).

    >>> SCBeginUpdateTask('Begin', 'CR-1024', 'Patch Tuesday').workflow_id
    'CR-1024'
    """

    TYPE_ID = 'Open Update Window'
    LABELS = ('Solidcore', 'SC: Begin Update Mode')
    DEFAULTS = {SC_SECTION: {'comment': '', 'handler': 'mapl', 'req': 'bu',
                             'requires_response': 'yes', 'workflow_id': ''}}

    def __init__(self, name, workflow_id='', comment='', description=''):
        """
        :param: name: The task name.
        :param: workflow_id: The Workflow ID (100 characters at most).
        :param: comment: The Comments (100 characters at most, with a
                         Workflow ID only).
        :param: description: The task description.
        """
        super(SCBeginUpdateTask, self).__init__(name, description)
        self.workflow_id = workflow_id
        self.comment = comment

    @property
    def workflow_id(self):
        """
        The Workflow ID.

        >>> SCBeginUpdateTask('B').workflow_id
        ''
        """
        return self._get('workflow_id', '')

    @workflow_id.setter
    def workflow_id(self, value):
        """
        Sets the Workflow ID.
        """
        self._set('workflow_id', value)

    @property
    def comment(self):
        """
        The Comments.

        >>> SCBeginUpdateTask('B', 'W', 'C').comment
        'C'
        """
        return self._get('comment', '')

    @comment.setter
    def comment(self, value):
        """
        Sets the Comments.
        """
        self._set('comment', value)

    def check(self):
        """
        Checks the name, the Workflow ID and the Comments.

        Valid / invalid (a Workflow ID longer than the console field):

        >>> SCBeginUpdateTask('B', 'CR-1024').check()
        >>> SCBeginUpdateTask('B', 'x' * 101).check()
        Traceback (most recent call last):
        ...
        ValueError: Workflow ID: 100 characters max (101 given).
        """
        super(SCBeginUpdateTask, self).check()
        self._check_workflow(self.name, self.workflow_id, self.comment)

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> SCBeginUpdateTask('B', 'CR-1024').md_rows()
        [('Workflow ID', 'CR-1024'), ('Comments', '-')]
        """
        return [('Workflow ID', self.workflow_id or '-'), ('Comments', self.comment or '-')]


class SCEndUpdateTask(SCClientTask):
    """
    Solidcore: SC: End Update Mode (the client returns to Enabled mode).
    The page has no option.

    >>> SCEndUpdateTask('End').md_rows()
    []
    """

    TYPE_ID = 'Close Update Window'
    LABELS = ('Solidcore', 'SC: End Update Mode')
    DEFAULTS = {SC_SECTION: {'handler': 'mapl', 'req': 'eu', 'requires_response': 'yes'}}

    def md_rows(self):
        """
        No option.
        """
        return []


class SCBeginInventoryTask(SCClientTask):
    """
    Solidcore: SC: Begin Inventory Mode (a reboot is required). The page
    has no option.

    >>> SCBeginInventoryTask('Inventory')._get('inventory_mode')
    'yes'
    """

    TYPE_ID = 'Open Inventory Mode'
    LABELS = ('Solidcore', 'SC: Begin Inventory Mode')
    DEFAULTS = {SC_SECTION: {'handler': 'mapl', 'inventory_mode': 'yes',
                             'reboot_if_required': 'yes', 'req': 'bi',
                             'requires_response': 'yes'}}

    def md_rows(self):
        """
        No option.
        """
        return []


class SCEndInventoryTask(SCClientTask):
    """
    Solidcore: SC: End Inventory Mode. The page has no option.

    >>> SCEndInventoryTask('End')._get('req')
    'ei'
    """

    TYPE_ID = 'Close Inventory Mode'
    LABELS = ('Solidcore', 'SC: End Inventory Mode')
    DEFAULTS = {SC_SECTION: {'handler': 'mapl', 'req': 'ei', 'requires_response': 'yes'}}

    def md_rows(self):
        """
        No option.
        """
        return []


class SCPullInventoryTask(SCClientTask):
    """
    Solidcore: SC: Pull Inventory (loads the software inventory of the
    systems into the ePO database). The page has no option.

    >>> SCPullInventoryTask('Pull')._get('req')
    'PullInventory'
    """

    TYPE_ID = 'Pull Inventory'
    LABELS = ('Solidcore', 'SC: Pull Inventory')
    DEFAULTS = {SC_SECTION: {'handler': 'mapl', 'req': 'PullInventory',
                             'requires_response': 'yes'}}

    def md_rows(self):
        """
        No option.
        """
        return []


class SCDebugInfoTask(SCClientTask):
    """
    Solidcore: SC: Collect Debug Info (an archive of system information
    and Solidcore logs; its location is in the Client Task Log). The page
    has no option.

    >>> SCDebugInfoTask('Debug')._get('type')
    'gatherinfo'
    """

    TYPE_ID = 'Run GatherInfo'
    LABELS = ('Solidcore', 'SC: Collect Debug Info')
    DEFAULTS = {SC_SECTION: {'handler': 'mapl', 'req': 'run_diagnostics',
                             'requires_response': 'no', 'type': 'gatherinfo'}}

    def md_rows(self):
        """
        No option.
        """
        return []


class SCDisableTask(SCClientTask):
    """
    Solidcore: SC: Disable, with or without reboot ("Reboot endpoint",
    checked by default; mandatory on Windows to disable the protection).

    >>> SCDisableTask('Disable', reboot=False)._get('reboot_if_required')
    'no'
    """

    TYPE_ID = 'Disable'
    LABELS = ('Solidcore', 'SC: Disable')
    DEFAULTS = {SC_SECTION: {'handler': 'mapl', 'reboot_if_required': 'yes', 'req': 'disable',
                             'requires_response': 'yes'}}

    def __init__(self, name, reboot=True, description=''):
        """
        :param: name: The task name.
        :param: reboot: "Reboot endpoint".
        :param: description: The task description.
        """
        super(SCDisableTask, self).__init__(name, description)
        self.reboot = reboot

    @property
    def reboot(self):
        """
        "Reboot endpoint" (reboot_if_required).

        >>> SCDisableTask('D').reboot
        True
        """
        return self._flag('reboot_if_required')

    @reboot.setter
    def reboot(self, value):
        """
        Sets "Reboot endpoint".
        """
        self._set('reboot_if_required', _yes_no(value))

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> SCDisableTask('D').md_rows()
        [('Reboot endpoint', 'Yes')]
        """
        return [('Reboot endpoint', self.md_bool(self.reboot))]


class SCCLIAccessTask(SCClientTask):
    """
    Solidcore: SC: Change Local CLI Access: Restrict (lockdown, the
    default) or Allow (recover) the Solidcore command line on the systems.

    >>> SCCLIAccessTask('Allow CLI', allow=True)._get('req')
    'recover'
    """

    TYPE_ID = 'Change CLI Status'
    LABELS = ('Solidcore', 'SC: Change Local CLI Access')
    DEFAULTS = {SC_SECTION: {'handler': 'mapl', 'req': 'lockdown', 'requires_response': 'yes'}}

    def __init__(self, name, allow=False, description=''):
        """
        :param: name: The task name.
        :param: allow: True for Allow, False for Restrict.
        :param: description: The task description.
        """
        super(SCCLIAccessTask, self).__init__(name, description)
        self.allow = allow

    @property
    def allow(self):
        """
        True for "Allow" (req recover), False for "Restrict" (req lockdown).

        >>> SCCLIAccessTask('C').allow
        False
        """
        return self._get('req') == 'recover'

    @allow.setter
    def allow(self, value):
        """
        Sets Allow (True) or Restrict (False).
        """
        self._set('req', 'recover' if value else 'lockdown')

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> SCCLIAccessTask('C', allow=True).md_rows()
        [('Change CLI Status', 'Allow')]
        """
        return [('Change CLI Status', 'Allow' if self.allow else 'Restrict')]


class SCObserveModeTask(SCClientTask):
    """
    Solidcore: SC: Observe Mode: Start Observe Mode (with an optional
    Workflow ID and Comments), or End Observe Mode and then enable or
    disable the Solidcore client.

    >>> SCObserveModeTask('Start', workflow_id='OBS-1').start
    True
    >>> SCObserveModeTask('End', start=False, enable_on_end=False)._get('next_state')
    'disable'
    """

    TYPE_ID = 'Observation'
    LABELS = ('Solidcore', 'SC: Observe Mode')
    DEFAULTS = {SC_SECTION: {'comment': '', 'handler': 'mapl', 'next_state': 'enable',
                             'req': 'ob', 'requires_response': 'yes', 'start': 'yes',
                             'update_inv': 'yes', 'workflow_id': ''}}

    def __init__(self, name, start=True, workflow_id='', comment='', enable_on_end=True,
                 description=''):
        """
        :param: name: The task name.
        :param: start: True for Start Observe Mode, False for End Observe Mode.
        :param: workflow_id: The Workflow ID (Start only, 100 characters at most).
        :param: comment: The Comments (Start only, with a Workflow ID).
        :param: enable_on_end: End only: enable (True) or disable (False)
                               the Solidcore client.
        :param: description: The task description.
        """
        super(SCObserveModeTask, self).__init__(name, description)
        self.start = start
        self.workflow_id = workflow_id
        self.comment = comment
        self.enable_on_end = enable_on_end

    @property
    def start(self):
        """
        True for Start Observe Mode, False for End Observe Mode.

        >>> SCObserveModeTask('O').start
        True
        """
        return self._flag('start')

    @start.setter
    def start(self, value):
        """
        Sets Start (True) or End (False). The console doesn't save the
        Workflow ID and the Comments of an End task: they are removed.

        >>> task = SCObserveModeTask('O', workflow_id='W')
        >>> task.start = False
        >>> task._get('workflow_id') is None
        True
        """
        self._set('start', _yes_no(value))
        if not value:
            self.remove_setting(SC_SECTION, 'workflow_id')
            self.remove_setting(SC_SECTION, 'comment')

    @property
    def workflow_id(self):
        """
        The Workflow ID (Start Observe Mode).

        >>> SCObserveModeTask('O', workflow_id='W').workflow_id
        'W'
        """
        return self._get('workflow_id', '')

    @workflow_id.setter
    def workflow_id(self, value):
        """
        Sets the Workflow ID (written for a Start task only).
        """
        if self.start:
            self._set('workflow_id', value)
        elif value:
            raise ValueError('The Workflow ID is for Start Observe Mode only.')

    @property
    def comment(self):
        """
        The Comments (Start Observe Mode).

        >>> SCObserveModeTask('O', workflow_id='W', comment='C').comment
        'C'
        """
        return self._get('comment', '')

    @comment.setter
    def comment(self, value):
        """
        Sets the Comments (written for a Start task only).
        """
        if self.start:
            self._set('comment', value)
        elif value:
            raise ValueError('The Comments are for Start Observe Mode only.')

    @property
    def enable_on_end(self):
        """
        End Observe Mode: "Enable Solidcore client" (True, the default) or
        "Disable Solidcore client" (False), next_state.

        >>> SCObserveModeTask('O').enable_on_end
        True
        """
        return self._get('next_state') != 'disable'

    @enable_on_end.setter
    def enable_on_end(self, value):
        """
        Sets the state of the client after End Observe Mode.
        """
        self._set('next_state', 'enable' if value else 'disable')

    def check(self):
        """
        Checks the name, the Workflow ID and the Comments.

        Valid / invalid (a comment without Workflow ID):

        >>> SCObserveModeTask('O', workflow_id='W', comment='C').check()
        >>> SCObserveModeTask('O', comment='C').check()
        Traceback (most recent call last):
        ...
        ValueError: Task "O": Cannot enter Comments without Workflow ID.
        """
        super(SCObserveModeTask, self).check()
        self._check_workflow(self.name, self.workflow_id, self.comment)

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> SCObserveModeTask('O', start=False).md_rows()
        [('Observe Mode', 'End Observe Mode, Enable Solidcore client')]
        """
        if self.start:
            return [('Observe Mode', 'Start Observe Mode'),
                    ('Workflow ID', self.workflow_id or '-'), ('Comments', self.comment or '-')]
        return [('Observe Mode', 'End Observe Mode, {} Solidcore client'.format(
            'Enable' if self.enable_on_end else 'Disable'))]


class SCRunCommandsTask(SCClientTask):
    """
    Solidcore: SC: Run Commands: Solidcore command line commands (sadmin
    arguments, e.g. "updaters add ..."), run in order on the systems.

    >>> SCRunCommandsTask('Status', ['status'], requires_response=True).commands
    ['status']
    """

    TYPE_ID = 'Run Commands'
    LABELS = ('Solidcore', 'SC: Run Commands')
    DEFAULTS = {SC_SECTION: {'handler': 'sadmin', 'requires_response': 'no'}}

    def __init__(self, name, commands=(), requires_response=False, description=''):
        """
        :param: name: The task name.
        :param: commands: The commands, one per line of the console (3000
                          characters at most each, not blank).
        :param: requires_response: "Requires Response" (the result is sent
                                   back to ePO).
        :param: description: The task description.
        """
        super(SCRunCommandsTask, self).__init__(name, description)
        self.commands = commands
        self.requires_response = requires_response

    @property
    def commands(self):
        """
        The commands (cmd_1, cmd_2...).

        >>> SCRunCommandsTask('R', ['status', 'config show']).commands
        ['status', 'config show']
        """
        commands = []
        index = 1
        while self._get('cmd_{}'.format(index)) is not None:
            commands.append(self._get('cmd_{}'.format(index)))
            index += 1
        return commands

    @commands.setter
    def commands(self, lines):
        """
        Sets the commands (the previous ones are removed).
        """
        for setting in [name for name in self.sections.get(SC_SECTION, {})
                        if re.fullmatch(r'cmd_\d+', name)]:
            self.remove_setting(SC_SECTION, setting)
        for index, line in enumerate(lines, 1):
            self._set('cmd_{}'.format(index), line)

    @property
    def requires_response(self):
        """
        "Requires Response".

        >>> SCRunCommandsTask('R', ['status']).requires_response
        False
        """
        return self._flag('requires_response')

    @requires_response.setter
    def requires_response(self, value):
        """
        Sets "Requires Response".
        """
        self._set('requires_response', _yes_no(value))

    def check(self):
        """
        Checks the commands: one at least, none blank (the console keeps
        Save disabled), 3000 characters at most each.

        Valid / invalid (a blank command):

        >>> SCRunCommandsTask('R', ['status']).check()
        >>> SCRunCommandsTask('R', ['status', ' ']).check()
        Traceback (most recent call last):
        ...
        ValueError: Run Commands is required.
        """
        super(SCRunCommandsTask, self).check()
        commands = self.commands
        if not commands:
            raise ValueError('Task "{}": add a command.'.format(self.name))
        for command in commands:
            check_length('Run Commands', command, MAX_COMMAND, required=True)

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> SCRunCommandsTask('R', ['status']).md_rows()
        [('Run Commands', 'status'), ('Requires Response', 'No')]
        """
        return [('Run Commands', '\n'.join(self.commands) or '-'),
                ('Requires Response', self.md_bool(self.requires_response))]


class SCEnableTask(SCClientTask):
    """
    Solidcore: SC: Enable. Activates the Solidcore client for Change
    Control and/or Application Control.

    For Windows "All except NT/2000" (the console page of the current
    clients) the task also sets the initial scan priority, the initial
    feature configuration (MP / SAU disabled), the activation (limited:
    no restart, or full: restart), Inventory Mode, Observe Mode and Pull
    Inventory, all with Application Control only. For Windows NT/2000 and
    Unix the page has the features and "Reboot endpoint" only; AIX/HP-UX
    has Change Control only.

    >>> task = SCEnableTask('Enable AC', application_control=True, change_control=False,
    ...                     limited_activation=True)
    >>> task._get('type'), task._get('req'), task._get('reboot_if_required')
    ('enable awl', 'enable2', 'no')
    """

    TYPE_ID = 'Enable'
    LABELS = ('Solidcore', 'SC: Enable')
    DEFAULTS = {SC_SECTION: {'client_platform': 'WIN', 'defer_initial_scan_and_enforce': 'no',
                             'fetch_inventory': 'no', 'handler': 'mapl', 'inventory_mode': 'no',
                             'mp_disabled': 'no', 'observation_mode': 'no',
                             'reboot_if_required': 'yes', 'req': 'enable2',
                             'requires_response': 'yes', 'sau_disabled': 'no',
                             'so_priority': 'normal', 'task_version': '1',
                             'type': 'enable fim', 'unix_sub_platform': 'LIN_SOL_WR',
                             'win_sub_platform': 'OTHERS'}}

    # Platforms and sub platforms of the page (scorPlatforms,
    # scorWinSubplatforms, scorUnixSubplatforms) -> console labels.
    PLATFORMS = {'WIN': 'Windows', 'UNIX': 'Unix'}
    SUB_PLATFORMS = {'WIN': {'OTHERS': 'All except NT/2000', 'WINNT_2K': 'Windows NT/2000'},
                     'UNIX': {'LIN_SOL_WR': 'Linux/Solaris/Windriver Linux',
                              'AIX_HPUX': 'AIX/HPUX'}}
    # Initial Scan Priority (so_priority) -> console label.
    PRIORITIES = {'low': 'Low', 'normal': 'Normal', 'high': 'High'}

    def __init__(self, name, change_control=True, application_control=False, platform='WIN',
                 sub_platform=None, description='', reboot=True, scan_priority='normal',
                 mp_disabled=False, sau_disabled=False, limited_activation=False,
                 inventory_mode=False, observe_mode=False, pull_inventory=None):
        """
        :param: name: The task name.
        :param: change_control: Enable Change Control (fim).
        :param: application_control: Enable Application Control (awl).
        :param: platform: WIN or UNIX.
        :param: sub_platform: OTHERS (All except NT/2000) or WINNT_2K for
                              WIN, LIN_SOL_WR or AIX_HPUX for UNIX; the first
                              one by default.
        :param: description: The task description.
        :param: reboot: "Reboot endpoint" (Windows NT/2000 and Unix pages).
        :param: scan_priority: Initial Scan Priority: low, normal or high.
        :param: mp_disabled: Initial feature configuration: MP disabled.
        :param: sau_disabled: Initial feature configuration: SAU disabled.
        :param: limited_activation: Limited Feature Activation (no restart)
                                    instead of Full Feature Activation.
        :param: inventory_mode: Start Inventory Mode.
        :param: observe_mode: Start Observe Mode.
        :param: pull_inventory: Pull Inventory; by default checked with
                                Application Control on the page of the
                                current Windows clients, as in the console.
        """
        super(SCEnableTask, self).__init__(name, description)
        self.platform_code = platform
        self.sub_platform = sub_platform or next(iter(self.SUB_PLATFORMS.get(platform, {'': ''})))
        self.change_control = change_control
        self.application_control = application_control
        self.scan_priority = scan_priority
        self.mp_disabled = mp_disabled
        self.sau_disabled = sau_disabled
        self.inventory_mode = inventory_mode
        self.observe_mode = observe_mode
        if pull_inventory is None:
            # Checked with Application Control on the page of the current
            # Windows clients; the other pages have no Pull Inventory.
            pull_inventory = application_control and self.current_page
        self.pull_inventory = pull_inventory
        if self.current_page:
            self.limited_activation = limited_activation
        else:
            self.reboot = reboot

    # The platform attribute of the task element is not used by Solidcore:
    # the platform of the page is the client_platform setting.
    @property
    def platform_code(self):
        """
        The platform of the page: WIN or UNIX (client_platform).

        >>> SCEnableTask('E', platform='UNIX').platform_code
        'UNIX'
        """
        return self._get('client_platform') or 'WIN'

    @platform_code.setter
    def platform_code(self, value):
        """
        Sets the platform (WIN or UNIX) and the request that goes with the
        page (see _update_request()).

        >>> SCEnableTask('E').platform_code = 'MAC'
        Traceback (most recent call last):
        ...
        ValueError: Platform must be one of ['WIN', 'UNIX'].
        """
        if value not in self.PLATFORMS:
            raise ValueError('Platform must be one of {}.'.format(list(self.PLATFORMS)))
        self._set('client_platform', value)
        self._update_request()

    @property
    def sub_platform(self):
        """
        The sub platform of the platform: OTHERS / WINNT_2K for WIN,
        LIN_SOL_WR / AIX_HPUX for UNIX (both settings are always written).

        >>> SCEnableTask('E', platform='UNIX', sub_platform='AIX_HPUX').sub_platform
        'AIX_HPUX'
        """
        setting = 'win_sub_platform' if self.platform_code == 'WIN' else 'unix_sub_platform'
        return self._get(setting) or ''

    @sub_platform.setter
    def sub_platform(self, value):
        """
        Sets the sub platform of the current platform.

        >>> SCEnableTask('E').sub_platform = 'AIX_HPUX'
        Traceback (most recent call last):
        ...
        ValueError: Sub platform of WIN must be one of ['OTHERS', 'WINNT_2K'].
        """
        platform = self.platform_code
        if value not in self.SUB_PLATFORMS[platform]:
            raise ValueError('Sub platform of {} must be one of {}.'.format(
                platform, list(self.SUB_PLATFORMS[platform])))
        self._set('win_sub_platform' if platform == 'WIN' else 'unix_sub_platform', value)
        self._update_request()

    @property
    def current_page(self):
        """
        True for the page of the current Windows clients (WIN, All except
        NT/2000): activation options instead of "Reboot endpoint", req
        enable2. The other sub platforms have the page of the older clients.

        >>> SCEnableTask('E').current_page, SCEnableTask('E', platform='UNIX').current_page
        (True, False)
        """
        return self.platform_code == 'WIN' and self.sub_platform == 'OTHERS'

    def _update_request(self):
        """
        Sets req as the console does: enable2 for the page of the current
        Windows clients, enable for the other pages.

        >>> task = SCEnableTask('E')
        >>> task._set('win_sub_platform', 'WINNT_2K'); task._update_request(); task._get('req')
        'enable'
        """
        if self._get('win_sub_platform') is not None:
            self._set('req', 'enable2' if self.current_page else 'enable')

    def _features(self):
        """
        Returns the features of the "type" setting ("enable awl_fim",
        "enable awl", "enable fim").

        >>> sorted(SCEnableTask('E', application_control=True)._features())
        ['awl', 'fim']
        """
        value = self._get('type') or 'enable fim'
        return {item for item in value.partition(' ')[2].split('_') if item}

    def _set_feature(self, feature, value):
        """
        Adds or removes a feature (awl or fim) of the "type" setting.

        >>> task = SCEnableTask('E')
        >>> task._set_feature('awl', True); task._get('type')
        'enable awl_fim'
        """
        features = self._features()
        if value:
            features.add(feature)
        else:
            features.discard(feature)
        self._set('type', 'enable ' + '_'.join(sorted(features)))

    @property
    def change_control(self):
        """
        Enable Change Control.

        >>> SCEnableTask('E').change_control
        True
        """
        return 'fim' in self._features()

    @change_control.setter
    def change_control(self, value):
        """
        Sets Change Control.
        """
        self._set_feature('fim', value)

    @property
    def application_control(self):
        """
        Enable Application Control.

        >>> SCEnableTask('E').application_control
        False
        """
        return 'awl' in self._features()

    @application_control.setter
    def application_control(self, value):
        """
        Sets Application Control.
        """
        self._set_feature('awl', value)

    @property
    def scan_priority(self):
        """
        Initial Scan Priority: low, normal or high (so_priority).

        >>> SCEnableTask('E').scan_priority
        'normal'
        """
        return self._get('so_priority', 'normal')

    @scan_priority.setter
    def scan_priority(self, value):
        """
        Sets the Initial Scan Priority.

        >>> SCEnableTask('E').scan_priority = 'urgent'
        Traceback (most recent call last):
        ...
        ValueError: Initial Scan Priority must be one of ['low', 'normal', 'high'].
        """
        if value not in self.PRIORITIES:
            raise ValueError('Initial Scan Priority must be one of {}.'.format(
                list(self.PRIORITIES)))
        self._set('so_priority', value)

    @property
    def mp_disabled(self):
        """
        Initial feature configuration: MP disabled (Memory Protection).

        >>> SCEnableTask('E').mp_disabled
        False
        """
        return self._flag('mp_disabled')

    @mp_disabled.setter
    def mp_disabled(self, value):
        """
        Sets "MP disabled".
        """
        self._set('mp_disabled', _yes_no(value))

    @property
    def sau_disabled(self):
        """
        Initial feature configuration: SAU disabled.

        >>> SCEnableTask('E').sau_disabled
        False
        """
        return self._flag('sau_disabled')

    @sau_disabled.setter
    def sau_disabled(self, value):
        """
        Sets "SAU disabled".
        """
        self._set('sau_disabled', _yes_no(value))

    @property
    def reboot(self):
        """
        "Reboot endpoint" of the Windows NT/2000 and Unix pages
        (reboot_if_required); on the page of the current Windows clients it
        follows the activation (full: yes, limited: no).

        >>> SCEnableTask('E', platform='UNIX', reboot=False).reboot
        False
        """
        return self._flag('reboot_if_required')

    @reboot.setter
    def reboot(self, value):
        """
        Sets "Reboot endpoint".
        """
        self._set('reboot_if_required', _yes_no(value))

    @property
    def limited_activation(self):
        """
        Limited Feature Activation (no restart) instead of Full Feature
        Activation: reboot_if_required "no".

        >>> SCEnableTask('E', application_control=True, limited_activation=True).limited_activation
        True
        """
        return not self.reboot

    @limited_activation.setter
    def limited_activation(self, value):
        """
        Sets Limited (True) or Full (False) Feature Activation.
        """
        self.reboot = not value

    @property
    def inventory_mode(self):
        """
        Start Inventory Mode.

        >>> SCEnableTask('E').inventory_mode
        False
        """
        return self._flag('inventory_mode')

    @inventory_mode.setter
    def inventory_mode(self, value):
        """
        Sets "Start Inventory Mode".
        """
        self._set('inventory_mode', _yes_no(value))

    @property
    def observe_mode(self):
        """
        Start Observe Mode.

        >>> SCEnableTask('E').observe_mode
        False
        """
        return self._flag('observation_mode')

    @observe_mode.setter
    def observe_mode(self, value):
        """
        Sets "Start Observe Mode".
        """
        self._set('observation_mode', _yes_no(value))

    @property
    def pull_inventory(self):
        """
        Pull Inventory (fetch_inventory).

        >>> SCEnableTask('E', application_control=True).pull_inventory
        True
        """
        return self._flag('fetch_inventory')

    @pull_inventory.setter
    def pull_inventory(self, value):
        """
        Sets "Pull Inventory".
        """
        self._set('fetch_inventory', _yes_no(value))

    def check(self):
        """
        Checks the task against the rules of the console pages:
        - a feature at least; Change Control only on AIX/HP-UX;
        - page of the current Windows clients: the scan priority, MP/SAU
          disabled, limited activation, Inventory Mode, Observe Mode and
          Pull Inventory need Application Control; Inventory Mode and
          Observe Mode not together; Inventory Mode pulls the inventory and
          keeps MP and SAU enabled;
        - Windows NT/2000 and Unix pages: these options are not on the
          page and must keep their default.

        Valid / invalid (Observe Mode without Application Control):

        >>> SCEnableTask('E', application_control=True, observe_mode=True).check()
        >>> SCEnableTask('E', observe_mode=True).check()
        Traceback (most recent call last):
        ...
        ValueError: Task "E": Start Observe Mode needs Application Control.
        """
        super(SCEnableTask, self).check()
        if not self.change_control and not self.application_control:
            raise ValueError('Task "{}": Select a feature to enable.'.format(self.name))
        if self.sub_platform == 'AIX_HPUX' and self.application_control:
            raise ValueError('Task "{}": AIX/HPUX supports Change Control only.'.format(
                self.name))
        options = [('Initial Scan Priority (other than Normal)', self.scan_priority != 'normal'),
                   ('MP disabled', self.mp_disabled), ('SAU disabled', self.sau_disabled),
                   ('Limited Feature Activation', self.current_page and self.limited_activation),
                   ('Start Inventory Mode', self.inventory_mode),
                   ('Start Observe Mode', self.observe_mode),
                   ('Pull Inventory', self.pull_inventory)]
        for label, used in options:
            if not used:
                continue
            if not self.current_page:
                raise ValueError('Task "{}": {} is only on the page of the Windows clients '
                                 '(All except NT/2000).'.format(self.name, label))
            if not self.application_control:
                raise ValueError('Task "{}": {} needs Application Control.'.format(
                    self.name, label))
        if self.inventory_mode:
            if self.observe_mode:
                raise ValueError('Task "{}": Inventory Mode and Observe Mode can\'t be started '
                                 'together.'.format(self.name))
            if not self.pull_inventory or self.mp_disabled or self.sau_disabled:
                raise ValueError('Task "{}": Inventory Mode pulls the inventory and keeps MP and '
                                 'SAU enabled.'.format(self.name))

    def md_rows(self):
        """
        Returns the options as the console page shows them.

        >>> SCEnableTask('E', platform='UNIX').md_rows()
        [('Solidcore Client', 'Unix, Linux/Solaris/Windriver Linux'), ('Enable', 'Change Control'), ('Reboot endpoint', 'Yes')]
        """
        features = [label for label, used in (('Change Control', self.change_control),
                                              ('Application Control', self.application_control))
                    if used]
        rows = [('Solidcore Client', '{}, {}'.format(
                    self.PLATFORMS.get(self.platform_code, self.platform_code),
                    self.SUB_PLATFORMS.get(self.platform_code, {}).get(self.sub_platform,
                                                                       self.sub_platform))),
                ('Enable', ', '.join(features) or '-')]
        if not self.current_page:
            return rows + [('Reboot endpoint', self.md_bool(self.reboot))]
        if self.application_control:
            rows += [('Initial Scan Priority', self.PRIORITIES.get(self.scan_priority,
                                                                   self.scan_priority)),
                     ('MP disabled', self.md_bool(self.mp_disabled)),
                     ('SAU disabled', self.md_bool(self.sau_disabled))]
        rows += [('Activation Options', 'Limited Feature Activation' if self.limited_activation
                  else 'Full Feature Activation')]
        if self.application_control:
            rows += [('Start Inventory Mode', self.md_bool(self.inventory_mode)),
                     ('Start Observe Mode', self.md_bool(self.observe_mode)),
                     ('Pull Inventory', self.md_bool(self.pull_inventory))]
        return rows


# Classes of the task types the library supports: (product id, type id of
# the export) -> class.
TASK_CLASSES = {(cls.PRODUCT_ID, cls.TYPE_ID): cls for cls in (
    TADeploymentTask, TAUpdateTask, SIRFileRetrievalTask, SCEnableTask, SCDisableTask,
    SCBeginUpdateTask, SCEndUpdateTask, SCBeginInventoryTask, SCEndInventoryTask,
    SCPullInventoryTask, SCDebugInfoTask, SCCLIAccessTask, SCObserveModeTask, SCRunCommandsTask)}


class ClientTaskList():
    """
    The client tasks of a clienttask.export file, or a new list to import
    (clienttask.importClientTask, epo.client_tasks.import_tasks()).

    >>> tasks = ClientTaskList()
    >>> tasks.add(SCPullInventoryTask('Pull'))
    >>> tasks
    <ClientTaskList of 1 task(s)>
    """

    def __init__(self, xml=None):
        """
        :param: xml: The XML of clienttask.export (bytes or text), or None
                     for an empty list.
        :raise: ValueError: Not a client task file.
        """
        self.tasks = []
        self.version = {'vermjr': '5', 'vermin': '10', 'verrel': '0', 'verbld': '0'}
        if xml is not None:
            root = et.fromstring(xml.encode('utf-8') if isinstance(xml, str) else xml)
            if root.tag != '{%s}EPOTaskSchema' % NAMESPACE:
                raise ValueError('Not a client task file: {}'.format(root.tag))
            info = root.find('EPOTaskVerInfo')
            if info is not None:
                self.version = dict(info.attrib)
            self.tasks = [ClientTask.from_element(element)
                          for element in root.findall('EPOTaskObjectInstance')]

    def __repr__(self):
        """
        Shows the number of tasks.
        """
        return '<ClientTaskList of {} task(s)>'.format(len(self.tasks))

    def __iter__(self):
        """
        Iterates over the tasks.
        """
        return iter(self.tasks)

    def __len__(self):
        """
        Returns the number of tasks.
        """
        return len(self.tasks)

    def get(self, name, product_id=None, type_id=None):
        """
        Returns the first task of this name (and product id and type id when
        given), or None.

        >>> tasks = ClientTaskList()
        >>> tasks.add(SCPullInventoryTask('Pull'))
        >>> tasks.get('Pull', 'SOLIDCORE_META')
        <SCPullInventoryTask SOLIDCORE_META/Pull Inventory Pull>
        >>> tasks.get('Pull', 'EPOAGENTMETA') is None
        True
        """
        for task in self.tasks:
            if task.name == name and product_id in (None, task.product_id) and \
                    type_id in (None, task.type_id):
                return task
        return None

    def add(self, task):
        """
        Adds a task after checking it, or replaces the task of the same
        product, type and name (as the import does).

        :raise: ValueError: The task breaks a rule of its console page, or
                            another task of the list has the same name with
                            another case (the import would skip it).

        >>> tasks = ClientTaskList()
        >>> tasks.add(SCPullInventoryTask('Pull'))
        >>> tasks.add(SCPullInventoryTask('PULL'))
        Traceback (most recent call last):
        ...
        ValueError: Task "PULL": the list has "Pull" of the same type; the import skips a name that differs by case only.
        """
        task.check()
        for index, item in enumerate(self.tasks):
            if item.key == task.key:
                self.tasks[index] = task
                return
            if item.key[:2] == task.key[:2] and item.name.lower() == task.name.lower():
                raise ValueError('Task "{}": the list has "{}" of the same type; the import skips '
                                 'a name that differs by case only.'.format(task.name, item.name))
        self.tasks.append(task)

    def remove(self, name, product_id=None, type_id=None):
        """
        Removes the tasks of this name (and product id and type id when given).

        >>> tasks = ClientTaskList()
        >>> tasks.add(SCPullInventoryTask('Pull'))
        >>> tasks.remove('Pull'); len(tasks)
        0
        """
        self.tasks = [task for task in self.tasks
                      if not (task.name == name and product_id in (None, task.product_id) and
                              type_id in (None, task.type_id))]

    def get_xml_content_str(self):
        """
        Returns the file as clienttask.export writes it (text): the XML
        declaration and the root on their own lines, the tasks on one line.

        >>> ClientTaskList().get_xml_content_str()[:59]
        '<?xml version="1.0" encoding="UTF-8"?>\\r\\n<epo:EPOTaskSchema '
        """
        text = ('<?xml version="1.0" encoding="UTF-8"?>' + _EOL +
                '<epo:EPOTaskSchema xmlns:epo="{}" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'.format(NAMESPACE) +
                '<EPOTaskVerInfo {} />'.format(' '.join(
                    '{}="{}"'.format(name, _attr(value)) for name, value in self.version.items())))
        for task in self.tasks:
            text += task.to_xml()
        return text + '</epo:EPOTaskSchema>' + _EOL

    def get_xml_content(self):
        """
        Returns the file to import (UTF-8 bytes; the client task import of
        the Web API reads UTF-8 right, unlike the policy import), after
        checking every task.

        :raise: ValueError: A task breaks a rule of its console page.
        """
        for task in self.tasks:
            task.check()
        return self.get_xml_content_str().encode('utf-8')

    def save_to_file(self, file_path):
        """
        Writes the file to import (clienttask.importClientTask).
        """
        with open(file_path, 'wb') as xml_file:
            xml_file.write(self.get_xml_content())

    @classmethod
    def load_from_file(cls, file_path):
        """
        Reads a file of clienttask.export.
        """
        with open(file_path, 'rb') as xml_file:
            return cls(xml_file.read())

    def check_server(self, epo):
        """
        Checks the tasks against an ePO server before the import (read
        only), for the cases the import skips without an error or the
        clients can't run:
        - a task of the server with the same product and type and a name
          that differs by case only (the import skips the task: "Imported 0
          client tasks");
        - a Product Deployment line whose package (product id, version,
          branch, language) is not in the repository (the product in the
          branch only, with "Automatically deploy latest version");
        - a Product Deployment line whose package is not for one of the
          target platforms (the console shows "The selection is not valid
          for the selected platforms" and saves the task);
        - a Product Update package that is not in the repository.

        :param: epo: An EPOClient.
        :return: The problems found, one text per problem ([] when the
                 tasks can be imported as written).
        """
        existing = {}
        for item in epo.call('clienttask.find'):
            existing.setdefault(item['productId'], []).append(item)
        packages = epo.repository.packages()
        found = {(item.product_id, item.branch, item.build_version, item.language)
                 for item in packages}
        codes = {item.product_id for item in packages}
        package_platforms = {}
        for item in packages:
            package_platforms.setdefault(item.product_id, set()).update(item.platforms)
        problems = []
        for task in self.tasks:
            for item in existing.get(task.product_id, []):
                if task.is_type_name(item['typeName']) and item['objectName'] != task.name and \
                        item['objectName'].lower() == task.name.lower():
                    problems.append('Task "{}": the server has "{}" ({}); the import skips a '
                                    'name that differs by case only.'.format(
                                        task.name, item['objectName'], item['typeName']))
            if isinstance(task, TADeploymentTask):
                for line in task.products:
                    supported = package_platforms.get(line.product_id)
                    if supported:
                        missing = [label for label in task.platforms
                                   if not set(PLATFORMS[label].split('|')) & supported]
                        if missing:
                            problems.append('Task "{}": package {} is not for the platforms {} '
                                            '(console: "The selection is not valid for the '
                                            'selected platforms").'.format(
                                                task.name, line.product_id, ', '.join(missing)))
                    if line.action != 'Install':
                        continue
                    if task.auto_update:
                        # The latest version of the branch is deployed: the
                        # product only has to be in the branch.
                        if not any(item[:2] == (line.product_id, line.branch) for item in found):
                            problems.append('Task "{}": no package {} in the {} branch.'.format(
                                task.name, line.product_id, line.branch))
                    elif (line.product_id, line.branch, line.version,
                          line.language) not in found:
                        problems.append('Task "{}": package {} {} ({}, {}) not in the '
                                        'repository.'.format(task.name, line.product_id,
                                                             line.version, line.branch,
                                                             line.language))
            elif isinstance(task, TAUpdateTask):
                for code in task.packages or []:
                    if code not in codes:
                        problems.append('Task "{}": package {} not in the repository.'.format(
                            task.name, code))
        return problems

    def to_markdown(self):
        """
        Returns the tasks as Markdown, grouped by product and task type as
        in the Client Task Catalog.

        >>> tasks = ClientTaskList()
        >>> tasks.add(SCDisableTask('Disable'))
        >>> print(tasks.to_markdown())
        # Client Tasks
        <BLANKLINE>
        ## Solidcore / SC: Disable
        <BLANKLINE>
        ### Disable
        <BLANKLINE>
        | Option | Value |
        |---|---|
        | Reboot endpoint | Yes |
        """
        lines = ['# Client Tasks']
        groups = {}
        for task in self.tasks:
            groups.setdefault(task.labels, []).append(task)
        for labels in sorted(groups):
            lines += ['', '## {} / {}'.format(*(Policy.md_heading(label) for label in labels))]
            for task in sorted(groups[labels], key=lambda item: item.name.lower()):
                lines += ['', task.to_markdown(labels=False)]
        return '\n'.join(lines)
