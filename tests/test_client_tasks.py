"""
Client tasks (trellix_epo.clienttasks, trellix_epo.epoclienttasks),
without a server.

client_tasks.xml: clienttask.export (all products) of the ePO 5.10 Update 7
lab, byte for byte, with the test tasks of the console checks:
- "Claude - Deployment Test": saved twice in the console (2nd save: auto
  update, two Install lines, the Remove line deleted - the server kept its
  sections with NumUninstalls 0 - and postponing disabled - its values
  kept);
- "Claude - Update Test": selected packages, progress dialog and postpone;
- "Claude - SIR Test": imported (overwrite test A2);
- "Claude - SC ... Test": one task per Solidcore type saved in the console
  (Enable on the Windows, NT/2000 and AIX/HP-UX pages, Observe Mode start
  and end...), "Claude - SC Pull Inventory Test" also imported twice in one
  file (the last one wins) and with the Run Commands type;
- the tasks of the lab (Install ..., Update All, SC Enable Full & Reboot...).
The library rebuilds this file identically (test_lab_file_rebuilt).
"""

import doctest
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import clienttasks as module
from trellix_epo import epoclienttasks as operations
from trellix_epo import (ClientTask, ClientTaskList, DeploymentItem, EPOClient, TADeploymentTask,
                         TAUpdateTask, SIRFileRetrievalTask, SCEnableTask, SCDisableTask,
                         SCBeginUpdateTask, SCEndUpdateTask, SCBeginInventoryTask,
                         SCEndInventoryTask, SCPullInventoryTask, SCDebugInfoTask,
                         SCCLIAccessTask, SCObserveModeTask, SCRunCommandsTask)
from trellix_epo.clienttasks import LANGUAGES, PLATFORMS, TASK_CLASSES
from trellix_epo.epo import EPOError

FIXTURE = Path(__file__).parent / 'fixtures' / 'client_tasks.xml'


@pytest.fixture(name='lab')
def fixture_lab():
    """
    The lab export.
    """
    return ClientTaskList.load_from_file(FIXTURE)


def test_docstring_examples():
    result = doctest.testmod(module)
    assert result.attempted >= 140 and result.failed == 0
    result = doctest.testmod(operations)
    assert result.attempted >= 2 and result.failed == 0


def test_read_lab_export(lab):
    assert len(lab) == 44
    assert {type(task) for task in lab} == set(TASK_CLASSES.values())
    deployment = lab.get('Claude - Deployment Test')
    assert isinstance(deployment, TADeploymentTask)
    assert deployment.platforms == ['Windows', 'Linux', 'Mac']
    assert deployment.auto_update
    # The stale Remove line (NumUninstalls 0) is not read.
    assert deployment.products == [
        DeploymentItem('SIR_____1000', '1.0.3252', 'Install', '0409', 'Current', '/claude-test',
                       'SystemInformationReporter'),
        DeploymentItem('EPOAGENT3700LYNX', '5.8.7752', 'Install', '0409', 'Current', '',
                       'TrellixAgentforLINUX')]
    assert not deployment.allow_postpone
    assert (deployment.max_postpones, deployment.postpone_timeout,
            deployment.postpone_text) == (3, 60, 'Claude postpone text')
    update = lab.get('Claude - Update Test')
    assert update.packages == ['VSCANENG1000', 'VSCANDAT1000', 'AMCORDAT2000',
                               'EPOAGENT3000META', 'SOLIDCOR_KMOD_5000_LNX']
    assert update.show_progress and update.allow_postpone
    assert lab.get('Update All').packages is None
    sir = lab.get('Acquire Files')
    assert sir.paths == ['C:\\Test\\Clone.exe', 'C:\\Quarantine'] and sir.include_subfolders
    commands = lab.get('Claude - SC Run Commands Test')
    assert commands.commands == ['status', 'updaters add -l "Claude <Test> & co" '
                                 '"C:\\Program Files\\Claude\\a.exe"', 'config show']
    assert commands.requires_response
    assert lab.get('Claude - SC Begin Update Test').comment == 'Claude comment "quoted" <b>'
    assert lab.get('Claude - Accents éàü Test').name == 'Claude - Accents éàü Test'
    # Same name in two types (import test E1).
    assert isinstance(lab.get('Claude - SC Pull Inventory Test', type_id='Run Commands'),
                      SCRunCommandsTask)
    assert lab.get('Claude - SC Pull Inventory Test', type_id='Pull Inventory').description == \
        'D3 dup in file'


def test_lab_file_rebuilt(lab):
    assert lab.get_xml_content_str().encode('utf-8') == FIXTURE.read_bytes()


def test_enable_pages(lab):
    win = lab.get('Claude - SC Enable WIN Test')
    assert (win.platform_code, win.sub_platform, win.current_page) == ('WIN', 'OTHERS', True)
    assert win.change_control and win.application_control
    assert (win.scan_priority, win.mp_disabled, win.sau_disabled, win.limited_activation,
            win.pull_inventory) == ('high', True, True, True, True)
    observe = lab.get('Claude - SC Enable Observe Test')
    assert observe.observe_mode and not observe.change_control and not observe.limited_activation
    inventory = lab.get('Claude - SC Enable Inventory Test')
    assert inventory.inventory_mode and inventory.pull_inventory and inventory.limited_activation
    aix = lab.get('Claude - SC Enable AIX Test')
    assert (aix.platform_code, aix.sub_platform, aix.current_page, aix.reboot) == (
        'UNIX', 'AIX_HPUX', False, False)
    nt = lab.get('Claude - SC Enable NT Test')
    assert nt.sub_platform == 'WINNT_2K' and nt.reboot and nt.application_control
    for task in (win, observe, inventory, aix, nt, lab.get('SC Enable Full & Reboot')):
        task.check()


@pytest.mark.parametrize('name, built', [
    ('Claude - SC Enable WIN Test',
     SCEnableTask('Claude - SC Enable WIN Test', application_control=True, scan_priority='high',
                  mp_disabled=True, sau_disabled=True, limited_activation=True)),
    ('Claude - SC Enable Observe Test',
     SCEnableTask('Claude - SC Enable Observe Test', change_control=False,
                  application_control=True, observe_mode=True, pull_inventory=False)),
    ('Claude - SC Enable Inventory Test',
     SCEnableTask('Claude - SC Enable Inventory Test', change_control=False,
                  application_control=True, inventory_mode=True, limited_activation=True)),
    ('Claude - SC Enable AIX Test',
     SCEnableTask('Claude - SC Enable AIX Test', platform='UNIX', sub_platform='AIX_HPUX',
                  reboot=False)),
    ('Claude - SC Enable NT Test',
     SCEnableTask('Claude - SC Enable NT Test', change_control=False, application_control=True,
                  sub_platform='WINNT_2K')),
    ('SC Enable Full & Reboot',
     SCEnableTask('SC Enable Full & Reboot', application_control=True, platform='UNIX')),
    ('Claude - SC Disable Test', SCDisableTask('Claude - SC Disable Test', reboot=False)),
    ('Claude - SC Begin Update Test',
     SCBeginUpdateTask('Claude - SC Begin Update Test', 'WF-Claude-1',
                       'Claude comment "quoted" <b>')),
    ('Claude - SC End Update Test', SCEndUpdateTask('Claude - SC End Update Test')),
    ('Claude - SC Begin Inventory Test', SCBeginInventoryTask('Claude - SC Begin Inventory Test')),
    ('Claude - SC End Inventory Test', SCEndInventoryTask('Claude - SC End Inventory Test')),
    ('Claude - SC Debug Info Test', SCDebugInfoTask('Claude - SC Debug Info Test')),
    ('Claude - SC CLI Access Test', SCCLIAccessTask('Claude - SC CLI Access Test', allow=True)),
    ('Claude - SC Observe Start Test',
     SCObserveModeTask('Claude - SC Observe Start Test', workflow_id='WF-Observe',
                       comment='only comment')),
    ('Claude - SC Observe End Test',
     SCObserveModeTask('Claude - SC Observe End Test', start=False, enable_on_end=False)),
    ('Claude - SC Run Commands Test',
     SCRunCommandsTask('Claude - SC Run Commands Test',
                       ['status', 'updaters add -l "Claude <Test> & co" '
                        '"C:\\Program Files\\Claude\\a.exe"', 'config show'],
                       requires_response=True)),
    ('Claude - Update Test',
     TAUpdateTask('Claude - Update Test', ['VSCANENG1000', 'VSCANDAT1000', 'AMCORDAT2000',
                                           'EPOAGENT3000META', 'SOLIDCOR_KMOD_5000_LNX'],
                  description='Claude test: every update option', show_progress=True,
                  allow_postpone=True, max_postpones=2, postpone_timeout=30,
                  postpone_text='Claude update postpone')),
    ('Update All', TAUpdateTask('Update All')),
])
def test_built_like_console(lab, name, built):
    """
    A task built with the library has the settings of the task saved in the
    console with the same options.
    """
    saved = lab.get(name, built.product_id, built.type_id)
    assert built.sections == saved.sections
    assert built.description == saved.description


def test_deployment_built_like_console(lab):
    saved = lab.get('Claude - Deployment Test')
    built = TADeploymentTask('Claude - Deployment Test', saved.products,
                             platforms=['Windows', 'Linux', 'Mac'],
                             description='Claude test: every deployment option', auto_update=True,
                             max_postpones=3, postpone_timeout=60,
                             postpone_text='Claude postpone text')
    assert built.platform == saved.platform
    # The console kept the sections of the deleted Remove line.
    stale = {'Uninstall\\XCLIENT_1000LYNX'}
    assert set(saved.sections) - set(built.sections) == stale
    for section, settings in built.sections.items():
        if section == 'Uninstall':
            assert settings == {'NumUninstalls': '0'}
        elif section == 'ProductName':
            assert saved.sections[section] == dict(settings, ProductName__Remove_1=
                                                   'TrellixEDRwithForensicsforLinux')
        else:
            assert settings == saved.sections[section], section


def test_deployment_rules():
    sir = DeploymentItem('SIR_____1000', '1.0.3252')
    TADeploymentTask('D', [sir]).check()
    with pytest.raises(ValueError, match='select a target platform'):
        TADeploymentTask('D', [sir], platforms=[]).check()
    with pytest.raises(ValueError, match='add a product'):
        TADeploymentTask('D').check()
    with pytest.raises(ValueError, match='once only'):
        TADeploymentTask('D', [sir, DeploymentItem('SIR_____1000', '1.0.3252',
                                                   action='Remove')]).check()
    with pytest.raises(ValueError, match='needs the Current branch'):
        TADeploymentTask('D', [DeploymentItem('A', '1.0', branch='Previous')],
                         auto_update=True).check()
    with pytest.raises(ValueError, match='Command line: 254'):
        TADeploymentTask('D', [DeploymentItem('A', '1.0', command_line='x' * 255)]).check()
    with pytest.raises(ValueError, match='unknown language'):
        TADeploymentTask('D', [DeploymentItem('A', '1.0', language='9999')]).check()
    with pytest.raises(ValueError, match='between 1 and 999: 1000'):
        TADeploymentTask('D', [sir], postpone_timeout=1000).check()
    with pytest.raises(ValueError, match='Display this text: 2047'):
        TADeploymentTask('D', [sir], postpone_text='x' * 2048).check()
    assert len(PLATFORMS) == 9 and LANGUAGES['0000'] == 'Language Neutral'


def test_deployment_rewrite_removes_stale_lines(lab):
    task = lab.get('Claude - Deployment Test')
    task.products = [DeploymentItem('SIR_____1000', '1.0.3252', action='Remove')]
    assert sorted(task.sections) == ['AutoUpdateOption', 'DeploymentOptions', 'General', 'Install',
                                     'SchedulerExtraData', 'Settings', 'Uninstall',
                                     'Uninstall\\SIR_____1000', 'UpdateOptions']
    assert task.sections['Install'] == {'NumInstalls': '0'}
    assert task.products == [DeploymentItem('SIR_____1000', '1.0.3252', action='Remove')]


def test_update_rules():
    TAUpdateTask('U').check()
    with pytest.raises(ValueError, match='select a package'):
        TAUpdateTask('U', []).check()
    with pytest.raises(ValueError, match='Engine'):
        TAUpdateTask('U', ['VSCANENG1000']).check()
    with pytest.raises(ValueError, match='Update in Progress'):
        TAUpdateTask('U', allow_postpone=True).check()
    task = TAUpdateTask('U', ['VSCANDAT1000'])
    task.packages = None
    assert task.sections['SelectedUpdates'] == {'NumOfUpdates': '0', 'UpdateAll': '1'}
    assert 'SelectedUpdates\\VSCANDAT1000' not in task.sections


def test_solidcore_rules():
    with pytest.raises(ValueError, match='Select a feature'):
        SCEnableTask('E', change_control=False).check()
    with pytest.raises(ValueError, match='AIX/HPUX supports Change Control only'):
        SCEnableTask('E', application_control=True, platform='UNIX',
                     sub_platform='AIX_HPUX').check()
    with pytest.raises(ValueError, match='Limited Feature Activation needs Application'):
        SCEnableTask('E', limited_activation=True).check()
    with pytest.raises(ValueError, match='only on the page of the Windows clients'):
        SCEnableTask('E', application_control=True, platform='UNIX',
                     pull_inventory=True).check()
    with pytest.raises(ValueError, match="can't be started together"):
        SCEnableTask('E', application_control=True, inventory_mode=True,
                     observe_mode=True).check()
    with pytest.raises(ValueError, match='keeps MP and SAU enabled'):
        SCEnableTask('E', application_control=True, inventory_mode=True,
                     mp_disabled=True).check()
    with pytest.raises(ValueError, match='Comments without Workflow ID'):
        SCBeginUpdateTask('B', comment='C').check()
    with pytest.raises(ValueError, match='Start Observe Mode only'):
        SCObserveModeTask('O', start=False, workflow_id='W')
    with pytest.raises(ValueError, match='add a command'):
        SCRunCommandsTask('R').check()
    with pytest.raises(ValueError, match='3000 characters max'):
        SCRunCommandsTask('R', ['x' * 3001]).check()
    task = SCEnableTask('E')
    task.platform_code = 'UNIX'
    task.sub_platform = 'LIN_SOL_WR'
    assert task._get('req') == 'enable'   # pylint: disable=protected-access


def test_list_add_replace_and_case(lab):
    tasks = ClientTaskList()
    tasks.add(SCDisableTask('Disable'))
    tasks.add(SCDisableTask('Disable', reboot=False))
    assert len(tasks) == 1 and not tasks.get('Disable').reboot
    tasks.add(SCPullInventoryTask('Disable'))   # same name, other type
    assert len(tasks) == 2
    with pytest.raises(ValueError, match='differs by case only'):
        tasks.add(SCDisableTask('DISABLE'))
    tasks.remove('Disable', type_id='Disable')
    assert [task.type_id for task in tasks] == ['Pull Inventory']
    unknown = ClientTask('Collect All', 'EPOAGENTMETA', 'Statistics',
                         sections={'General': {'TaskType': 'Statistics'}})
    tasks.add(unknown)
    assert ClientTaskList(tasks.get_xml_content()).get('Collect All').sections == unknown.sections


def test_markdown(lab):
    text = lab.to_markdown()
    assert text.startswith('# Client Tasks')
    assert '## Trellix Agent / Product Deployment' in text
    assert '| Target platforms | Windows, Linux, Mac |' in text
    # Markdown and HTML characters escaped (Policy.md_escape)
    assert ('| Run Commands | status<br>updaters add -l "Claude &lt;Test&gt; & co" '
            '"C:\\\\Program Files\\\\Claude\\\\a.exe"<br>config show |') in text
    assert '| Comments | Claude comment "quoted" &lt;b&gt; |' in text
    assert '| Observe Mode | End Observe Mode, Disable Solidcore client |' in text


class FakeServer(EPOClient):
    """
    EPOClient whose server is a list of answers; the requests are kept in
    self.requests as (command, form fields or multipart body).
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
        if request.get_header('Content-type').startswith('multipart/'):
            fields = request.data
        else:
            fields = dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))
        self.requests.append((command, fields))
        return self.answers.pop(0)


FIND = ('OK:\r\n[{"productId": "SOLIDCORE_META", "typeName": "Solidcore 8.4.5: SC: Pull '
        'Inventory", "objectName": "Pull", "typeId": 20, "objectId": 195, "productName": '
        '"Solidcore 8.4.5"}, {"productId": "SOLIDCORE_META", "typeName": "Solidcore 8.4.5: SC: '
        'Run Commands", "objectName": "Pull", "typeId": 22, "objectId": 202, "productName": '
        '"Solidcore 8.4.5"}]')


def test_export_and_import():
    epo = FakeServer('OK:\r\n' + FIXTURE.read_text(encoding='utf-8'),
                     'OK:\r\nImported 2 client tasks.\r\n',
                     'OK:\r\nImported 0 client tasks.\r\n')
    assert len(epo.client_tasks.export()) == 44
    assert epo.requests[0] == ('clienttask.export', {})
    assert epo.client_tasks.import_tasks([SCDisableTask('D'), SCPullInventoryTask('P')]) == 2
    command, body = epo.requests[1]
    assert command == 'clienttask.importClientTask'
    assert b'name="uploadFile"; filename="clienttasks.xml"' in body
    assert b'typeid="Pull Inventory"' in body
    with pytest.raises(EPOError, match='differs by case only'):
        epo.client_tasks.import_tasks(SCDisableTask('d'))


def test_run_resolves_the_task():
    epo = FakeServer(FIND, 'OK:\r\nSucceeded', FIND)
    assert epo.client_tasks.run(SCPullInventoryTask('Pull'), ['W10ENTB01', 4]) == 'Succeeded'
    command, fields = epo.requests[1]
    assert command == 'clienttask.run'
    assert fields == {'names': 'W10ENTB01,4', 'productId': 'SOLIDCORE_META', 'taskId': '195',
                      'retryAttempts': '1', 'retryIntervalInSeconds': '30',
                      'abortAfterMinutes': '5', 'useAllAgentHandlers': 'false',
                      'stopAfterMinutes': '20', 'randomMinutes': '0', 'timeoutInHours': '48'}
    # A name alone is ambiguous when two types have it.
    with pytest.raises(EPOError, match='2 client task'):
        epo.client_tasks.run('Pull', 'W10ENTB01')


def test_run_finds_the_sir_task_with_both_labels():
    # SIR extension 1.0.7.70 renamed "File Retrieval Task" to "File
    # Assembly Task" (same type id and settings).
    for label in ('File Retrieval Task', 'File Assembly Task'):
        find = ('OK:\r\n[{"productId": "SIR_____1000", "typeName": "System Information '
                'Reporter: ' + label + '", "objectName": "Acquire Files", "typeId": 30, '
                '"objectId": 155, "productName": "System Information Reporter"}]')
        epo = FakeServer(find, 'OK:\r\nSucceeded')
        assert epo.client_tasks.run(SIRFileRetrievalTask('Acquire Files'), 'W10ENTB01') == \
            'Succeeded'
        assert epo.requests[1][1]['taskId'] == '155'


def test_console_tasks_pass_check():
    # The tasks saved by the console (and by the server for a checked in
    # package, e.g. the EDR tasks with part of the Windows codes) are valid.
    for task in ClientTaskList.load_from_file(FIXTURE):
        task.check()
    edr = [task for task in ClientTaskList.load_from_file(FIXTURE)
           if task.platform == 'WVST|WVSTS|WNT7W|WIN8W|WIN8S|WINXW|WINXS']
    assert edr and all(task.platforms == ['Windows'] for task in edr)


def test_applied_query():
    epo = FakeServer('OK:\r\n[{"EPOLeafNode.NodeName": "W10ENTB01", '
                     '"EPOTaskAppliedTasks.NodeTxtPath": "\\\\Workstations\\\\W10ENTB01", '
                     '"EPOTaskAppliedTasks.ProductCode": "EPOAGENTMETA", '
                     '"EPOTaskAppliedTasks.TaskTypeId": 1, "EPOTaskAppliedTasks.Name": '
                     '"Update All", "EPOTaskAppliedTasks.upToDate": false}]')
    rows = epo.client_tasks.applied('W10ENTB01', 'Update All')
    assert rows == [{'system': 'W10ENTB01', 'path': '\\Workstations\\W10ENTB01',
                     'product_id': 'EPOAGENTMETA', 'type_number': 1, 'name': 'Update All',
                     'up_to_date': False}]
    fields = epo.requests[0][1]
    assert fields['target'] == 'EPOTaskAppliedTasks'
    assert fields['where'] == ('(and (eq EPOLeafNode.NodeName "W10ENTB01") '
                               '(eq EPOTaskAppliedTasks.Name "Update All"))')


def test_check_server(lab):
    packages = ('OK:\r\n[{"productID": "SIR_____1000", "packageBranch": "Current", '
                '"productDetectionProductVersion": "1.0.3", "buildNumber": "252", '
                '"packageLangID": "0409", "productDetectionPlatformID": "WVSTS:6:1:0|WINXS"}, '
                '{"productID": "VSCANDAT1000", "packageBranch": "Current"}]')
    find = ('OK:\r\n[{"productId": "SOLIDCORE_META", "typeName": "Solidcore 8.4.5: SC: '
            'Disable", "objectName": "Claude - SC Disable Test", "typeId": 19, "objectId": 185}]')
    epo = FakeServer(find, packages)
    tasks = ClientTaskList()
    tasks.add(SCDisableTask('CLAUDE - SC DISABLE TEST'))
    tasks.add(TADeploymentTask('D', [DeploymentItem('SIR_____1000', '1.0.3252'),
                                     DeploymentItem('SIR_____1000X', '1.0')],
                               platforms=['Windows', 'Mac']))
    tasks.add(TAUpdateTask('U', ['VSCANDAT1000', 'AMCORDAT2000']))
    problems = tasks.check_server(epo)
    assert problems == [
        'Task "CLAUDE - SC DISABLE TEST": the server has "Claude - SC Disable Test" (Solidcore '
        '8.4.5: SC: Disable); the import skips a name that differs by case only.',
        'Task "D": package SIR_____1000 is not for the platforms Mac (console: "The selection '
        'is not valid for the selected platforms").',
        'Task "D": package SIR_____1000X 1.0 (Current, 0409) not in the repository.',
        'Task "U": package AMCORDAT2000 not in the repository.']
