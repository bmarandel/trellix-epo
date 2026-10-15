"""
ePO Web API client (trellix_epo.epo), without a server: _send is
replaced by a fake server that records the requests and returns answers
copied from the ePO 5.10 Update 7 lab.
"""

import doctest
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import epo as epo_module
from trellix_epo import ESTPPolicies, Policies, SCRuleGroups, SIRPolicies
from trellix_epo.epo import EPOClient, EPOError

FIXTURES = Path(__file__).parent / 'fixtures'


class FakeEPO(EPOClient):
    """
    EPOClient whose server is a list of answers; the requests are kept in
    self.requests as (command, output, fields or multipart body, headers).
    """

    def __init__(self, *answers):
        """
        :param: answers: The raw answers of the server, in the order of the
                         requests, e.g. 'OK:\\r\\n[...]' or 'Error 1 :\\r\\n...'.
        """
        super(FakeEPO, self).__init__('https://epo.example.com:8443/', 'admin', 'secret')
        self.answers = list(answers)
        self.requests = []

    def _send(self, request):
        """
        Records the request (command, :output, form fields as a dictionary or
        the multipart body as bytes, headers) and returns the next answer.
        """
        url = urllib.parse.urlsplit(request.full_url)
        command = url.path.split('/remote/')[1]
        output = urllib.parse.parse_qs(url.query)[':output'][0]
        if request.get_header('Content-type').startswith('multipart/'):
            fields = request.data
        else:
            fields = dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))
        self.requests.append((command, output, fields, dict(request.header_items())))
        return self.answers.pop(0)


def test_docstring_examples():
    result = doctest.testmod(epo_module)
    assert result.attempted >= 14 and result.failed == 0


def test_call_request():
    epo = FakeEPO('OK:\r\n[{"EPOLeafNode.NodeName": "rhel96srv"}]')
    rows = epo.query('EPOLeafNode', '(select (top 1) EPOLeafNode.NodeName)')
    assert rows == [{'EPOLeafNode.NodeName': 'rhel96srv'}]
    command, output, fields, headers = epo.requests[0]
    assert (command, output) == ('core.executeQuery', 'json')
    assert fields == {'target': 'EPOLeafNode', 'select': '(select (top 1) EPOLeafNode.NodeName)'}
    assert headers['Authorization'] == 'Basic YWRtaW46c2VjcmV0'     # admin:secret
    assert 'secret' not in repr(epo)


def test_errors():
    epo = FakeEPO("Error 0 :\r\nInvalid ProductID 'NOPE'",
                  'OK:\r\n{"result": null, "success": false, "errorCode": 1, '
                  '"message": "Possible values for the ruleGroupOS parameter are WIN or UNIX."}')
    with pytest.raises(EPOError) as error:
        epo.export_policies('NOPE')
    assert (error.value.command, error.value.code) == ('policy.export', 0)
    with pytest.raises(EPOError) as error:
        epo.call('scor.rulegroup.find', 'WINDOWS', 'APPLICATION_CONTROL')
    assert error.value.code == 1 and 'WIN or UNIX' in error.value.message


def test_from_environment(monkeypatch):
    monkeypatch.setenv('EPO_URL', 'https://epo.example.com:8443')
    monkeypatch.setenv('EPO_USER', 'admin')
    monkeypatch.delenv('EPO_PASSWORD', raising=False)
    with pytest.raises(ValueError, match='EPO_PASSWORD'):
        EPOClient.from_environment()
    monkeypatch.setenv('EPO_PASSWORD', 'secret')
    assert EPOClient.from_environment(verify=False).url == 'https://epo.example.com:8443'


def test_export_policies():
    xml = (FIXTURES / 'sir_limits.xml').read_text(encoding='utf-8')
    epo = FakeEPO('OK:\r\n' + xml, 'OK:\r\n' + xml)
    policies = epo.export_policies('SIR_____1000')
    assert isinstance(policies, SIRPolicies)
    assert policies.contain('SIR_____1000_COLLECT_DATA', 'Claude - SIR Collect Test')
    assert epo.requests[0][2] == {'productId': 'SIR_____1000'}
    # A product without a class of the library gives Policies.
    assert type(epo.export_policies('DXL_______1000')) is Policies
    assert EPOClient.PRODUCTS['ENDP_AM_1000'] is ESTPPolicies


def test_import_policies():
    epo = FakeEPO('OK:\r\nNumber of imported policies: 1 Number of matching policies that '
                  'were not overwritten: 1\r\n')
    policies = SIRPolicies()
    policies.load_from_file(str(FIXTURES / 'sir_limits.xml'))
    assert epo.import_policies(policies, force=True).startswith('Number of imported policies: 1')
    command, output, body, headers = epo.requests[0]
    assert (command, output) == ('policy.importPolicy', 'terse')
    assert headers['Content-type'].startswith('multipart/form-data; boundary=')
    assert b'name="force"\r\n\r\ntrue\r\n' in body
    assert b'filename="policies.xml"' in body
    assert policies.get_xml_content() in body


def test_rule_groups():
    xml = ('<Rule-Groups><Rule-Group name="Docker" platform="WIN" type="awl" '
           'is-read-only="false"></Rule-Group><Active-Directories/></Rule-Groups>')
    epo = FakeEPO('OK:\r\nDocker\r\nGlobal Rules\r\n', 'OK:\r\n' + xml,
                  'OK:\r\n{"result": null, "success": false, "errorCode": 0, "message": '
                  '"No rule groups found with type: CHANGE_CONTROL and operating system: WIN."}',
                  'OK:\r\nDocker\r\n')
    group = epo.export_rule_group(SCRuleGroups.WINDOWS, SCRuleGroups.APPLICATION_CONTROL, 'Docker')
    assert group.get_name() == 'Docker'
    assert epo.requests[1][2] == {'param1': 'WIN', 'param2': 'APPLICATION_CONTROL',
                                  'ruleGroupName': 'Docker'}
    assert epo.find_rule_groups(SCRuleGroups.WINDOWS, SCRuleGroups.CHANGE_CONTROL) == []
    # An unknown name is not exported (the server would return "Global Rules").
    assert epo.export_rule_group(SCRuleGroups.WINDOWS, SCRuleGroups.APPLICATION_CONTROL,
                                 'Nope') is None
    assert len(epo.requests) == 4
    with pytest.raises(ValueError):
        epo.find_rule_groups('WINDOWS', SCRuleGroups.APPLICATION_CONTROL)


# Answers of scor.rulegroup.import on the lab (JSON even if not asked).
IMPORT_MESSAGE = ('{{"result": null, "success": true, "errorCode": 0, "message": "success::::'
                  'Rule groups were {}imported successfully.</br></br>For details, review '
                  'information for the &nbsp;<b>Import Solidcore Rule Groups</b>&nbsp;server '
                  'task."}}')


def test_import_rule_groups():
    epo = FakeEPO('OK:\r\n' + IMPORT_MESSAGE.format(''), 'OK:\r\n' + IMPORT_MESSAGE.format('not '))
    assert epo.import_rule_groups(SCRuleGroups(), override=True) == (
        'Rule groups were imported successfully. For details, review information for the '
        'Import Solidcore Rule Groups server task.')
    assert b'name="override"\r\n\r\ntrue\r\n' in epo.requests[0][2]
    with pytest.raises(EPOError, match='not imported successfully'):
        epo.import_rule_groups(SCRuleGroups())


def test_rename_rule_group():
    epo = FakeEPO('OK:\r\nRule group with type: APPLICATION_CONTROL, operating system: WIN, '
                  'and name: Docker 2, is updated.\r\n')
    assert epo.rename_rule_group(SCRuleGroups.WINDOWS, SCRuleGroups.APPLICATION_CONTROL,
                                 'Docker', 'Docker 2').endswith('is updated.')
    assert epo.requests[0][2] == {'param1': 'WIN', 'param2': 'APPLICATION_CONTROL',
                                  'param3': 'Docker', 'param4': 'Docker 2'}
