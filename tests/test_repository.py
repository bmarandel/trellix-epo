"""
Main Repository and repositories (trellix_epo.repository,
trellix_epo.eporepository), without a server.

repository_packages.json: repository.findPackages of the ePO 5.10 Update 7
lab (48 lines: 46 packages of the Main Repository page, plus the ExtraDAT
and SuperDAT entries). repositories.json: repository.find of the lab (the
source and fallback sites and the Main Repository; no password).
"""

import doctest
import json
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import repository as module
from trellix_epo import eporepository as operations
from trellix_epo import EPOClient, Package, Repository, packages_to_markdown
from trellix_epo.epo import EPOError

FIXTURES = Path(__file__).parent / 'fixtures'
PACKAGES = (FIXTURES / 'repository_packages.json').read_text(encoding='utf-8')
REPOSITORIES = (FIXTURES / 'repositories.json').read_text(encoding='utf-8')


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


def test_docstring_examples():
    result = doctest.testmod(module)
    assert result.attempted >= 19 and result.failed == 0
    result = doctest.testmod(operations)
    assert result.attempted >= 3 and result.failed == 0


def test_packages_as_the_main_repository_page():
    epo = FakeServer('OK:\r\n' + PACKAGES)
    packages = epo.repository.packages()
    # The page lists 46 packages: not the ExtraDAT and SuperDAT entries.
    assert len(packages) == 46
    assert not any(package.placeholder for package in packages)
    assert epo.requests[0][0] == 'repository.findPackages'
    platform = [package for package in packages if package.product_id == 'ENDP_GS_1070'][0]
    assert (platform.name, platform.version, platform.minor_version, platform.branch,
            platform.language, platform.package_type) == (
                'Endpoint Security Platform', '26.8.0', '22584', 'Current', '0000', 'Install')
    assert platform.build_version == '26.8.022584'
    assert platform.platform_labels == ['Windows']
    assert platform.checkin_date.isoformat() == '2026-10-17T10:30:05+02:00'
    assert platform.distribution == 'licensed'
    firewall = [package for package in packages if package.product_id == 'ENDP_FW_1070'][0]
    assert firewall.dependency == 'ENDP_GS_1070'
    plugin = [package for package in packages if package.package_type == 'Plugin'][0]
    assert plugin.type_label == 'Plug-in'


def test_packages_filters():
    epo = FakeServer(*['OK:\r\n' + PACKAGES] * 4)
    assert len(epo.repository.packages(include_placeholders=True)) == 48
    dats = epo.repository.packages(package_type='DAT')
    assert {package.product_id for package in dats} >= {'VSCANDAT1000', 'AMCORDAT2000'}
    assert all(package.branch == 'Current' for package in epo.repository.packages(branch='Current'))
    assert [package.product_id for package in epo.repository.packages(
        'Endpoint Security Platform', product_id='ENDP_GS_1070')] == ['ENDP_GS_1070']
    assert epo.requests[3][1] == {'searchText': 'Endpoint Security Platform'}
    with pytest.raises(ValueError, match='Branch must be one of'):
        epo.repository.packages(branch='current')


def test_get():
    epo = FakeServer('OK:\r\n' + PACKAGES, 'OK:\r\n' + PACKAGES, 'OK:\r\n[]')
    assert epo.repository.get('ENDP_GS_1070').minor_version == '22584'
    assert epo.repository.get('ENDP_GS_1070', branch='Previous') is None
    assert epo.repository.get('NOPE') is None
    two = json.dumps([{'productID': 'X', 'packageType': 'Install', 'packageBranch': 'Current',
                       'packageLangID': language, 'checkinDate': '2026-10-17T10:30:05+02:00'}
                      for language in ('0409', '040c')])
    epo = FakeServer('OK:\r\n' + two, 'OK:\r\n' + two)
    with pytest.raises(EPOError, match=r'several languages \(0409, 040c\)'):
        epo.repository.get('X')
    assert epo.repository.get('X', language='040c').language == '040c'


def test_markdown():
    packages = [Package.from_json(item) for item in json.loads(PACKAGES)]
    text = packages_to_markdown([package for package in packages if not package.placeholder])
    assert text.count('\n') == 2 + 1 + 46
    assert ('| Endpoint Security Platform | Install | 26.8.0 | 22584 | 2026-10-17 10:30 | '
            'Licensed | Current | ENDP\\_GS\\_1070 | Language Neutral |') in text
    # Sorted by name as the page.
    names = [line.split(' | ')[0][2:] for line in text.splitlines()[4:]]
    assert names == sorted(names, key=str.lower)


def test_repositories():
    epo = FakeServer(*['OK:\r\n' + REPOSITORIES] * 2)
    repositories = epo.repository.repositories()
    assert [(item.name, item.kind, item.protocol) for item in repositories] == [
        ('TrellixFtpMigrated', 'mirror', 'HTTP'), ('Trellix HTTPS', 'fallback', 'HTTP'),
        ('ePO_W2022EPO510', 'master', 'SPIPE'), ('Local Source', 'mirror', 'UNC')]
    assert repositories[1].secure_port == 443
    assert repositories[3].location == '\\\\W2022EPO510\\LocalSource'
    assert [item.name for item in epo.repository.repositories(kind='master')] == [
        'ePO_W2022EPO510']
    assert isinstance(repositories[0], Repository)


def test_check_in(tmp_path):
    package = tmp_path / 'Stinger64-ePO.zip'
    package.write_bytes(b'PK zip')
    epo = FakeServer('OK:\r\ntrue', 'OK:\r\ntrue')
    assert epo.repository.check_in(str(package), branch='Evaluation') is True
    command, body = epo.requests[0]
    assert command == 'repository.checkInPackage'
    assert b'name="file"; filename="Stinger64-ePO.zip"' in body and b'PK zip' in body
    assert b'name="branch"\r\n\r\nEvaluation' in body and b'name="force"\r\n\r\ntrue' in body
    epo.repository.check_in('C:\\Packages\\sdat.exe', option='superdat', server_path=True)
    assert epo.requests[1][1] == {'packageLocation': 'C:\\Packages\\sdat.exe',
                                  'branch': 'Current', 'option': '/superdat', 'force': 'true'}
    with pytest.raises(ValueError, match='Option must be one of'):
        epo.repository.check_in(str(package), option='dat')


def test_change_branch_and_delete():
    epo = FakeServer('OK:\r\n' + PACKAGES, 'OK:\r\ntrue', 'OK:\r\ntrue', 'OK:\r\ntrue')
    platform = epo.repository.get('ENDP_GS_1070')
    assert epo.repository.change_branch(platform, 'Previous', move=True) is True
    assert epo.requests[1] == ('repository.changeBranch', {
        'productId': 'ENDP_GS_1070', 'packageType': 'Install', 'sourceBranch': 'Current',
        'targetBranch': 'Previous', 'packageVersion': '26.8.0', 'packageMinorVersion': '22584',
        'move': 'true'})
    with pytest.raises(ValueError, match='already in the Current branch'):
        epo.repository.change_branch(platform, 'Current')
    epo.repository.delete(platform)
    epo.repository.delete('VSCANDAT1000', 'DAT', 'Previous')
    assert epo.requests[2] == ('repository.deletePackage', {
        'productId': 'ENDP_GS_1070', 'packageType': 'Install', 'branch': 'Current'})
    assert epo.requests[3][1]['branch'] == 'Previous'
    with pytest.raises(ValueError, match='Give a Package'):
        epo.repository.delete('VSCANDAT1000')


def test_pull_and_replicate():
    # Answers of the lab: one package pulled, then an unknown product id.
    epo = FakeServer('OK:\r\nsuccess\nupdated: Evaluation\\EPOAGENT5000META\\5.8.7\\Update\\0000',
                     'OK:\r\nsuccess', 'OK:\r\ntrue', 'OK:\r\ntrue')
    assert epo.repository.pull('Trellix HTTPS', ['AMCORDAT2000', 'VSCANDAT1000'],
                               branch='Evaluation') == [
        'Evaluation\\EPOAGENT5000META\\5.8.7\\Update\\0000']
    assert epo.requests[0] == ('repository.pull', {
        'sourceRepository': 'Trellix HTTPS', 'targetBranch': 'Evaluation',
        'moveToPrevious': 'false', 'productList': 'AMCORDAT2000,VSCANDAT1000'})
    with pytest.raises(ValueError, match='At least one product'):
        epo.repository.pull('Trellix HTTPS', [])
    assert epo.repository.pull('Trellix HTTPS', 'NOPE_9999') == []
    epo.repository.replicate()
    epo.repository.replicate(['DR1', 'DR2'], incremental=True)
    assert epo.requests[2] == ('repository.replicate', {})
    assert epo.requests[3][1] == {'repositoryList': 'DR1|DR2', 'incremental': 'true'}


def test_sites():
    epo = FakeServer('OK:\r\n<ns:SiteLists/>\r\n',
                     'OK:\r\nsuccess\r\nskipped (conflict): TrellixFtpMigrated\r\n'
                     'skipped (conflict): Local Source')
    assert epo.repository.export_sites() == '<ns:SiteLists/>'
    assert epo.repository.import_sites('<ns:SiteLists/>', 'distributed', overwrite=True) == [
        'skipped (conflict): TrellixFtpMigrated', 'skipped (conflict): Local Source']
    command, body = epo.requests[1]
    assert command == 'repository.importRepositories'
    assert b'name="repositoryType"\r\n\r\ndistributed' in body
    with pytest.raises(ValueError, match='Repository type must be one of'):
        epo.repository.import_sites('<x/>', 'mirror')
