"""
Ported from the user's own test-oas.py, run against oas_policy.xml - now the
most recent ENS Threat Prevention On-Access Scan export (ePO 5.10.0.0),
which also introduced the "Ransomware" options (detect_unknown_ransomware,
ransomware_bait_files).
"""

from pathlib import Path

import pytest

from trellix_epo import ESTPPolicyOnAccessScan, OASProcessList, OASExclusionList

FIXTURE = Path(__file__).parent / 'fixtures' / 'oas_policy.xml'


@pytest.fixture
def oas_policy():
    policy = ESTPPolicyOnAccessScan()
    policy.load_from_file(str(FIXTURE))
    return policy


def test_epo_metadata(oas_policy):
    assert oas_policy.get_epo_server() == 'W2022EPO510'
    assert oas_policy.get_epo_version() == '5.10.0.0'


def test_gti_level(oas_policy):
    assert oas_policy.get_gti_level() == '5'


def test_ransomware_options(oas_policy):
    # Detect unknown ransomware based on behaviour - checked by default.
    assert oas_policy.detect_unknown_ransomware == '1'
    oas_policy.detect_unknown_ransomware = '0'
    assert oas_policy.detect_unknown_ransomware == '0'

    # Create ransomware bait files on file system - unchecked by default.
    assert oas_policy.ransomware_bait_files == '0'
    oas_policy.ransomware_bait_files = '1'
    assert oas_policy.ransomware_bait_files == '1'


def test_process_list_workflow(oas_policy):
    proc_list = OASProcessList(oas_policy.get_process_list())

    proc_list.add('test.exe', 'Low Risk')
    assert proc_list.add('test.exe', 'High Risk') is False
    proc_list.add_low_risk('test_low.exe')
    proc_list.add_high_risk('test_high.exe')
    assert proc_list.contains('test.exe') is True
    assert proc_list.contains_low_risk('test_low.exe') is True
    assert proc_list.contains_high_risk('test_high.exe') is True

    proc_list.remove('test.exe')
    assert proc_list.contains('test.exe') is False


def test_exclusion_list_workflow(oas_policy):
    excl_list = OASExclusionList(oas_policy.get_exclusion_list())

    excl_list.add_folder('C:\\Test\\Folder\\', True, True, True, 'Test folder to remove')
    assert excl_list.contains_folder('C:\\Test\\Folder\\') is True
    assert excl_list.remove_folder('C:\\Test\\Folder\\') is True
    assert excl_list.contains_folder('C:\\Test\\Folder\\') is False

    excl_list.add_file_name('C:\\Test\\test.ben', True, True, 'Test file to remove')
    assert excl_list.contains_file_name('C:\\Test\\test.ben') is True
    assert excl_list.remove_file_name('C:\\Test\\test.ben') is True
    assert excl_list.contains_file_name('C:\\Test\\test.ben') is False

    excl_list.add_file_type('TEST', True, True, 'TEST extension to remove')
    assert excl_list.contains_file_type('TEST') is True
    assert excl_list.remove_file_type('TEST') is True
    assert excl_list.contains_file_type('TEST') is False

    excl_list.add_file_created(10, True, True, 'Created 10 days ago to remove')
    assert excl_list.contains_file_created(10) is True
    assert excl_list.remove_file_created(10) is True
    assert excl_list.contains_file_created(10) is False

    excl_list.add_file_modified(20, True, True, 'Modified 20 days ago to remove')
    assert excl_list.contains_file_modified(20) is True
    assert excl_list.remove_file_modified(20) is True
    assert excl_list.contains_file_modified(20) is False


# ------------------------------ Values accepted by the console ------------------------------
# Results of the page validators (Threat Prevention 26.8.0.16045) run on the lab:
# isValidPath, IsValidExclusionFileType, validateFileTypes, validateProcessItem.
from trellix_epo.validators import (is_ens_path, is_ens_exclusion_file_type,
                                            is_ens_file_types, is_ens_process_name)

ENS_PATHS = [('C:\\Temp\\', True), ('C:\\Temp\\a.exe', True), ('a.exe', True),
             ('Temp\\a.exe', False), ('**\\Temp\\', True), ('*\\Temp\\', True), ('\\Temp\\', True),
             ('\\\\server\\share\\', True), ('\\\\?\\C:\\x', False), ('C:\\a\\\\b', False),
             ('%TEMP%\\x', True), ('%TEMP\\x', False), ('D:a', False), ('C:/x', False),
             ('*', False), ('???', False), ('?:\\x\\', True), ('/opt/app/', False),
             ('C:\\a<b', False), ('  C:\\x  ', True)]
EXCLUSION_FILE_TYPES = [('exe', True), ('.exe', False), ('ex*', False), ('???', False),
                        ('e?e', True), (':::', True), ('ex:e', False), ('', False)]
FILE_TYPE_LISTS = [('doc docx :::', True), ('doc,docx', True), ('doc;docx', True), ('doc*', False),
                   ('???', False), ('do?', True), ('a:b', False), ('doc/x', False),
                   ('doc,docx,:::', False)]
PROCESS_NAMES = [('C:\\Tools\\app.exe', True), ('app.exe', True), ('Tools\\app.exe', True),
                 ('C:\\Tools\\\\app.exe', False), ('/usr/bin/app', True), ('?:\\x\\a.exe', True),
                 ('a*.exe', True), ('C:app.exe', False), ('a:b.exe', False), (' app.exe ', True)]


def test_console_validators():
    for function, cases in [(is_ens_path, ENS_PATHS),
                            (is_ens_exclusion_file_type, EXCLUSION_FILE_TYPES),
                            (is_ens_file_types, FILE_TYPE_LISTS),
                            (is_ens_process_name, PROCESS_NAMES)]:
        for value, valid in cases:
            assert bool(function(value)) is valid, (function.__name__, value)


def test_console_values(oas_policy):
    for value in (10, 9999, '45'):
        oas_policy.set_max_scan_time(value)
    for value in (9, 10000, 'ten'):
        with pytest.raises(ValueError):
            oas_policy.set_max_scan_time(value)
    oas_policy.set_alert_message('m' * 256)
    for message in ('', 'm' * 257):
        with pytest.raises(ValueError):
            oas_policy.set_alert_message(message)
    oas_policy.set_process_list([['/usr/bin/curl', 'High Risk'], ['?:\\Backup\\agent.exe', 'Low Risk']])
    for table in ([['C:app.exe', 'Low Risk']], [['a' * 260, 'Low Risk']],
                  [['app.exe', 'Low Risk'], ['APP.EXE', 'High Risk']]):
        with pytest.raises(ValueError):
            oas_policy.set_process_list(table)
    oas_policy.set_what_to_scan('4', 'doc,docx,xls?,:::')            # stored as typed in the lab
    for extensions in ('doc*', 'x' * 3001):
        with pytest.raises(ValueError):
            oas_policy.set_what_to_scan('4', extensions)
    oas_policy.set_script_scan_exclusions(['https://intranet.example.com/', 'portal.example.com'])
    for urls in (['u' * 2049], ['a.example.com', ' a.example.com ']):
        with pytest.raises(ValueError):
            oas_policy.set_script_scan_exclusions(urls)


def test_exclusion_values(oas_policy):
    excl_list = OASExclusionList(oas_policy.get_exclusion_list())
    excl_list.add_folder('**\\Backup\\')
    excl_list.add_folder('/var/cache/app/')
    excl_list.add_file_name('%ProgramData%\\Vendor\\db.dat')
    excl_list.add_file_type(':::')
    excl_list.add_file_modified(9999)
    for call in (lambda: excl_list.add_folder('Temp\\x\\'),
                 lambda: excl_list.add_folder('C:\\' + 'a' * 255 + '\\'),
                 lambda: excl_list.add_file_type('.exe'),
                 lambda: excl_list.add_file_type('e' * 101),
                 lambda: excl_list.add_file_created(0),
                 lambda: excl_list.add_file_created(10000)):
        with pytest.raises(ValueError):
            call()
