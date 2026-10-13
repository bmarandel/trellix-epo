"""
Ported from the user's own test-ods.py, run against a real ePO export
(ods_policy.xml) captured from a live ePO 5.10.0.0 server. The original
script only printed the locations/exclusions; the exact values observed
during this session's dry run are now asserted, so this test also protects
the fs_locations key template (szScanItem{row}, no underscore) touched by
the get_indexed_list/set_indexed_list refactor.
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import ESTPPolicyOnDemandScan, ODSLocationList, ODSExclusionList

FIXTURE = Path(__file__).parent / 'fixtures' / 'ods_policy.xml'


@pytest.fixture
def ods_policy():
    policy = ESTPPolicyOnDemandScan()
    policy.load_from_file(str(FIXTURE))
    return policy


def test_epo_metadata(ods_policy):
    assert ods_policy.get_epo_server() == 'W2K12R2EPO510'
    assert ods_policy.get_epo_version() == '5.10.0.0'


def test_fs_locations(ods_policy):
    locations = ods_policy.fs_locations
    assert locations == [
        'SpecialScanForRootkits', 'SpecialMemory', 'SpecialCritical', 'My Computer',
        'LocalDrives', 'All fixed disks', 'All removable media', 'All Network drives',
        'HomeDir', 'ProfileDir', 'WinDir', 'ProgramFilesDir', 'TempDir',
        'SpecialRecycleName', 'C:\\TestBen', 'D:\\Apps', 'SpecialRegistry',
    ]
    loc_list = ODSLocationList(locations)
    assert len(loc_list.loc_list) == 17


def test_fs_exclusion_list(ods_policy):
    exclusions = ods_policy.fs_exclusion_list
    assert exclusions == [['4', '0', 'LOG', '']]
    excl_list = ODSExclusionList(exclusions)
    assert len(excl_list.excl_list) == 1
    assert excl_list.contains_file_type('LOG') is True


def test_gti_level(ods_policy):
    # GTISensitivityLevel lives in the <scan>_GTI section (was looked up in
    # <scan>_ScanOptions, so the getter returned None and the setter failed).
    assert ods_policy.fs_gti_level == '3'
    assert ods_policy.qs_gti_level == '3'
    assert ods_policy.rs_gti_level == '3'
    assert ods_policy.set_fs_gti_level('5')
    assert ods_policy.fs_gti_level == '5'
    assert ods_policy.qs_gti_level == '3'


# ------------------------------ Values accepted by the console ------------------------------
# Bounds and rules of the On-Demand Scan page (Threat Prevention 26.8.0.16045), checked on the
# lab: the defer settings are reset by the console when "User can defer scans" is unchecked, a
# user name makes the (console only) password required.
from mcafee_epo_policies.es.tp.ondemandscan import check_scan_location, DEFAULT_DEFER_MESSAGE

SCAN_LOCATION_PATHS = [('C:\\Data', True), ('D:\\Share\\folder\\', True), ('\\\\server\\share', True),
                       ('%TEMP%', True), ('relative', True), ('C:\\a;b', False), ('C:\\a*', False),
                       ('C:\\a?', False), ('C:/x', False), ('/var/data', True), ('C:\\a"b', False),
                       ('C:\\a|b', False), ('C:\\a<b', False), (' C:\\x', True)]


def test_console_values(ods_policy):
    ods_policy.set_fs_user_defer('0')
    with pytest.raises(ValueError):
        ods_policy.set_fs_user_defer_max(5)                    # "User can defer scans" off
    ods_policy.set_fs_user_defer('1')
    ods_policy.set_qs_user_defer('1')
    for setter, minimum, maximum in [(ods_policy.set_fs_user_defer_max, 1, 23),
                                     (ods_policy.set_fs_user_defer_msg_duration, 30, 300),
                                     (ods_policy.set_qs_user_defer_msg_duration, 30, 300),
                                     (ods_policy.set_fs_perf_max_cpu, 25, 99)]:
        setter(minimum)
        setter(maximum)
        for value in (minimum - 1, maximum + 1, 'x'):
            with pytest.raises(ValueError):
                setter(value)
    ods_policy.set_fs_user_defer_msg('F' * 60)
    ods_policy.set_qs_user_defer_msg('Q' * 50)
    ods_policy.set_qs_user_defer_msg(DEFAULT_DEFER_MESSAGE)       # 55 characters, console default
    for setter, message in [(ods_policy.set_fs_user_defer_msg, 'F' * 61),
                            (ods_policy.set_qs_user_defer_msg, 'Q' * 51)]:
        with pytest.raises(ValueError):
            setter(message)
    ods_policy.set_fs_domain_name('D' * 100)
    with pytest.raises(ValueError):
        ods_policy.set_fs_domain_name('D' * 101)
    with pytest.raises(ValueError):
        ods_policy.set_fs_user_name('svc_scan')                 # password defined in the console
    for path, valid in SCAN_LOCATION_PATHS:
        if valid:
            check_scan_location(path)
        else:
            with pytest.raises(ValueError):
                check_scan_location(path)
    ods_policy.set_fs_locations(['My Computer', 'D:\\Data\\', '/var/data', 'SpecialRegistry'])
    with pytest.raises(ValueError):
        ods_policy.set_fs_locations(['C:\\' + 'a' * 254])
    ods_policy.set_fs_file_types('4', 'doc,docx,:::')
    with pytest.raises(ValueError):
        ods_policy.set_fs_file_types('4', 'doc*')
    ods_policy.set_fs_exclusion_list([['3', '7', '**\\Backup\\', 'N' * 256], ['2', '3', '9999', '']])
    for row in (['3', '7', 'C:\\x\\', 'N' * 257], ['3', '7', 'Temp\\x\\', ''],
                ['4', '3', '.exe', ''], ['2', '3', '10000', '']):
        with pytest.raises(ValueError):
            ods_policy.set_fs_exclusion_list([row])
