"""
Endpoint Security Storage Protection (es/sp): ICAP and NetApp policies.

enssp_policies.xml is an export of the lab ePO 5.10 (productId VSESTOMD1300)
with the "My Default" policies and two test copies changed in the console:

- "Claude - SP ICAP Test": connection list overwritten and filtered
  (10.1.1.1, 10.2.0.0), server configuration overwritten (0.0.0.0:1345),
  default and specified file types "abc xyz" without "Also scan for macros",
  MIME decoding on, macro heuristics off, 90 s / 50 threads, threats:
  Continue Scanning, ANSI log limited to 20 MB with session settings.
- "Claude - SP NetApp Test": filer list overwritten (filer01.claude.test,
  10.3.3.3), specified file types "doc pdf" + files with no extension,
  program heuristics off, 5 exclusions (pattern with/without subfolders,
  file type, created 30 days, modified 10 days), client exclusions
  overwritten, unwanted programs: Delete then Continue.
"""

from pathlib import Path

import pytest

from trellix_epo import ESSPPolicies, ESSPPolicyICAP, ESSPPolicyNetApp, SPExclusion

FIXTURE = Path(__file__).parent / 'fixtures' / 'enssp_policies.xml'


def load(cls, name):
    policies = ESSPPolicies()
    policies.load_from_file(str(FIXTURE))
    return cls(policies.get_policy(cls.TYPE, name))


def test_policies():
    policies = ESSPPolicies()
    policies.load_from_file(str(FIXTURE))
    assert [(item['typeid'], item['name']) for item in policies.list()] == [
        ('VSES1000_Icap_Policies', 'Claude - SP ICAP Test'),
        ('VSES1000_Icap_Policies', 'My Default'),
        ('VSES1000_Netapp_Policies', 'Claude - SP NetApp Test'),
        ('VSES1000_Netapp_Policies', 'My Default')]
    with pytest.raises(ValueError):
        ESSPPolicyICAP(policies.get_policy('VSES1000_Netapp_Policies', 'My Default'))


def test_icap_read():
    policy = load(ESSPPolicyICAP, 'Claude - SP ICAP Test')
    assert (policy.overwrite_connection_list, policy.filter_connections) == ('1', '1')
    assert policy.connection_list == ['10.1.1.1', '10.2.0.0']
    assert (policy.overwrite_server_config, policy.bind_address, policy.port) == (
        '1', '0.0.0.0', 1345)
    assert policy.get_file_types_to_scan() == {
        'mode': ESSPPolicyICAP.DEFAULT_AND_SPECIFIED, 'file_types': ['abc', 'xyz'],
        'no_extension': False, 'scan_macros': False}
    assert (policy.decode_mime, policy.macro_heuristics) == ('1', '0')
    assert (policy.max_scan_time, policy.scan_threads) == (90, 50)
    assert policy.get_threat_actions() == (ESSPPolicyICAP.CONTINUE, '0')
    report = policy.get_reporting()
    assert (report['format'], report['max_size_mb'], report['log_settings']) == ('0', '20', '1')
    default = load(ESSPPolicyICAP, 'My Default')
    assert default.get_file_types_to_scan()['mode'] == ESSPPolicyICAP.ALL_FILES
    assert default.get_threat_actions() == (ESSPPolicyICAP.CLEAN, ESSPPolicyICAP.CONTINUE)


def test_netapp_read():
    policy = load(ESSPPolicyNetApp, 'Claude - SP NetApp Test')
    assert policy.overwrite_filer_list == '1'
    assert policy.filer_list == ['filer01.claude.test', '10.3.3.3']
    assert policy.get_filer_account()['enabled'] == '0'
    assert not policy.get_filer_account()['password_set']
    assert policy.get_file_types_to_scan() == {
        'mode': ESSPPolicyNetApp.SPECIFIED_ONLY, 'file_types': ['doc', 'pdf'],
        'no_extension': True, 'scan_macros': False}
    assert [(exclusion.item, exclusion.subfolders) for exclusion in policy.exclusions] == [
        ('C:\\Claude\\Data\\', True), ('All files of type tmp', False),
        ('Created 30 or more days ago', False), ('C:\\Temp\\*.log', False),
        ('Modified 10 or more days ago', False)]
    assert policy.overwrite_client_exclusions == '1'
    assert policy.get_unwanted_program_actions() == (ESSPPolicyNetApp.DELETE,
                                                     ESSPPolicyNetApp.CONTINUE)
    assert load(ESSPPolicyNetApp, 'My Default').overwrite_client_exclusions == '1'


def test_icap_write():
    policy = load(ESSPPolicyICAP, 'My Default')
    policy.connection_list = ['192.168.1.10']
    policy.port = 1350
    policy.set_file_types_to_scan(ESSPPolicyICAP.DEFAULT_AND_SPECIFIED, ['abc'],
                                  no_extension=True, scan_macros=True)
    assert policy.get_setting_value('ICAPDetection', 'LocalExtensionMode') == '2'
    assert policy.get_setting_value('ICAPDetection', 'szIncludeExts') == '::: abc'
    assert policy.get_setting_value('ICAPGeneral', 'szICAPClient_0') == '192.168.1.10'
    assert policy.get_setting_value('ICAPGeneral', 'dwICAPClientCount') == '1'
    policy.set_threat_actions(ESSPPolicyICAP.CONTINUE)
    assert policy.get_threat_actions() == ('1', '0')
    with pytest.raises(ValueError):
        policy.set_threat_actions(ESSPPolicyICAP.DELETE, ESSPPolicyICAP.CONTINUE)
    with pytest.raises(ValueError):
        policy.port = 70000
    with pytest.raises(ValueError):
        policy.set_file_types_to_scan(ESSPPolicyICAP.SPECIFIED_ONLY, [])
    policy.set_reporting(max_size_mb=100, format='2')
    assert policy.get_reporting()['max_size_mb'] == '100'


def test_netapp_write():
    policy = load(ESSPPolicyNetApp, 'My Default')
    assert policy.add_exclusion(SPExclusion.pattern('D:\\Backup\\', subfolders=True))
    assert policy.add_exclusion(SPExclusion.file_age(7, SPExclusion.CREATED))
    assert not policy.add_exclusion(SPExclusion.pattern('D:\\Backup\\', subfolders=True))
    with pytest.raises(ValueError):
        policy.add_exclusion(SPExclusion.file_age(7, SPExclusion.ACCESSED))
    with pytest.raises(ValueError):
        policy.add_exclusion(SPExclusion.file_age('x'))
    assert policy.get_setting_value('NetAppExclusions', 'ExcludedItem_0') == '3|4|D:\\Backup\\'
    assert policy.get_setting_value('NetAppExclusions', 'ExcludedItem_1') == '2|0|7'
    assert policy.remove_exclusion(SPExclusion.file_age(7, SPExclusion.CREATED))
    assert len(policy.exclusions) == 1
    policy.overwrite_client_exclusions = '0'
    assert policy.get_setting_value('NetAppExclusions', 'bAppendExclusions') == '1'
    policy.filer_list = ['nas01']
    assert policy.get_setting_value('NetAppGeneral', 'dwFilerCount') == '1'
    # No account in My Default: it can only be defined in the console.
    with pytest.raises(ValueError):
        policy.set_filer_account('1')


ENCRYPTED = 'EPOAES128:0876c27d771738022cecfbe4d4a2613fbc7bd181bf66d0807df30df6f39dcc02'


def test_netapp_filer_account_defined_in_the_console():
    # Account saved in the ePO 5.10 console (lab): the server encrypts the
    # password with its own key; the library keeps it and can only
    # enable/disable the account.
    policy = load(ESSPPolicyNetApp, 'My Default')
    for name, value in [('szFilerUsername', 'test'), ('szFilerDomainName', 'LOCAL'),
                        ('szFilerPassword', ENCRYPTED), ('szFilerPasswordConfirm', ENCRYPTED)]:
        policy.set_setting_value('NetAppGeneral', name, value)
    assert policy.get_filer_account() == {'enabled': '0', 'user': 'test', 'domain': 'LOCAL',
                                          'password_set': True}
    policy.set_filer_account('1')
    assert policy.get_setting_value('NetAppGeneral', 'bUseGroupedFilerAccount') == '1'
    assert policy.get_setting_value('NetAppGeneral', 'szFilerPassword') == ENCRYPTED
    text = policy.to_markdown()
    assert '| User name | test |' in text and '| Domain | LOCAL |' in text
    assert 'EPOAES128' not in text
    policy.set_filer_account('0')
    assert policy.get_setting_value('NetAppGeneral', 'szFilerPassword') == ENCRYPTED


def test_markdown():
    text = load(ESSPPolicyICAP, 'Claude - SP ICAP Test').to_markdown()
    assert 'Endpoint Security Storage Protection - ICAP Policies policy' in text
    for row in ['| 2 | 10.2.0.0 |', '| Port number | 1345 |',
                '| File types to scan | Default and specified file types |',
                '| Also scan for macros in all files | No |',
                '| Perform this action first | Continue Scanning |',
                '| Log file format | ANSI |']:
        assert row in text, row
    # No second action after "Continue Scanning", as in the console.
    assert text.count('If the first action fails') == 1
    text = load(ESSPPolicyNetApp, 'Claude - SP NetApp Test').to_markdown()
    for row in ['| 1 | filer01.claude.test |', '| 1 | C:\\\\Claude\\\\Data\\\\ | Yes |',
                '| 4 | C:\\\\Temp\\\\\\*.log | No |', '| 5 | Modified 10 or more days ago | -- |',
                '| Include files with no extension | Yes |']:
        assert row in text, row
    assert [heading for heading, _ in load(ESSPPolicyNetApp, 'My Default').md_sections()] == [
        'Filers', 'Scan Items', 'Exclusions', 'Performance', 'Actions', 'Reports']
