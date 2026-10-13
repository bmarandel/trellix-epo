"""
Solidcore: values accepted by the console (lab extension 8.4.0.58).

The rules come from the console pages (scor.validation of commonUtils.jsp,
the dialogs of the Application Control, Change Control, Integrity Monitor
and Exception Rules policies, the Numberbox limits of the Configuration and
Application Control Options pages) and from the ePO server, whose checks
were probed on the lab with the save actions of the pages
(saveGeneralPolicy.do, saveAwlOptionPolicies.do) on test copies. The
results below are those of the lab (1 accepted, 0 refused).

sc_limits.xml: "Claude - SC ... Test" copies written by the library at the
limits, imported, loaded by the console pages and saved again through
them (server answer code 0); the AWL Rules copy shows how the 8.4 console
stores trusted directories in "General_<n>" sections (the 4 directories of
the lab template it came from were removed from the fixture).
"""

from pathlib import Path

import pytest

from mcafee_epo_policies.sc import SCPolicies
from mcafee_epo_policies.sc.awl import SCAWLPolicyOptions, SCAWLPolicyRules
from mcafee_epo_policies.sc.cc import SCCCPolicyRules
from mcafee_epo_policies.sc.fim import SCFIMPolicyRules
from mcafee_epo_policies.sc.gen import SCGENPolicyConfiguration, SCGENPolicyExceptionRules
from mcafee_epo_policies.sc.rulegroups import check_rule_group_name
from mcafee_epo_policies.validators import (is_sc_path, is_sc_updater_name, is_sc_cc_path,
                                            is_sc_directory, is_sc_file_name, is_sc_email_list,
                                            is_sc_website, is_sc_exclusion_value, is_sc_fim_user,
                                            is_sc_fim_pattern, is_sc_registry_key,
                                            is_sc_top_level_path)

FIXTURE = Path(__file__).parent / 'fixtures' / 'sc_limits.xml'


def load(cls, type_id, name):
    policies = SCPolicies()
    policies.load_from_file(str(FIXTURE))
    return cls(policies.get_policy(type_id, name))


WIN_PATHS = ['C:\\Tools\\a.exe', 'C:\\Tools\\', 'C:\\', 'c:\\x', '*', '*\\a.exe', 'C:\\*\\a.exe',
 'C:\\Tools\\*', 'C:\\Tools\\*\\', 'C:\\a*b.exe', '\\\\server\\share\\a.exe', '\\\\\\server',
 '%WINDIR%\\System32', '%ProgramFiles(x86)%\\App', '%windir%', '%win dir%\\a', '%%\\a',
 'C:/Tools', 'C:\\a:b', 'C:\\a?b', 'C:\\a"b', 'C:\\a<b', 'C:\\a|b', 'C:\\Tools\\\\a',
 'C:\\.\\a', 'C:\\Tools\\.', 'a.exe', 'Tools\\a.exe', '?:\\a', '*:\\a', ':\\a', 'C:a', '',
 ' C:\\a', 'C:\\a ',
 'C:\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 'C:\\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 '\\\\?\\C:\\a', 'C:\\a\\*\\*\\b', '%TEMP%\\*.tmp', '\\a', '/usr/bin']
UNIX_PATHS = ['/usr/bin', '/usr/bin/', '/', '*', '/usr/*', '/usr/*/bin', '/usr/b*n', 'usr/bin', '/a:b',
 '/a?b', '/a<b', '/a>b', '/a|b', '/a b', '/a\\b', '', ' /a', '//a', '/a*', '/*/']
LAB_PATHS = {'cc': '111100111110111100111110000010000011011100',
 'du': '111100111110111100010000000000000001001100',
 'fn': '000000000000001000000000001000001000000000',
 'up': '111100111110111111111110001110111111011111',
 'vpU': '11110100000001100100',
 'vpW': '111110100010111100000000000000000011001000'}
MAILS = [(['admin@example.com', 'a@example.com;b@example.com', 'a@example.com,b@example.com', 'a@b',
   'a@b.abcdefg', 'A@EXAMPLE.COM', '', ' a@example.com'],
  '11001100'),
 (['a@example.com', 'a@example.c', 'a@example.co', 'a@example.abcdefghijklm', 'a@ex_ample.com',
   'a_b@example.com', "a'b@example.com", 'a+b@example.com', 'a.b@example.com', '.a@example.com',
   'a..b@example.com', 'a@-example.com', 'a@example..com', 'a@example.com;',
   'a@example.com; b@example.com', 'a@example.com;;b@example.com', 'a@123.45.67.89',
   'a@[10.0.0.1]', 'a@example.com1', 'é@example.com', 'a b@example.com', 'a@example.com ',
   '"a"@example.com', 'a@example.com;bad', 'a@example.12'],
  '1011110010010010000000000'),
 (['a@x.com ;b@x.com', 'a@x.com;  b@x.com', 'a@x.com;\tb@x.com', 'a@sub.example.co.uk',
   'a-b@x.com', 'a@x-.com', 'a@x.c0m', 'A_B.C-D@X_Y.COM', 'a@x.com; b@x.com; c@x.com', 'a@.com',
   '@x.com', 'a@x.com,b@x.com'],
  '100111001000'),
 (['a@b.cc', 'a-@x.com', '-a@x.com', 'a@x_y.com', 'a.@x.com', 'a@x.com ; b@x.com',
   'a@x.com;b@x.com ', '1@2.ab'],
  '11110101'),
 (['a.b-c@x.com', 'a_b.c@x.com', 'a@x_y.COM', 'A_B@X.COM', 'a.b_c@x.com', 'ab.c-d@x.com',
   'A.B@X_Y.COM', 'a_b.c-d@x.com', 'a@X_Y.COM', 'A_B.C@x.com', 'a.b@x_y.com', 'a@x_y.z_w.com'],
  '011100101110')]
SITES = [(['www.example.com', 'example.com', 'http://www.example.com', 'https://example.com/path?x=1',
   'ftp://example.com', 'file://x', 'example', 'http://example', '10.0.0.1',
   'http://10.0.0.1:8080/', 'www.example.com/path', 'https://exa mple.com',
   'https://example.com/a b', 'javascript:alert(1)', '<b>x</b>', 'https://example.com/<x>',
   'www.exa_mple.com', 'HTTPS://EXAMPLE.COM', 'https://example.com:99999', 'xxxxx.com'],
  '11001000000000000111'),
 (['a.b.example.com', 'www.a.example.com', 'example.com:80', 'example.com/',
   'http://example.com', 'https://example.com', 'ftp://www.example.com',
   'https://sub.example.com', 'https://example.com/', 'https://example.co.uk',
   'www.example.co.uk', 'example.c', 'example.abcdefgh', 'ex-ample.com', '-example.com',
   'example-.com', 'http://exa_mple.com', 'https://example.com:', 'www.example.com:8080',
   'example.com.', 'example..com', 'http:/example.com', 'HTTP://www.example.com',
   'sftp://example.com'],
  '111001110110110000100000'),
 (['ftps://x.com', '_ex.com', 'ex_.com', '1example.com', 'example.com:0', 'a.b',
   'https://example.com:80', 'https://www.example.com:8443', 'example.COM', 'example.com ',
   ' example.com', 'https://-x.com', 'ftp://x.com:21', 'x.y.z.w.example.com',
   'https://example.com:abc', 'xn--bcher-kva.example', 'a.1b', 'a.b1'],
  '000110111000110100'),
 (['ex-ample.com', 'www.example-site.com', 'a1-b2.example.com'], '111')]
EXCLUSION_VALUES = ['notepad.exe', 'C:\\Tools\\a.exe', 'C:\\Tools\\', 'D:', 'D:\\', 'D:\\Data', '\\\\srv\\share',
 'a*b', '\\*.log', 'C:\\*\\a', 'C:\\Tools\\\\a', 'a:b', 'a"b', "a'b", 'a|b', 'ab', 'a',
 'C:\\a.', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\*\\Run', 'SOFTWARE\\x', '?:\\Data', 'C:\\Data\\ ',
 'x/y', '', '%WINDIR%\\a', '*.tmp', 'C:\\Program Files\\App\\*']
LAB_EXCLUSIONS = {'casp_bypass': '111111101101111111111110111',
 'library': '111111101101111111111110111',
 'parent_process_ctx_bypass': '100000000000010110000000000',
 'parent_uninstall_bypass': '111111101101111111111110111',
 'process_ctx_bypass': '100000000000010110000000000',
 'skipChangeTracking': '111001101100000101111100111',
 'skipDenyWrite': '111001101100000101111100111',
 'skipFileOperation': '111001101100000101111100111',
 'skipSolidification': '011011000100000000001000001',
 'skipVolume': '111111101101111111111110111'}


def pairs(values, lab):
    assert len(values) == len(lab)
    return [(value, flag == '1') for value, flag in zip(values, lab)]


ids = lambda value: repr(value)[:30]
PATH_CHECKS = [('vpW', WIN_PATHS, lambda value: is_sc_path(value, 'WIN')),
               ('vpU', UNIX_PATHS, lambda value: is_sc_path(value, 'UNIX')),
               ('up', WIN_PATHS, is_sc_updater_name), ('cc', WIN_PATHS, is_sc_cc_path),
               ('du', WIN_PATHS, is_sc_directory), ('fn', WIN_PATHS, is_sc_file_name)]


@pytest.mark.parametrize('key,values,check', PATH_CHECKS, ids=[c[0] for c in PATH_CHECKS])
def test_path_rules(key, values, check):
    for value, valid in pairs(values, LAB_PATHS[key]):
        assert check(value) is valid, value


@pytest.mark.parametrize('value,valid', [p for values, lab in MAILS for p in pairs(values, lab)],
                         ids=ids)
def test_email_rule(value, valid):
    assert is_sc_email_list(value) is valid


@pytest.mark.parametrize('value,valid', [p for values, lab in SITES for p in pairs(values, lab)],
                         ids=ids)
def test_website_rule(value, valid):
    assert is_sc_website(value) is valid


@pytest.mark.parametrize('field', sorted(LAB_EXCLUSIONS))
def test_exclusion_rules(field):
    for value, valid in pairs(EXCLUSION_VALUES, LAB_EXCLUSIONS[field]):
        assert is_sc_exclusion_value(value, field) is valid, value
    unix = pairs(EXCLUSION_VALUES, '100000100000110110010010100')
    assert all(is_sc_exclusion_value(value, 'skipSolidification', 'UNIX') is valid
               for value, valid in unix)


def test_fim_rules():
    users = ['jdoe', 'DOMAIN\\jdoe', '\\jdoe', 'jdoe\\', 'a\\b\\c', 'a/b', '/jdoe', 'j*doe',
             'NT AUTHORITY\\SYSTEM', 'j.doe@corp', '', ' x']
    assert all(is_sc_fim_user(v) is ok for v, ok in pairs(users, '111100001111'))
    assert all(is_sc_fim_user(v, 'UNIX') is ok for v, ok in pairs(users, '100000000111'))
    tops = ['C:\\', 'C:\\Users', 'c:\\users\\', 'C:\\Windows', 'C:\\Program Files (x86)',
            'C:\\Program Data\\', 'C:\\WINNT', '%WINDIR%', '%ProgramFiles(x86)%\\', '%HOMEDRIVE%',
            'C:\\Data', 'D:\\', 'C:\\Windows\\System32', '%PROGRAMDATA%', 'C:\\ProgramData']
    assert all((not is_sc_top_level_path(v)) is ok for v, ok in pairs(tops, '000000001010101'))
    patterns = ['*.cfg', '*', 'a*b', '**', '*a*', 'a\\b', '\\a', 'a\\', 'a/b', 'a?b', 'a:b',
                '*.c?g', 'abc', 'a*', '*a', '.*.']
    assert all(is_sc_fim_pattern(v) is ok for v, ok in pairs(patterns, '1100000000001110'))
    keys = ['HKEY_LOCAL_MACHINE\\SOFTWARE\\*\\Run', 'HKLM\\SOFTWARE', '\\REGISTRY\\MACHINE',
            'hkey_users\\x', 'HKEY_CURRENT_USER\\x*', 'HKEY_CURRENT_USER\\*',
            'HKEY_CURRENT_USER\\a*\\b']
    assert all(is_sc_registry_key(v) is ok for v, ok in pairs(keys, '1011000'))


def test_configuration():
    policy = load(SCGENPolicyConfiguration, 'Lockdown Rules', 'Claude - SC Config Test')
    assert (policy.cli_failed_attempts, policy.log_file_size, policy.log_file_num,
            policy.mp_compat) == ('100', '100000', '50', '2')
    for setter, value in [('set_cli_failed_attempts', 0), ('set_cli_failed_attempts', 101),
                          ('set_cli_lockdown_minutes', 1441), ('set_events_threshold', 1000000),
                          ('set_file_diff_max_size', 10001), ('set_log_file_size', 1999),
                          ('set_log_file_num', 51), ('set_inventory_merge_timeout', 10001),
                          ('set_inventory_merge_by_size_period', 149), ('set_mp_compat', 3),
                          ('set_vtp_trust_check', 2), ('set_file_diff_attr_only_types', '.zip'),
                          ('set_paths_writable_only_by_updaters', 'C:\\a,D:\\b')]:
        with pytest.raises(ValueError):
            getattr(policy, setter)(value)
    assert policy.log_file_num == '50'


def test_awl_options():
    policy = load(SCAWLPolicyOptions, 'AWL Options (Windows)', 'Claude - SC AWL Options Win Test')
    assert len(policy.self_approval_text) == 1500
    assert policy.helpdesk_mail_to == 'help.desk@example.com; soc-team@example.org'
    assert policy.helpdesk_website == 'https://helpdesk.example.com:8443'
    assert (policy.pull_inventory_interval, policy.inventory_updates_interval,
            policy.atd_file_size_limit) == ('180', '180', '10')
    for setter, value in [('set_self_approval_text', 'x' * 1501), ('set_self_approval_timeout', 0),
                          ('set_helpdesk_mail_to', 'a@example.com, b@example.com'),
                          ('set_helpdesk_mail_to', ''), ('set_helpdesk_mail_subject', 'S' * 101),
                          ('set_helpdesk_website', 'http://helpdesk.example.com'),
                          ('set_helpdesk_epo_address', ''), ('set_pull_inventory_interval', 181),
                          ('set_inventory_updates_interval', 0), ('set_atd_file_size_limit', 11)]:
        with pytest.raises(ValueError):
            getattr(policy, setter)(value)


def test_awl_rules():
    policy = load(SCAWLPolicyRules, 'AWL Rules (Windows)', 'Claude - SC AWL Rules Win Test')
    assert sorted(r['path'] for r in policy.get_trusted_directories()) == [
        '%LOCALAPPDATA%\\App', '\\\\fileserver\\installers\\']
    updaters = policy.get_updaters()
    assert updaters[0]['binary'] == 'setup?.exe' and len(updaters[1]['tag']) == 255
    assert len(policy.get_execution_control_rules()[0]['description']) == 260
    calls = [('add_updater', ('*setup.exe', 'x')), ('add_updater', ('setup.exe', ' ')),
             ('add_updater', ('setup.exe', 'x'), {'parent': '?'}),
             ('add_trusted_directory', ('Program Files\\App',)),
             ('add_trusted_user', ('DOMAIN\\deploy', 'again')),
             ('add_executable_file', ('N' * 256, 'a.exe')),
             ('add_execution_control_rule', ('C:\\a.exe',)),
             ('add_execution_control_rule', ('a.exe', 'block', [])),
             ('add_execution_control_rule', ('a.exe', 'block', [('path', 'equals', 'C:\\*\\a.exe')])),
             ('add_execution_control_rule', ('a.exe', 'block', [('user', 'equals', ' ')])),
             ('add_exclusion', ('process_ctx_bypass', 'C:\\a.exe')),
             ('add_exclusion', ('skipSolidification', 'App\\x')),
             ('add_exclusion', ('vasr_force_reloc_bypass', 'a.exe'), {'library': 'lib*.dll'})]
    for call in calls:
        name, args, kwargs = call if len(call) == 3 else call + ({},)
        with pytest.raises(ValueError):
            getattr(policy, name)(*args, **kwargs)
    assert policy.add_execution_control_rule('cmd.exe', 'block',
                                             [('command_line', 'noArgSpecified', '')])


def test_cc_and_fim():
    cc = load(SCCCPolicyRules, 'CC Rules (Windows)', 'Claude - SC CC Rules Win Test')
    assert len(cc.get_write_protect_file_list()) == 2
    for name, value in [('add_write_protect_file', 'Config\\a.ini'), ('add_read_protect', ' '),
                        ('add_write_protect_registry', 'HKLM\\SOFTWARE')]:
        with pytest.raises(ValueError):
            getattr(cc, name)(value)
    fim = load(SCFIMPolicyRules, 'Mon Rules (Windows)', 'Claude - SC FIM Win Test')
    assert len(fim.get_file_list()) == 3
    for name, args in [('add_file', ('\\\\srv\\a.cfg', True, True)),
                       ('add_file', ('C:\\Windows', True, True)),
                       ('add_file', ('C:\\App\\b.cfg', False, True)), ('add_user', ('a\\b\\c',)),
                       ('add_extension', ('a-b',)), ('add_registry', ('SOFTWARE\\x',)),
                       ('add_directory_change_tracking', ('C:\\App\\Other', True, ['a*b']))]:
        with pytest.raises(ValueError):
            getattr(fim, name)(*args)


def test_exceptions_and_rule_group_names():
    policy = load(SCGENPolicyExceptionRules, 'Attr Rules (Windows)',
                  'Claude - SC Exceptions Win Test')
    assert len(policy.get_exclusion_list()) == 3
    with pytest.raises(ValueError):
        policy.add_exclusion('skipChangeTracking', 'C:\\Logs\\\\x')
    assert check_rule_group_name('Servers - Windows')
    for name in ['', ' ', '=cmd', '@x', '+x', '-x', '|x']:
        with pytest.raises(ValueError):
            check_rule_group_name(name)
