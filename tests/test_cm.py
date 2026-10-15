"""
Endpoint Security Common (es/cm): Options policy.

common_policies.xml is an export of the lab ePO 5.10 (productId ENDP_GS_1000)
with "My Default" and "Claude - Common Options Test", changed in the console:
French client interface, Standard access with lockout (3 attempts, 5 min, 15
min) and a time-based password, uninstall password, Self Protection files
Report only / registry off / processes Block only, 2 process exclusions, 1 AAC
exclusion, local time logs, ODS activity logging, activity log 20 MB in
German, debug logging Access Protection + Firewall (60 MB), event DB 70 MB,
varied event and EDR levels, proxy proxy.claude.test:8080 with 2 exclusions,
IPv6, no Update Now button, no default update task, hotfixes and patches only,
managed tasks hidden. The passwords (and the time-based password time) are not
in the export.
"""

from pathlib import Path

import pytest

from trellix_epo import ESCommonPolicies, ESCommonPolicyOptions, AACExclusion

FIXTURE = Path(__file__).parent / 'fixtures' / 'common_policies.xml'


def load(name='My Default'):
    policies = ESCommonPolicies()
    policies.load_from_file(str(FIXTURE))
    return ESCommonPolicyOptions(policies.get_policy(ESCommonPolicyOptions.TYPE, name))


def test_read_default():
    policy = load()
    assert policy.access_level == ESCommonPolicyOptions.FULL_ACCESS
    assert (policy.get_option('uninstall_password'), policy.get_option('self_protection'),
            policy.get_option('ipv6')) == ('0', '1', '0')
    assert (policy.interface_language, policy.activity_log_language) == ('0000', '0000')
    assert policy.get_sp_process_exclusions() == [] and policy.get_aac_exclusions() == []
    assert policy.get_event_level('AP') == '3'
    assert policy.get_edr_event_level('AP') == '1'          # missing: console default
    assert policy.get_proxy()['type'] == '0'
    assert policy.update_level == '1'


def test_read_console_changes():
    policy = load('Claude - Common Options Test')
    assert policy.access_level == ESCommonPolicyOptions.STANDARD_ACCESS
    assert [policy.get_option(name) for name in ['interface_lockout', 'uninstall_password',
                                                 'time_based_password', 'ipv6',
                                                 'update_now_button', 'default_update_task',
                                                 'managed_tasks', 'sp_registry']] == \
        ['1', '1', '1', '1', '0', '0', '0', '0']
    assert [policy.get_option(name) for name in ['password_attempts', 'lockout_time_frame',
                                                 'lockout_minutes', 'activity_log_size',
                                                 'debug_log_size', 'event_db_size']] == \
        [3, 5, 15, 20, 60, 70]
    assert (policy.interface_language, policy.activity_log_language, policy.log_utc) == (
        '040C', '0407', '0')
    assert (policy.get_sp_action('files'), policy.get_sp_action('processes')) == ('2', '1')
    assert policy.sp_process_exclusions == ['claudeone.exe', 'claudetwo.exe']
    assert policy.aac_exclusions == [AACExclusion(
        'C:\\Tools\\claudeaac.exe', '0123456789abcdef0123456789abcdef',
        'fedcba9876543210fedcba9876543210', 'Claude AAC note')]
    assert policy.get_tp_debug_logging() == '1' and policy.get_option('debug_fw') == '1'
    assert [policy.get_event_level(m) for m in ESCommonPolicyOptions.EVENT_MODULES] == \
        ['0', '1', '2', '4', '5', '3', '2']
    assert [policy.get_edr_event_level(m) for m in ESCommonPolicyOptions.EVENT_MODULES] == \
        ['2', '0', '2', '0', '1', '2', '0']
    assert policy.get_proxy() == {'type': '2', 'address': 'proxy.claude.test', 'port': 8080,
                                  'exclusions': ['*.claude.test', '10.0.0.1'],
                                  'authentication': '0', 'user': ''}
    assert policy.update_level == '2'


def test_write_as_the_console():
    """
    The console changes of the test policy, made by the library on My Default.
    """
    policy, console = load(), load('Claude - Common Options Test')
    policy.access_level = ESCommonPolicyOptions.STANDARD_ACCESS
    for name in ['interface_lockout', 'uninstall_password', 'time_based_password', 'ipv6',
                 'ods_activity_logging', 'debug_fw']:
        policy.set_option(name, '1')
    for name in ['update_now_button', 'default_update_task', 'managed_tasks', 'sp_registry']:
        policy.set_option(name, '0')
    for name, value in [('activity_log_size', 20), ('debug_log_size', 60),
                        ('event_db_size', 70)]:
        policy.set_option(name, value)
    policy.interface_language = '040C'
    policy.activity_log_language = '0407'
    policy.log_utc = '0'
    policy.set_sp_action('files', '2')
    policy.set_sp_action('processes', '1')
    policy.sp_process_exclusions = ['claudeone.exe', 'claudetwo.exe']
    policy.add_aac_exclusion(console.aac_exclusions[0])
    policy.set_tp_debug_logging('1', ['enableSPAPClientDebugLogging'])
    for module, level in zip(ESCommonPolicyOptions.EVENT_MODULES, '0124532'):
        policy.set_event_level(module, level)
    for module, level in zip(ESCommonPolicyOptions.EVENT_MODULES, '2020120'):
        policy.set_edr_event_level(module, level)
    policy.set_proxy('2', 'proxy.claude.test', 8080, ['*.claude.test', '10.0.0.1'])
    policy.update_level = '2'
    settings = lambda p: {(section.get('name'), setting.get('name')): setting.get('value')
                          for section in p.root.iter('Section')
                          for setting in section.findall('Setting')}
    mine, theirs = settings(policy), settings(console)
    assert {k: v for k, v in mine.items() if theirs.get(k) != v} == {}
    # The console also wrote these settings (new defaults of the extension).
    assert set(theirs) - set(mine) == set()


def test_checks():
    policy = load()
    for bad in [lambda: policy.set_access_level('3'),
                lambda: policy.set_option('ipv6', 'yes'),
                lambda: policy.set_option('activity_log_size', 1000),
                lambda: policy.set_interface_language('FR'),
                lambda: policy.set_sp_action('network', '1'),
                lambda: policy.set_event_level('AP', '9'),
                lambda: policy.set_proxy('2', '', 80),
                lambda: policy.add_aac_exclusion(AACExclusion('C:\\a.exe')),
                lambda: policy.add_aac_exclusion(AACExclusion('C:\\a.exe', md5='xyz'))]:
        with pytest.raises(ValueError):
            bad()
    assert policy.add_aac_exclusion(AACExclusion('C:\\a.exe', signer_md5='a' * 32))
    assert not policy.add_aac_exclusion(AACExclusion('C:\\a.exe', signer_md5='a' * 32))
    assert policy.remove_aac_exclusion('C:\\a.exe')
    assert policy.get_setting_value('GlobalExclusions', 'dwExclCount') == '0'


def test_markdown():
    text = load('Claude - Common Options Test').to_markdown()
    assert 'Endpoint Security Common - Options policy' in text
    assert '| Client Interface Mode | Standard access |' in text
    assert '| Administrator password | Defined in the ePO console (not exported) |' in text
    assert '| Files and folders | Report only |' in text
    assert '| 2 | claudetwo.exe |' in text
    assert '| Access Protection | All | Alerts and events |' in text
    assert '| HTTP address | proxy.claude.test |' in text
    assert '| What to update (Windows only) | Hotfixes and patches |' in text
    text = load().to_markdown()
    assert '| Client Interface Mode | Full access |' in text
    assert 'Administrator password' not in text


# ------------------------------ Values accepted by the console ------------------------------
# Number bounds tested on the lab page (Endpoint Security Platform 26.8.0.19750): min - 1 and
# max + 1 refused, min and max accepted; the cases below are the results of the page validators
# (validateLogfilePath, validateServerIpOrFqdn, validateExclusion) run on the lab.
NUMBER_BOUNDS = [('password_attempts', 1, 99), ('lockout_time_frame', 1, 999),
                 ('lockout_minutes', 1, 999), ('activity_log_size', 1, 999),
                 ('debug_log_size', 1, 999), ('event_db_size', 50, 999)]
LOG_LOCATIONS = [('%DEFLOGDIR%', True), ('C:\\Logs', True), ('<SYSTEM_DRIVE>\\Logs', True),
                 ('<COMPUTER_NAME>\\x', False), ('C:\\Lo*gs', False), ('C:\\a|b', False),
                 ('<SYSTEM_DRIVE', False), ('C:\\a"b', False), ('/var/log/ens', True),
                 ('/var/log/a;b', False), ('/var/log/a\\b', False), ('relative\\x', True),
                 ('D:\\a b\\c?', False)]
PROXY_ADDRESSES = [('proxy.example.com', True), ('proxy', True), ('10.0.0.1', True),
                   ('fd00::1', True), (' proxy', False), ('proxy ', False), ('pro xy.com', False),
                   ('proxy.example.com.', False), ('proxy-.com', False),
                   ('proxy_1.example.com', True), ('http://proxy', False), ('proxy:8080', False),
                   ('a.b-c.d', True), ('é.com', True)]
SP_EXCLUSIONS = [('C:\\Tools\\app.exe', True), ('app.exe', True), ('*.exe', True),
                 ('C:\\Tools\\*', True), ('C:\\\\Tools', False), ('\\\\server\\share\\a.exe', False),
                 ('C:/Tools/app.exe', False), ('a"b.exe', False), ('a|b.exe', False), ('C:', True),
                 ('  ', False), ('?:\\x\\*.exe', True), ('<SYSTEM_DRIVE>\\a.exe', False),
                 ('%ProgramFiles%\\a.exe', False)]


@pytest.mark.parametrize('name,minimum,maximum', NUMBER_BOUNDS)
def test_number_bounds(name, minimum, maximum):
    policy = load()
    for value in (minimum, maximum, ' {} '.format(maximum)):
        policy.set_option(name, value)
    for value in (minimum - 1, maximum + 1, '1.5', True):
        with pytest.raises(ValueError):
            policy.set_option(name, value)


def test_console_values():
    policy = load()
    for setter, cases in [(policy.set_log_location, LOG_LOCATIONS),
                          (lambda value: policy.set_proxy('2', address=value), PROXY_ADDRESSES),
                          (lambda value: policy.set_sp_process_exclusions([value]), SP_EXCLUSIONS)]:
        for value, valid in cases:
            if valid:
                setter(value)
            else:
                with pytest.raises(ValueError):
                    setter(value)
    for location in ['C:\\' + 'L' * 253, 'C:\\' + 'L' * 254]:
        if len(location) <= 256:
            policy.set_log_location(location)
        else:
            with pytest.raises(ValueError):
                policy.set_log_location(location)
    with pytest.raises(ValueError):
        policy.set_proxy('2', address='p' * 101)
    for port in (0, 65536, '80a'):
        with pytest.raises(ValueError):
            policy.set_proxy('2', port=port)
    policy.set_proxy('2', port=' 3128 ')
    assert policy.get_proxy()['port'] == 3128
    with pytest.raises(ValueError):
        policy.set_sp_process_exclusions(['app.exe', ' app.exe'])      # duplicate


def test_setting_length():
    """
    The ePO server keeps 3072 characters per setting (an import truncates
    the rest, checked on the lab with the proxy exclusions).
    """
    policy = load()
    exclusions = ['host{:04d}.example.com'.format(index) for index in range(146)]
    policy.set_proxy('2', address='proxy.example.com', exclusions=exclusions)   # 3065 characters
    with pytest.raises(ValueError):
        policy.set_proxy('2', exclusions=exclusions + ['host0146.example.com'])
