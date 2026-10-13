"""
Trellix EDR with Forensics (edrf): General, Streaming, Detection,
Investigation and Remediation policies.

edrf_policies.xml is an export of the lab ePO 5.10 (productId XCLIENT_META,
extension 2.1.2.270) with the "My Default" policies, "Demo (Monitor)",
"Demo (RemoteShell)" and test copies of "My Default" changed in the
console:

- "Claude - EDRF General Test 1" (first save): Self Protection off, content
  updates every 120 min, No HX server, poll 900 s / fastpoll 45 s, health
  report every 15 min, CPU 50 %, event storage 200 MB, Memory-mapped I/O,
  priority Below normal, log level Debug, log storage 30 days, separate log
  per module, libuv and SSL component logging, service log level Trace,
  buffer 40, max size 50, user defined proxy proxy.lab.local:8080
  (excluded hosts, exclude local names, user "claude", retry 30 min).
- "Claude - EDRF General Test 2" (second save): Self Protection on, HX
  server LABSE (its certificates and key replaced by fake values, its host
  by hx.example.com), health report off, In-memory, 200000 events, queue and
  job component logging, logger format None, proxy disabled.
- "Claude - EDRF General Test" (last save): Conventional, No HX server,
  logger format File, no component logging (the console wrote the mask
  "JOB", a bug of the extension).
- "Claude - EDRF Streaming Test": every Trace, Alerts, Process Tracker and
  Logon Tracker setting changed, S3 settings typed then cleared by the
  console (S3 disabled), quotes in two lists.
- "Claude - EDRF Detection Test": update every 30 min, events changed, two
  exclusion lists, four registry key exclusions (one per hive).
- "Claude - EDRF Investigation Test": every number and checkbox changed,
  items added to every exclusion list (one with quotes).
- "Claude - EDRF Remediation Test": Host Remediation on, message display
  off, messages (quotes, backslash), application paths, two allowed IPs.

The library writes the policies as the extension 50.3 does (see
test_edrf50.py): the double quotes typed in the 2.1.2 lists are compared
apart (escaped by the 2.1.2 server, refused or stored as typed by 50.3).
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import (EDRFPolicies, EDRFPolicyGeneral, EDRFPolicyStreaming,
                                 EDRFPolicyDetection, EDRFRegistryExclusion,
                                 EDRFPolicyInvestigation, EDRFPolicyRemediation, EDRFAllowedIP)

FIXTURE = Path(__file__).parent / 'fixtures' / 'edrf_policies.xml'
CLASSES = {'General': EDRFPolicyGeneral, 'Streaming': EDRFPolicyStreaming,
           'Detection': EDRFPolicyDetection, 'Investigation': EDRFPolicyInvestigation,
           'Remediation': EDRFPolicyRemediation}


def load_policies():
    policies = EDRFPolicies()
    policies.load_from_file(str(FIXTURE))
    return policies


def load(cls, name='My Default'):
    return cls(load_policies().get_policy(cls.TYPE, name))


def new(cls):
    """
    A copy of "My Default", as a console test copy.
    """
    return cls(load_policies().new_policy(cls.TYPE, 'Copy'))


def settings(policy):
    return {setting.get('name'): setting.get('value') for setting in policy.root.iter('Setting')}


def assert_same(policy, console, lists=(), skip=()):
    """
    The library-built policy has the settings of the console-saved one;
    the list options in lists are compared as lists (the console keeps the
    line breaks typed in some fields, the library writes semicolons), the
    options in skip are not compared.
    """
    built, saved = settings(policy), settings(console)
    for name in lists:
        setting = policy.OPTIONS[name][0]
        assert policy.get_list(name) == console.get_list(name)
        built.pop(setting), saved.pop(setting)
    for name in skip:
        built.pop(policy.OPTIONS[name][0]), saved.pop(policy.OPTIONS[name][0])
    assert built == saved


def test_policies():
    policies = load_policies()
    assert sorted({item['typeid'] for item in policies.list()}) == [
        'Detection', 'General', 'Investigation', 'Protection', 'Remediation', 'Streaming']
    for item in policies.list():
        if item['typeid'] in CLASSES:
            CLASSES[item['typeid']](policies.get_policy(item['typeid'], item['name']))
    with pytest.raises(ValueError):
        EDRFPolicyStreaming(policies.get_policy('General', 'My Default'))
    with pytest.raises(ValueError):
        EDRFPolicies(b'<epo:EPOPolicySchema xmlns:epo="mcafee-epo-policy">'
                     b'<EPOPolicySettings featureid="ENDP_GS_1000"/></epo:EPOPolicySchema>')
    assert EDRFPolicyGeneral.options()['cpu_limit'] == 'Acquisition CPU usage limit (Minimum of 10%)'


# ------------------------------ General ------------------------------
def test_general_read():
    default = load(EDRFPolicyGeneral)
    assert default.get_option('self_protection') == '1'
    assert default.get_option('health_interval') == 10          # 600 seconds
    assert default.get_option('proxy_retry_delay') == 20        # 1200 seconds
    assert default.get_option('storage_mode') == 'highintegrity'
    assert default.get_proxy() == 'system' and default.get_hx_server() == ''
    assert default.get_log_storage() == ('count', 100000)
    first = load(EDRFPolicyGeneral, 'Claude - EDRF General Test 1')
    assert first.get_proxy() == 'manual' and first.get_log_storage() == ('days', 30)
    assert first.get_option('proxy_exclude_hosts') == ['*.lab.local', '10.0.0.1']
    assert first.get_option('health_interval') == 15 and first.get_option('poll_interval') == 900
    second = load(EDRFPolicyGeneral, 'Claude - EDRF General Test 2')
    assert second.get_hx_server() == 'LABSE' and second.get_proxy() is None
    assert second.get_option('storage_mode') == 'inmemory'


def test_general_rebuild():
    """
    The console changes, applied with the library, rebuild the console-saved copies.
    """
    policy = new(EDRFPolicyGeneral)
    for name, value in [('self_protection', '0'), ('content_update_interval', 120),
                        ('poll_interval', 900), ('fastpoll_interval', 45), ('health_report', '1'),
                        ('health_interval', 15), ('cpu_limit', 50), ('event_storage', 200),
                        ('storage_mode', 'mmapio'), ('priority', 'below'), ('log_level', 'DEBUG'),
                        ('log_per_module', '1'), ('log_libuv', '1'), ('log_ssl', '1'),
                        ('service_log_level', '2'), ('service_log_buffer', 40),
                        ('service_log_max_size', 50)]:
        policy.set_option(name, value)
    policy.clear_hx_server()
    policy.set_log_storage('days', 30)
    policy.set_proxy('manual', host='proxy.lab.local', port=8080,
                     exclude_hosts=['*.lab.local', '10.0.0.1'], exclude_local='1',
                     username='claude', retry_delay=30)
    first = load(EDRFPolicyGeneral, 'Claude - EDRF General Test 1')
    assert_same(policy, first)
    second = load(EDRFPolicyGeneral, 'Claude - EDRF General Test 2')
    policy = first
    for name, value in [('self_protection', '1'), ('health_report', '0'),
                        ('storage_mode', 'inmemory'), ('log_libuv', '0'), ('log_ssl', '0'),
                        ('log_queue', '1'), ('log_job', '1'), ('service_log_format', 'none')]:
        policy.set_option(name, value)
    policy.copy_hx_server(second)
    policy.set_log_storage('count', 200000)
    policy.proxy = None
    assert_same(policy, second)
    last = load(EDRFPolicyGeneral, 'Claude - EDRF General Test')
    for name, value in [('storage_mode', 'highintegrity'), ('service_log_format', 'file'),
                        ('log_queue', '0'), ('log_job', '0')]:
        policy.set_option(name, value)
    policy.clear_hx_server()
    # The console kept "JOB" as mask (extension bug), the library writes an empty mask.
    assert policy.get_setting_value('General', 'mxa/log/mask') == ''
    policy.set_setting_value('General', 'mxa/log/mask', 'JOB')
    assert_same(policy, last)


def test_general_checks():
    policy = new(EDRFPolicyGeneral)
    for name, value in [('cpu_limit', 9), ('health_interval', 61), ('poll_interval', 59),
                        ('content_update_interval', 'x'), ('storage_mode', 'fast'),
                        ('proxy_retry_delay', 1)]:
        with pytest.raises(ValueError):
            policy.set_option(name, value)
    with pytest.raises(ValueError):
        policy.set_option('uninstall_password', '1')      # password defined in the console only
    with pytest.raises(ValueError):
        policy.set_log_storage('days', 366)
    with pytest.raises(ValueError):
        policy.set_proxy('manual')                         # no proxy name
    with pytest.raises(ValueError):
        policy.copy_hx_server(new(EDRFPolicyGeneral))      # no HX server
    for mode, (_, journal, in_memory, mapped, synchronous) in policy.STORAGE_MODES.items():
        policy.set_option('storage_mode', mode)
        assert [policy.get_setting_value('General', 'mxa/eventor/' + name) for name in
                ['db_journal_mode', 'db_in_memory', 'db_memory_mapped', 'db_synchronous',
                 'db_page_size']] == [journal, in_memory, mapped, synchronous, '4096']
    policy.set_option('log_queue', '1')
    policy.set_option('log_libuv', '1')
    assert policy.get_setting_value('General', 'mxa/log/mask') == 'UVPROC:QUEUE'
    policy.set_proxy('system')
    assert policy.get_proxy() == 'system'
    assert policy.get_setting_value('General', 'mxa/proxy/host') == ''


# ------------------------------ Streaming ------------------------------
STREAMING_CHANGES = [
    ('log_level', '2'), ('report_connectivity', '1'), ('deep_inspection', '0'),
    ('etw_ti_inspection', '0'), ('trace_storage', 160), ('cloud_interval', 120),
    ('windows_process_exclusions', ['C:\\Tools\\app.exe', 'C:\\Program Files\\Vendor\\agent.exe']),
    ('windows_disabled_rules', ['1001', '"x"']),
    ('linux_process_exclusions', ['/opt/vendor/bin/agent']), ('linux_disabled_rules', ['2001']),
    ('linux_file_exclusions', ['/var/log/app.log']), ('linux_folder_exclusions', ['/var/cache/app']),
    ('mac_process_exclusions', ['/Applications/Vendor.app/Contents/MacOS/agent']),
    ('mac_disabled_rules', ['3001']), ('ioc_alerts', '0'), ('process_tracker', '1'),
    ('logon_tracker', '1'), ('logon_backfill', '1'), ('logon_timeout', 720),
    ('logon_disable_enrichment', '1'), ('logon_max_events', 1000000),
    ('logon_ignore_addresses', ['10.0.0.1', '10.0.0.2']), ('logon_ignore_hosts', ['scanner01']),
    ('logon_ignore_accounts', ['svc_backup', '""']), ('logon_ignore_categories', ['network']),
    ('logon_ignore_status', ['failed']), ('logon_filter_tunneled', '1')]


def test_streaming_rebuild():
    policy = new(EDRFPolicyStreaming)
    for name, value in STREAMING_CHANGES:
        policy.set_option(name, value)
    # Missing from "My Default", added with their defaults by the console save.
    for setting, value in [('s3_use_endpoint', 'false'), ('s3_endpoint', '')]:
        policy.set_setting_value('Streaming', 'UEDR/TraceScanner/' + setting, value, True)
    console = load(EDRFPolicyStreaming, 'Claude - EDRF Streaming Test')
    assert console.get_list('windows_process_exclusions') == [
        'C:\\Tools\\app.exe', 'C:\\Program Files\\Vendor\\agent.exe']
    assert console.get_setting_value('Streaming', 'mxa/LogonTracker/ignore_accounts') == \
        'svc_backup;\\"\\";'
    # Escaped by the 2.1.2 server, shown as stored by the 50.3 console, stored as typed by 50.3.
    assert console.get_list('logon_ignore_accounts') == ['svc_backup', '\\"\\"']
    assert console.get_list('windows_disabled_rules') == ['1001', '\\"x\\"']
    assert policy.get_setting_value('Streaming', 'UEDR/TraceScanner/disabled_rules') == '1001;"x"'
    # The console stored line breaks, and the trailing ";" typed in the accounts.
    assert_same(policy, console, ['windows_process_exclusions'],
                ['logon_ignore_accounts', 'windows_disabled_rules'])


def test_streaming_s3():
    policy = new(EDRFPolicyStreaming)
    with pytest.raises(ValueError):
        policy.set_option('send_to_s3', '1')               # keys defined in the console only
    with pytest.raises(ValueError):
        policy.set_option('s3_bucket', 'edr-traces')       # S3 disabled
    policy.set_setting_value('Streaming', 'UEDR/TraceScanner/s3_bucket_aws_access_key_id',
                             'encrypted', True)
    policy.set_option('send_to_s3', '1')
    policy.set_option('s3_bucket', 'edr-traces')
    policy.set_option('s3_use_endpoint', '1')
    policy.set_option('s3_endpoint', 'https://s3.example.com')
    for name, value in [('s3_bucket', 'Edr'), ('s3_bucket', 'a..b'), ('s3_bucket', '10.0.0.1'),
                        ('s3_bucket', 'xn--edr'), ('s3_endpoint', 'https://s3.example.com/?a'),
                        ('s3_endpoint', 's3.example.com'), ('s3_interval', 9)]:
        with pytest.raises(ValueError):
            policy.set_option(name, value)
    policy.set_option('send_to_s3', '0')
    assert [policy.get_option(name) for name in ['s3_bucket', 's3_endpoint', 's3_use_endpoint',
                                                 's3_interval']] == ['', '', '0', 30]
    assert policy.get_setting_value('Streaming',
                                    'UEDR/TraceScanner/s3_bucket_aws_access_key_id') == ''


# ------------------------------ Detection ------------------------------
def test_detection_rebuild():
    policy = new(EDRFPolicyDetection)
    assert policy.get_option('update_interval') == 1        # missing: 60 seconds
    assert policy.get_registry_exclusions() == []
    for name, value in [('update_interval', 30), ('udp_events', '1'), ('network_events', '0'),
                        ('dns_events', '0'), ('url_events', '0'),
                        ('path_exclusions', ['C:\\Temp\\build\\*', 'D:\\Data', '/tmp/build']),
                        ('process_exclusions', ['C:\\Tools\\app.exe'])]:
        policy.set_option(name, value)
    for exclusion in [EDRFRegistryExclusion('LocalMachine', 'SOFTWARE\\Vendor\\Agent',
                                            ['Version', 'InstallPath']),
                      EDRFRegistryExclusion('Users', '*\\Software\\Vendor\\Cache'),
                      EDRFRegistryExclusion('ClassesRoot',
                                            'CLSID\\{00000000-0000-0000-0000-000000000001}',
                                            ['Default']),
                      EDRFRegistryExclusion('CurrentControlSet', 'Services\\VendorSvc')]:
        policy.add_registry_exclusion(exclusion)
    console = load(EDRFPolicyDetection, 'Claude - EDRF Detection Test')
    assert console.get_registry_exclusions() == policy.get_registry_exclusions()
    assert_same(policy, console, ['path_exclusions'])        # console line break stored as "|"
    policy.remove_registry_exclusion('Users', '*\\Software\\Vendor\\Cache')
    assert len(policy.registry_exclusions) == 3
    for exclusion in [EDRFRegistryExclusion('HKLM', 'SOFTWARE'), EDRFRegistryExclusion('Users', ''),
                      EDRFRegistryExclusion('Users', 'Software', ['a,b'])]:
        with pytest.raises(ValueError):
            policy.add_registry_exclusion(exclusion)
    with pytest.raises(ValueError):
        policy.set_option('update_interval', 1441)


# ------------------------------ Investigation ------------------------------
def test_investigation_rebuild():
    policy = new(EDRFPolicyInvestigation)
    assert policy.get_list('windows_hashing_files') == [
        'C:\\PAGEFILE.SYS', 'C:\\hiberfil.sys', 'C:\\swapfile.sys']
    for name, value in [('max_search_results', 1024), ('process_history', '0'),
                        ('network_sniffer', '1'), ('network_log_system', '1'),
                        ('network_storage', 240), ('network_storage_percentage', 5),
                        ('network_max_results', 1024), ('hashing_power_saved', '0'),
                        ('hashing_storage', 128), ('hashing_storage_percentage', 4),
                        ('hashing_max_results', 2048), ('hash_strategy', 'auto'),
                        ('hash_delay', 300), ('hash_max_file_size', 200),
                        ('network_process_exclusions',
                         ['C:\\Tools\\scanner.exe', 'C:\\Tools\\backup.exe'])]:
        policy.set_option(name, value)
    for name, items in [('windows_hashing_files', ['C:\\Temp\\big.iso']),
                        ('windows_hashing_extensions', ['.iso']),
                        ('windows_hashing_paths', ['FOLDERID_ProgramData\\Vendor\\Cache']),
                        ('linux_hashing_files', ['/opt/app/data.bin']),
                        ('linux_hashing_extensions', ['.iso']),
                        ('linux_hashing_paths', ['/opt/app/cache']),
                        ('mac_hashing_extensions', ['.dmg', '.strings']),   # .strings: already in
                        ('mac_hashing_paths', ['/opt/app/cache'])]:
        policy.add_to_list(name, items)
    with pytest.raises(ValueError):          # stops the 50.3 console from opening the policy
        policy.set_list('mac_hashing_files', ['/Users/Shared/big.dmg', '/tmp/"q"'])
    console = load(EDRFPolicyInvestigation, 'Claude - EDRF Investigation Test')
    assert console.get_list('mac_hashing_files') == ['/Users/Shared/big.dmg', '/tmp/"q"']
    assert_same(policy, console, skip=['mac_hashing_files'])
    policy.remove_from_list('linux_hashing_paths', ['/opt/app/cache'])
    assert '/opt/app/cache' not in policy.get_list('linux_hashing_paths')


def test_list_checks():
    policy = new(EDRFPolicyInvestigation)
    for name, items in [('windows_hashing_files', ['C:\\\\Temp\\\\a.iso']),  # double backslash
                        ('windows_hashing_files', ['a;b']), ('linux_hashing_files', ['']),
                        ('linux_hashing_files', ['/tmp/\U0001F600']),       # not BMP
                        ('linux_hashing_files', ['/tmp/' + 'x' * 200000])]:
        with pytest.raises(ValueError):
            policy.set_list(name, items)
    with pytest.raises(ValueError):
        policy.set_list('hash_delay', ['1'])
    with pytest.raises(ValueError):
        policy.set_option('hash_strategy', 'fast')


# ------------------------------ Remediation ------------------------------
def test_remediation_rebuild():
    policy = new(EDRFPolicyRemediation)
    assert policy.get_allowed_ips() == []
    for name, value in [('host_remediation', '1'), ('display_message', '0'),
                        ('release_message', 'Released by the SOC.'),
                        ('windows_allowed_paths', ['C:\\Tools\\remote.exe',
                                                   'C:\\Program Files\\Vendor\\vpn.exe']),
                        ('mac_allowed_paths', ['/Applications/VPN.app/Contents/MacOS/vpn']),
                        ('linux_allowed_paths', ['/usr/sbin/openvpn'])]:
        policy.set_option(name, value)
    policy.add_allowed_ip(EDRFAllowedIP('10.0.0.10', 'SOC jump host'))
    policy.add_allowed_ip(EDRFAllowedIP('dns.lab.local', 'Internal DNS'))
    policy.add_allowed_ip(EDRFAllowedIP('2001:db8:0:0:0:0:0:10'))
    policy.remove_allowed_ip('dns.lab.local')
    with pytest.raises(ValueError):          # stops the 50.3 console from opening the policy
        policy.set_option('containment_message', 'Call "SOC" at C:\\SOC now')
    console = load(EDRFPolicyRemediation, 'Claude - EDRF Remediation Test')
    assert console.get_option('containment_message') == 'Call "SOC" at C:\\SOC now'
    assert_same(policy, console, skip=['containment_message'])
    policy.add_allowed_ip(EDRFAllowedIP('fd00::10'))      # refused by the 2.1.2 console only
    for address in ['10.0.0.256', 'bad host', '10.0.0.10']:     # last: duplicate
        with pytest.raises(ValueError):
            policy.add_allowed_ip(EDRFAllowedIP(address))
    with pytest.raises(ValueError):
        policy.set_option('uncontain_password', '1')
    assert load(EDRFPolicyRemediation, 'Demo (RemoteShell)').get_allowed_ips() == []


# ------------------------------ All policies ------------------------------
def test_lossless():
    """
    Writing back what was read changes nothing (all lab policies, except the
    lists where the console kept line breaks).
    """
    policies = load_policies()
    for item in policies.list():
        if item['typeid'] not in CLASSES:
            continue
        policy = CLASSES[item['typeid']](policies.get_policy(item['typeid'], item['name']))
        before = settings(policy)
        for name in policy.OPTIONS:
            value = policy.get_option(name)
            if value is not None and policy.get_setting_value(policy.TYPE,
                                                              policy.OPTIONS[name][0]) is not None:
                if name in ('windows_process_exclusions', 'path_exclusions') and \
                        item['name'].startswith('Claude'):
                    continue
                if name.startswith('s3_') and policy.get_option('send_to_s3') != '1':
                    continue
                if name == 'storage_mode':      # sets the page size 4096, as the console
                    continue
                if name == 'containment_message':   # also builds the 50.3 containment page
                    continue
                if '\\"' in (policy.get_setting_value(policy.TYPE, policy.OPTIONS[name][0]) or '') \
                        and policy.OPTIONS[name][0] in policy.DOUBLE_BACKSLASHES and \
                        not policy.QUOTES_BREAK_CHUNKS:
                    continue    # 2.1.2 escaped quote: its backslash doubled, as by the 50.3 console
                if '"' in str(value) and policy.OPTIONS[name][0] in policy.CHUNKED and \
                        policy.QUOTES_BREAK_CHUNKS:     # refused for the 50.3 console
                    continue
                policy.set_option(name, value)
        if isinstance(policy, EDRFPolicyDetection) and policy.get_registry_exclusions():
            policy.set_registry_exclusions(policy.get_registry_exclusions())
        if isinstance(policy, EDRFPolicyRemediation) and policy.get_allowed_ips():
            policy.set_allowed_ips(policy.get_allowed_ips())
        assert settings(policy) == before, item


def test_markdown():
    policies = load_policies()
    for item in policies.list():
        if item['typeid'] in CLASSES:
            text = CLASSES[item['typeid']](policies.get_policy(
                item['typeid'], item['name'])).to_markdown()
            assert text.startswith('# ') and 'Trellix EDR with Forensics - ' in text
    text = load(EDRFPolicyGeneral, 'Claude - EDRF General Test 1').to_markdown()
    for expected in ['## 4. Trellix EDR with Forensics Health (advanced)',
                     '| Report every (minutes) | 15 |', '| Storage mode | Memory-mapped I/O |',
                     '| Log storage | 30 days |', '| Proxy name | proxy.lab.local |',
                     '| Registered Forensics(HX) server | No HX server |']:
        assert expected in text
    assert '| HX servers | hx.example.com |' in load(
        EDRFPolicyGeneral, 'Claude - EDRF General Test 2').to_markdown()
    text = load(EDRFPolicyDetection, 'Claude - EDRF Detection Test').to_markdown()
    assert '| 1 | SOFTWARE\\\\Vendor\\\\Agent | Version, InstallPath | LocalMachine |' in text
    text = load(EDRFPolicyRemediation, 'Claude - EDRF Remediation Test').to_markdown()
    assert '| 1 | 10.0.0.10 | SOC jump host |' in text
    text = load(EDRFPolicyStreaming, 'Claude - EDRF Streaming Test').to_markdown()
    assert '| Windows | Exclude process(es) by full path | C:\\\\Tools\\\\app.exe; ' in text
    assert '| Accounts | svc\\_backup; \\\\"\\\\" |' in text


def test_console_breaking_values():
    """
    Values that stop the console from opening the policy (checked on the lab).
    """
    general = new(EDRFPolicyGeneral)
    for name, value in [('proxy_username', 'LAB\\user'), ('proxy_host', 'proxy"'),
                        ('proxy_exclude_hosts', ['a\\b'])]:
        with pytest.raises(ValueError):
            general.set_option(name, value)
    with pytest.raises(ValueError):
        new(EDRFPolicyRemediation).add_allowed_ip(EDRFAllowedIP('10.0.0.1', 'Internal "DNS"'))
    streaming = new(EDRFPolicyStreaming)                  # opens fine in the console
    streaming.set_list('logon_ignore_accounts', ['LAB\\svc_backup'])
    assert streaming.get_list('logon_ignore_accounts') == ['LAB\\svc_backup']
