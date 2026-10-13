"""
Trellix EDR with Forensics (edrf), extension 50.3.0.900: split settings,
Event streamer, containment page, field lengths.

edrf_policies_50.xml is an export of the lab ePO 5.10 (productId
XCLIENT_META, extension 50.3.0.900) with the "My Default" policies and test
copies of "My Default" saved in the console (General is not included: its
page did not change):

- "Claude - EDRF 50.3 Streaming Test": 131 Windows process exclusions
  (4826 characters, one with a double quote), an account with a double
  quote added to the Logon Tracker exclusions, Event streamer on with the
  process, DNS and registry OS events, the default event logs plus Sysmon,
  an IIS file event, one filter (two conditions), DXL, Helix (ID typed with
  a double quote) and two syslog servers, delete batch size 150.
- "Claude - EDRF 50.3 Detection Test": 220 path exclusions (4179
  characters, line breaks stored as "|").
- "Claude - EDRF 50.3 Investigation Test": 121 Windows hashing paths
  (4460 characters, one with an apostrophe), ".qcow2" added to the Linux
  extensions.
- "Claude - EDRF 50.3 Remediation ByHand Test": Host Remediation on,
  "Enter by hand" containment page (title, two-line message with
  backslashes, logo.png), release message, a Windows application path, an
  IPv6 allowed address. The console favicon is replaced by fake base64
  split in 3072 character parts, as the server does.
- "Claude - EDRF 50.3 Remediation URL Test": "From URL" containment page.
- "Claude - EDRF 50.3 Limits2 Streaming Test": imported with four event
  logs (JSON of 2981 characters): the console only shows three of them.
"""

import base64
import json
from pathlib import Path

import pytest

from mcafee_epo_policies import (EDRFPolicies, EDRFPolicyGeneral, EDRFPolicyStreaming,
                                 EDRFPolicyDetection, EDRFPolicyInvestigation,
                                 EDRFPolicyRemediation, EDRFAllowedIP, EDRFRegistryExclusion)
from mcafee_epo_policies.edrf import (EDRFEventLog, EDRFFileEvent, EDRFEventFilter,
                                      EDRFFilterCondition, EDRFSyslogServer)
from mcafee_epo_policies.edrf.policy import EDRFPolicy
from mcafee_epo_policies.validators import is_ipv4, is_ipv6, is_hostname, is_ip_or_hostname

FIXTURE = Path(__file__).parent / 'fixtures' / 'edrf_policies_50.xml'
FIXTURE_212 = Path(__file__).parent / 'fixtures' / 'edrf_policies.xml'


def load_policies(fixture=FIXTURE):
    policies = EDRFPolicies()
    policies.load_from_file(str(fixture))
    return policies


def load(cls, name='My Default'):
    return cls(load_policies().get_policy(cls.TYPE, name))


def new(cls, fixture=FIXTURE):
    return cls(load_policies(fixture).new_policy(cls.TYPE, 'Copy'))


def settings(policy):
    return {setting.get('name'): setting.get('value') for setting in policy.root.iter('Setting')}


def add_console_defaults(policy, console, extra=()):
    """
    Copy the settings the console adds at the first save of a policy of an
    older extension (missing from "My Default"): their values must be the
    library defaults, except the settings in extra (not managed).
    """
    built = settings(policy)
    for name, value in settings(console).items():
        if name not in built:
            if name not in extra:
                assert policy._get(name) == policy._decode(name, value), name
            policy.set_setting_value(policy.TYPE, name, value, True)


def assert_same(policy, console, lists=()):
    built, saved = settings(policy), settings(console)
    for name in lists:
        setting = policy.OPTIONS[name][0]
        assert policy.get_list(name) == console.get_list(name)
        for stored in (built, saved):
            for key in [key for key in stored if key == setting or key.startswith(setting + '_')]:
                stored.pop(key)
    assert built == saved


# ------------------------------ Validators ------------------------------
def test_validators():
    assert is_ipv4('10.0.0.1') and is_ipv4('010.0.0.1') and not is_ipv4('10.0.0.256')
    for value in ['fd00::10', '::1', '2001:db8:0:0:0:0:0:10', 'fe80::1%eth0', '::ffff:10.0.0.1']:
        assert is_ipv6(value)
    assert not is_ipv6('fd00:::10') and not is_ipv6('10.0.0.1')
    assert is_hostname('dns.lab.local') and not is_hostname('localhost')
    assert not is_hostname('1.2.3.256') and not is_hostname('bad host')
    assert is_ip_or_hostname('fd00::10') and not is_ip_or_hostname('bad host')


# ------------------------------ Split settings ------------------------------
def test_split_chunks():
    assert EDRFPolicy.split_chunks('a' * 3072) == ['a' * 3072]
    assert EDRFPolicy.split_chunks('a' * 3073) == ['a' * 3072, 'a']
    assert EDRFPolicy.split_chunks('ab;' * 1025) == ['ab;' * 1024, 'ab;']
    value = ';'.join('item{:04d}'.format(index) for index in range(2000))
    parts = EDRFPolicy.split_chunks(value)
    assert ''.join(parts) == value and all(len(part) <= 3072 for part in parts)
    assert all(part.endswith(';') for part in parts[:-1])


def test_split_read():
    streaming = load(EDRFPolicyStreaming, 'Claude - EDRF 50.3 Streaming Test')
    items = streaming.get_list('windows_process_exclusions')
    assert len(items) == 131 and items[-1] == 'C:\\Tools\\a"b.exe'     # quote kept by 50.3
    assert streaming.get_list('logon_ignore_accounts')[0] == 'svc"x'
    detection = load(EDRFPolicyDetection, 'Claude - EDRF 50.3 Detection Test')
    assert len(detection.get_list('path_exclusions')) == 220
    investigation = load(EDRFPolicyInvestigation, 'Claude - EDRF 50.3 Investigation Test')
    paths = investigation.get_list('windows_hashing_paths')
    assert len(paths) == 121 and paths[-1] == "C:\\Users\\O'Brien\\Big"


def test_investigation_rebuild():
    """
    The library splits the lists as the ePO server does.
    """
    policy = new(EDRFPolicyInvestigation)
    paths = ['FOLDERID_ProgramData\\Vendor{:03d}\\Cache'.format(index) for index in range(120)]
    # The whole field was replaced in the console (no trailing ";" kept).
    policy._set('UEDR/FileHashing/ignored_paths_windows',
                ';'.join(paths + ["C:\\Users\\O'Brien\\Big"]))
    policy.set_setting_value('Investigation', 'UEDR/FileHashing/ignored_extensions_linux',
                             policy.get_setting_value('Investigation',
                                                      'UEDR/FileHashing/ignored_extensions_linux')
                             + ';.qcow2')                    # typed after the console ";"
    assert_same(policy, load(EDRFPolicyInvestigation, 'Claude - EDRF 50.3 Investigation Test'))
    policy.set_list('windows_hashing_paths', ['C:\\Temp'])
    assert policy.get_setting_value('Investigation',
                                    'UEDR/FileHashing/ignored_paths_windows_1') is None


def test_detection_rebuild():
    policy = new(EDRFPolicyDetection)
    policy.set_list('path_exclusions',
                    ['D:\\Data\\Share{:03d}\\*'.format(index) for index in range(220)])
    console = load(EDRFPolicyDetection, 'Claude - EDRF 50.3 Detection Test')
    add_console_defaults(policy, console, ['mxa/eventor/excludedPaths_1'])
    policy.set_registry_exclusions([])                        # stored as an empty JSON document
    assert_same(policy, console, ['path_exclusions'])        # console separator "|"
    assert console.get_option('update_interval') == 1        # 60 seconds added by the console


# ------------------------------ Streaming ------------------------------
SYSLOG = [EDRFSyslogServer('Syslog "A"', '10.0.0.5', '514', 'P2'),
          EDRFSyslogServer('B', '10.0.0.6', 6514, 'P4', tls=True, enabled=False)]
FILTERS = [EDRFEventFilter('Drop "noise"', 'ms_windows_event', [
    EDRFFilterCondition('EventID', '4688', 'exclude', 'match'),
    EDRFFilterCondition('Image', '.*\\\\svc"x\\.exe', 'exclude', 'regex')],
    default_action='allow')]
FILE_EVENTS = [EDRFFileEvent('IIS logs', 'IIS', 'C:\\\\inetpub\\\\logs\\\\*.log')]
SYSMON = EDRFEventLog('Sysmon "x"', 'Microsoft-Windows-Sysmon/Operational', '1, 3')


def test_streaming_rebuild():
    policy = new(EDRFPolicyStreaming)
    assert policy.get_table('event_logs') == EDRFPolicyStreaming.DEFAULT_EVENT_LOGS
    policy.set_list('windows_process_exclusions', [
        'C:\\Program Files\\Vendor{:03d}\\agent.exe'.format(index) for index in range(130)] +
        ['C:\\Tools\\a"b.exe'])
    policy.set_list('logon_ignore_accounts', ['svc"x'] + policy.get_list('logon_ignore_accounts'))
    for name, value in [('event_streamer', '1'), ('os_process_events', '1'),
                        ('os_dns_events', '1'), ('os_registry_events', '1'),
                        ('events_to_dxl', '1'), ('events_to_helix', '1'),
                        ('helix_server', 'abc.ingest.apps.fireeye.com'),
                        ('helix_path', '/ingest/abc'), ('events_to_syslog', '1'),
                        ('delete_batch_size', 150)]:
        policy.set_option(name, value)
    with pytest.raises(ValueError):
        policy.set_option('helix_id', 'hx"id')               # shown as hx\"id by the console
    policy.set_setting_value('Streaming', 'mxa/EventStreamer/helixId', 'hx\\"id', True)
    policy.set_table('syslog_servers', SYSLOG)
    policy.set_table('event_filters', FILTERS)
    policy.set_table('file_events', FILE_EVENTS)
    policy.add_to_table('event_logs', SYSMON)
    console = load(EDRFPolicyStreaming, 'Claude - EDRF 50.3 Streaming Test')
    add_console_defaults(policy, console, [
        'UEDR/TraceScanner/ignored_process_1', 'UEDR/TraceScanner/max_hash_file_size_mb',
        'UEDR/TraceScanner/max_hash_file_size_mb_linux',
        'UEDR/TraceScanner/max_hash_file_size_mb_mac', 'mxa/EventStreamer/dxl/compressioned',
        'mxa/EventStreamer/dxl/topic_compressed', 'mxa/EventStreamer/dxl/topic_uncompressed'])
    assert console.get_table('syslog_servers') == SYSLOG
    assert console.get_table('event_logs')[-1] == SYSMON
    # Console line breaks; ";" kept at the end of the accounts (typed before the default ones).
    assert_same(policy, console, ['windows_process_exclusions', 'logon_ignore_accounts'])
    text = console.to_markdown()
    for expected in ['## 2. Event streamer', '| Process Event | Yes |',
                     '| Yes | Syslog "A" | P2 | 10.0.0.5 | 514 | No |',
                     '| Drop "noise" | Event Log | Windows | Allow | Exclude EventID Match 4688',
                     '| Helix server | abc.ingest.apps.fireeye.com |']:
        assert expected in text, expected
    policy.remove_from_table('syslog_servers', 'B')
    assert policy.get_table('syslog_servers') == SYSLOG[:1]


def test_streaming_tables_checks():
    policy = new(EDRFPolicyStreaming)
    for name, rows in [
            ('syslog_servers', [EDRFSyslogServer('', '10.0.0.5', 514)]),
            ('syslog_servers', [EDRFSyslogServer('A', 'bad host', 514)]),
            ('syslog_servers', [EDRFSyslogServer('A', '10.0.0.5', 65536)]),
            ('syslog_servers', [EDRFSyslogServer('A', '10.0.0.5', 514, 'P5')]),
            ('syslog_servers', [EDRFSyslogServer('A', '10.0.0.5', 514),
                                EDRFSyslogServer('A ', '10.0.0.6', 514)]),     # duplicate name
            ('event_filters', [EDRFEventFilter('F', 'ms_dns_es', [])]),
            ('event_filters', [EDRFEventFilter('F', 'ms_dns_es', [
                EDRFFilterCondition('a', 'b')], os='linux')]),             # OS Events only
            ('event_filters', [EDRFEventFilter('F', 'ms_dns_es', [
                EDRFFilterCondition('a', '')])]),
            ('event_filters', [EDRFEventFilter('F', 'syslog', [EDRFFilterCondition('a', 'b')])]),
            ('file_events', [EDRFFileEvent('F', 'APACHE', 'C:\\logs\\*.log')]),
            ('file_events', [EDRFFileEvent('F', 'IIS', 'x' * 257)]),
            ('event_logs', [EDRFEventLog('', 'Security', '1')]),
            ('event_logs', [EDRFEventLog('L', 'Security', '1' * 3073)]),
            ('event_logs', [EDRFFileEvent('F', 'IIS', 'C:\\logs\\*.log')])]:   # wrong row class
        with pytest.raises(ValueError):
            policy.set_table(name, rows)
    policy.set_table('event_filters', [EDRFEventFilter('Linux', 'xagt_realtime_evt', [
        EDRFFilterCondition('process', 'cron')], os='linux')])
    with pytest.raises(ValueError):
        policy.remove_from_table('file_events', 'missing')


def test_streaming_table_length():
    """
    The console cuts an event list whose JSON reaches 2820 characters
    (checked on the lab: 3 of the 4 imported logs shown).
    """
    console = load(EDRFPolicyStreaming, 'Claude - EDRF 50.3 Limits2 Streaming Test')
    logs = console.get_table('event_logs')
    assert len(logs) == 4
    policy = new(EDRFPolicyStreaming)
    with pytest.raises(ValueError):
        policy.set_table('event_logs', logs)
    policy.set_table('event_logs', logs[:3])


def test_streaming_options():
    policy = new(EDRFPolicyStreaming)
    with pytest.raises(ValueError):
        policy.set_option('helix_id', 'abc')                 # Helix not enabled
    policy.set_option('events_to_helix', '1')
    policy.set_option('helix_id', 'abc')
    with pytest.raises(ValueError):
        policy.set_option('helix_server', 'x' * 129)
    policy.set_option('events_to_helix', '0')                # cleared, as the console does
    assert policy.get_option('helix_id') == ''
    for name, value in [('cloud_interval', 9), ('cloud_interval', 1801), ('delete_batch_size', 0),
                        ('send_interval', 61), ('batch_max_events', 1),
                        ('vacuum_frequency', 499), ('max_events_in_db', 25001),
                        ('send_on_num_events', 4)]:
        with pytest.raises(ValueError):
            policy.set_option(name, value)
    policy.set_option('cloud_interval', 10)
    assert EDRFPolicyStreaming.options()['send_to_cloud'] == 'Send trace events to DXL Broker'


# ------------------------------ Remediation ------------------------------
def test_remediation_byhand_rebuild():
    console = load(EDRFPolicyRemediation, 'Claude - EDRF 50.3 Remediation ByHand Test')
    name, logo = console.get_containment_image()
    assert name == 'logo.png' and logo.startswith(b'\x89PNG')
    policy = new(EDRFPolicyRemediation)
    assert policy.get_option('message_source') == 'byhand'
    for option, value in [('host_remediation', '1'), ('containment_title', 'Lab SOC Alert'),
                          ('containment_message', 'Contact the SOC: C:\\SOC\\help.txt\nLine 2 é'),
                          ('release_message', 'Released by the SOC.'),
                          ('windows_allowed_paths', ['C:\\Tools\\vpn.exe'])]:
        policy.set_option(option, value)
    policy.set_containment_image(name, logo)
    policy.add_allowed_ip(EDRFAllowedIP('fd00::10', 'ULA host'))      # refused by the 2.1.2
    add_console_defaults(policy, console, ['UEDR/NetworkFlow/favicon',
                                           'UEDR/NetworkFlow/favicon_1',
                                           'UEDR/NetworkFlow/favicon_2'])
    assert_same(policy, console)
    page = console.get_containment_page()
    assert '<title>Lab SOC Alert</title>' in page and '<img src="logo.png" />' in page
    assert 'C:\\SOC\\help.txt\nLine 2 é</pre>' in page
    assert console.get_option('containment_message') == 'Contact the SOC: C:\\SOC\\help.txt;Line 2 é'
    assert len(console._get('UEDR/NetworkFlow/favicon')) == 9216     # 3 parts joined
    text = console.to_markdown()
    assert '| Logo | logo.png (79 bytes) |' in text and '| Title | Lab SOC Alert |' in text
    policy.set_option('containment_title', 'New $& title')        # JavaScript replace() codes
    assert '<title>New {title} title</title>' in policy.get_containment_page()
    assert 'help.txt\nLine 2 é</pre>' in policy.get_containment_page()
    # Opened again, the console shows the stored message (semicolons) and builds the page with it.
    reopened = EDRFPolicyRemediation(policy.root)
    reopened.set_option('containment_title', 'Lab SOC Alert')
    assert 'help.txt;Line 2 é</pre>' in reopened.get_containment_page()
    policy.clear_containment_image()
    assert policy.get_containment_image() is None
    assert '<img src="" />' in policy.get_containment_page()


def test_remediation_url_rebuild():
    policy = new(EDRFPolicyRemediation)
    with pytest.raises(ValueError):
        policy.set_option('containment_url', 'http://10.0.0.5/contained.html')   # by hand
    policy.set_option('message_source', 'url')
    for url in ['http://host.example.com/a.html', 'ftp://10.0.0.5/a.html',
                'http://10.0.0.5/a.txt', 'http://[::1]/a.html', 'http://10.0.0.5/' + 'a' * 100]:
        with pytest.raises(ValueError):
            policy.set_option('containment_url', url)
    policy.set_option('containment_url', 'http://10.0.0.5/contained.html')
    for option, value in [('containment_title', 'T'), ('containment_message', 'M')]:
        with pytest.raises(ValueError):
            policy.set_option(option, value)                 # "Enter by hand" options
    with pytest.raises(ValueError):
        policy.set_containment_image('logo.png', b'')
    console = load(EDRFPolicyRemediation, 'Claude - EDRF 50.3 Remediation URL Test')
    add_console_defaults(policy, console)
    policy.set_allowed_ips([])                                # stored as an empty JSON list
    assert_same(policy, console)
    assert '| From URL | http://10.0.0.5/contained.html |' in console.to_markdown()
    policy.set_option('message_source', 'byhand')
    assert policy.get_option('containment_url') == '' and policy.get_containment_page()


def test_remediation_checks():
    policy = new(EDRFPolicyRemediation)
    for option, value in [('containment_title', ''), ('containment_title', 'x' * 101),
                          ('containment_message', ' '), ('release_message', ''),
                          ('containment_message', 'Call "SOC"'),      # stops the console page
                          ('windows_allowed_paths', ['C:\\"x"'])]:
        with pytest.raises(ValueError):
            policy.set_option(option, value)
    policy.set_option('containment_title', 'Call "SOC"')              # escaped: no problem
    for name, data in [('logo.bmp', b'x'), ('logo.png', b'x' * 1024001), ('a"b.png', b'x'),
                       ('dir/logo.png', b'x')]:
        with pytest.raises(ValueError):
            policy.set_containment_image(name, data)
    policy.set_containment_image('LOGO.JPEG', b'x' * 1024000)
    assert len(policy.get_setting_value('Remediation', 'UEDR/NetworkFlow/containment_notify_image')) \
        == 3072                                              # split in parts
    for address in [EDRFAllowedIP('h' * 97 + '.com'), EDRFAllowedIP('10.0.0.1', 'd' * 101)]:
        with pytest.raises(ValueError):
            policy.add_allowed_ip(address)


# ------------------------------ Field lengths ------------------------------
def test_field_lengths():
    """
    maxlength of the console fields (read on the lab pages of the extension
    50.3: an orion:textbox without maxlength gets 100) and 3072 characters
    per stored setting.
    """
    general = new(EDRFPolicyGeneral, FIXTURE_212)
    for name, value in [('proxy_host', 'p' * 101), ('proxy_username', 'u' * 101),
                        ('proxy_exclude_hosts', ['h' * 3073]),
                        ('proxy_username', 'a`b'), ('proxy_host', '${x}')]:
        with pytest.raises(ValueError):
            general.set_option(name, value)
    general.set_option('proxy_host', 'p' * 100)
    investigation = new(EDRFPolicyInvestigation)
    investigation.set_list('network_process_exclusions', ['C:\\' + 'x' * 199997])
    assert len(investigation._get('UEDR/NetworkFlow/ignored_paths')) == 200000
    assert len(investigation._get_stored('UEDR/NetworkFlow/ignored_paths')) == 200001
    with pytest.raises(ValueError):
        investigation.set_list('network_process_exclusions', ['C:\\' + 'x' * 199998])
    detection = new(EDRFPolicyDetection)
    for exclusion in [EDRFRegistryExclusion('Users', 'k' * 261),
                      EDRFRegistryExclusion('Users', 'Software', ['v' * 130, 'w' * 130])]:
        with pytest.raises(ValueError):
            detection.add_registry_exclusion(exclusion)
    detection.add_registry_exclusion(EDRFRegistryExclusion('Users', 'k' * 260, ['v' * 260]))
    remediation = new(EDRFPolicyRemediation)
    with pytest.raises(ValueError):                           # JSON longer than 3072 characters
        remediation.set_allowed_ips([EDRFAllowedIP('10.0.{}.{}'.format(index // 250, index % 250),
                                                   'd' * 40) for index in range(60)])


def test_xml_content_ascii():
    """
    The Web API import reads a UTF-8 file as ISO-8859-1 (checked on the lab):
    the characters out of ASCII are written as XML character references.
    """
    policy = new(EDRFPolicyRemediation)
    policy.set_option('containment_title', 'Alerte sécurité €')
    data = policy.get_xml_content()
    assert data.isascii() and b'Alerte s&#233;curit&#233; &#8364;' in data
    assert 'Alerte sécurité €' in policy.get_xml_content_str()
    copy = EDRFPolicies()
    copy.set_xml_content(data)
    assert EDRFPolicyRemediation(copy.root).get_option('containment_title') == 'Alerte sécurité €'
