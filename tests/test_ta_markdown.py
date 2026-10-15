"""
Markdown export of the McAfee (Trellix) Agent policies, checked against the
ePO 5.10 console (Trellix Agent > General, Repository, Troubleshooting,
Custom Properties, Product Improvement Program) on the lab policies:

- ma_general.xml ("My Default") and ma_general_systray.xml ("Demo
  (Systray)"): the console shows the value of the section named after its
  form fields (AgentListenServer, AgentLogging...) when the "service" section
  differs (Demo: LazyCaching checked, HttpServerService.IsLazyCachingEnabled
  0; My Default: Relay Communication unchecked, RelayService.EnableClient 1),
  "Roll over count" is LogMaxRollover (1, not nGeneralRollOver 5), a
  SuperAgent repository path "DEFAULT" is shown empty, the "Sensor options"
  group stays hidden.
"""

import xml.etree.ElementTree as et
from pathlib import Path

from trellix_epo import (TAPolicyGeneral, TAPolicyRepository,
                                 TAPolicyTroubleshooting, TAPolicyCustomProps,
                                 TAPolicyTelemetry)

FIXTURES = Path(__file__).parent / 'fixtures'


def load(cls, name):
    return cls(et.parse(str(FIXTURES / name)).getroot())


def section(policy, heading):
    return dict(policy.md_sections())[heading]


def test_general_tabs():
    policy = load(TAPolicyGeneral, 'ma_general.xml')
    assert [heading for heading, _ in policy.md_sections()] == [
        'General', 'SuperAgent', 'Events', 'Logging', 'Updates', 'Peer-to-Peer', 'Deployment']
    text = policy.to_markdown()
    assert text.startswith('# My Default\n\nTrellix Agent - General policy')
    for row in ['| Policy enforcement interval (minutes) | 60 |',
                '| Enable About box in the Trellix system tray menu | Yes |',
                '| IP reporting mode | Default |',
                '| Force automatic reboot after (seconds) | No |',
                '| Agent-to-server communication interval (minutes) | 60 |',
                '| Enable Relay Communication | No |',
                '| Forward events with a priority equal or greater than | Major |',
                '| Roll over count | 1 |',
                '| Zipped log file size limit (MB) | 50 (default) |',
                '| Repository path (Unix) |  |',
                '| Enable Incompatibility check | Yes |']:
        assert row in text, row
    assert 'Sensor options' not in text


def test_general_console_sections_first():
    text = load(TAPolicyGeneral, 'ma_general_systray.xml').to_markdown()
    for row in ['| Enable LazyCaching (Ensure one or more Repository is enabled) | Yes |',
                '| Repository path (Windows) |  |',
                '| Enable Trellix system tray icon in a remote desktop session | Yes |',
                '| Agent-to-server communication interval (minutes) | 5 |',
                '| Zipped log file size limit (MB) | 200 |']:
        assert row in text, row
    assert 'Sensor options' not in text


def test_update_branches():
    text = section(load(TAPolicyGeneral, 'ma_general.xml'), 'Updates')
    assert '| Signatures and engines | AMCore Content Package | AMCORDAT2000 | Yes | Current |' \
        in text
    assert '| Patches and service packs | MsgBus Cert Updater | EPOAGENT5000META | Yes | Current |' \
        in text
    # The signatures and engines are listed first, as in the console.
    assert text.index('Signatures and engines |') < text.index('Patches and service packs |')


def test_repository():
    policy = load(TAPolicyRepository, 'ma_repository.xml')
    text = policy.to_markdown()
    assert [heading for heading, _ in policy.md_sections()] == ['Repositories', 'Proxy']
    assert '| Select repository by | Ping time |' in text
    assert '| Ping timeout (seconds) | 30 |' in text
    assert '| 1 | ePO\\_W2022EPO510 | Enabled |' in text
    assert '| Proxy settings | Use Internet Explorer settings' in text


def test_repository_proxy_password_never_written():
    policy = load(TAPolicyRepository, 'ma_repository.xml')
    for name, value in [('uiUseProxyType', '2'), ('szHttpProxyServer', 'proxy.example.com'),
                        ('bUseHttpAuthentication', '1'), ('szHttpProxyUser', 'svc'),
                        ('szHttpProxyPassword', 'S3cret!')]:
        policy.set_setting_value('ProxySettings', name, value)
    text = section(policy, 'Proxy')
    assert '| HTTP address | proxy.example.com |' in text
    assert '| HTTP password | Set |' in text
    assert 'S3cret' not in text


def test_troubleshooting():
    text = load(TAPolicyTroubleshooting, 'ma_troubleshooting.xml').to_markdown()
    assert '| Select language used by agent (Windows, Mac OSX and EWS agents only) | No |' in text
    assert '| Language |' not in text
    text = load(TAPolicyTroubleshooting, 'ma_troubleshooting_english.xml').to_markdown()
    assert '| Language | English |' in text


def test_custom_properties_and_telemetry():
    text = load(TAPolicyCustomProps, 'ma_custom_props.xml').to_markdown()
    assert '| Custom Property 8 | Yes | Yes |' in text
    text = load(TAPolicyTelemetry, 'ma_telemetry.xml').to_markdown()
    assert 'Trellix Agent - Product Improvement Program policy' in text
    assert '| Allow Trellix to collect usage, threat and diagnostic data |' in text
