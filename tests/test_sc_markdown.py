"""
Markdown export of the Solidcore policies, checked against the ePO 5.10
console (Solidcore 8.4.5) on the lab test policies ("Claude - ..."):
console tabs, group boxes, list columns, the labels of the exclusion types
(scor.utils.optionStringMap), of the filter conditions and events, and of the
Execution Control actions/matches. The rules policies list their Rule Groups
(My Rules, then the shared Rule Groups) and the tabs of each rule group.
"""

from pathlib import Path

import pytest

from trellix_epo import (SCPolicies, SCGENPolicyConfiguration, SCGENPolicyExceptionRules,
                                 SCAWLPolicyOptions, SCAWLPolicyRules, SCCCPolicyRules,
                                 SCFIMPolicyRules)

FIXTURES = Path(__file__).parent / 'fixtures'


def load(name, cls):
    policies = SCPolicies()
    policies.load_from_file(str(FIXTURES / name))
    item = policies.list()[0]
    return cls(policies.get_policy(item['typeid'], item['name']))


def headings(policy):
    return [heading for heading, _ in policy.md_sections()]


def test_configuration():
    policy = load('sc_gen_config.xml', SCGENPolicyConfiguration)
    assert headings(policy) == ['CLI', 'Throttling', 'Miscellaneous', 'Logging configuration',
                                'Inventory configuration', 'Certificate configuration',
                                'Custom configuration']
    text = policy.to_markdown()
    assert text.startswith('# Claude - Config Import Test\n\nSolidcore - Configuration (Client)')
    for row in ['| Password | Set |',
                '| Disable CLI after ... failed attempts within ... minutes | 4 failed attempts '
                'within 30 minutes |',
                '| Events | No |', '| Solidcore log file size (KB) | 5000 |',
                '| SkipValidateFileLength | 1 |']:
        assert row in text, row
    # The CLI password is hashed by ePO: never written.
    hashes = policy.get_cli_password_hash()
    assert all(value not in text for value in hashes.values() if value)


def test_exception_rules():
    text = load('sc_gen_exceptions_win.xml', SCGENPolicyExceptionRules).to_markdown()
    assert 'Solidcore - Exception Rules (Windows) policy' in text
    for row in ['| Exclude path from write-protection rules | \\\\ClaudeTest\\\\wp |',
                '| Exclude volume from protection | Z: |',
                '| Disable ROP protection (DLL Relocation VASR) | claudetest.dll |']:
        assert row in text, row
    text = load('sc_gen_exceptions_unix.xml', SCGENPolicyExceptionRules).to_markdown()
    assert '| Exclude path from the allow list | /opt/claudetest |' in text


def test_awl_options():
    policy = load('sc_awl_options_win.xml', SCAWLPolicyOptions)
    assert headings(policy) == ['Self-Approval', 'End User Notifications', 'Features',
                                'Inventory', 'Reputation']
    text = policy.to_markdown()
    for row in ['| Justification Message | Optional |',
                '| Execution Denied | Claude test {file\\_name} | No |',
                '| NX (64-Bit) (reboot required) | Yes |',
                '| Pull Complete Inventory Interval (days between consecutive inventory pulls) | 8 |',
                '| Allow files with | Known Trusted and above |',
                '| Send files with | No |']:
        assert row in text, row
    unix = load('sc_awl_options_unix.xml', SCAWLPolicyOptions)
    assert headings(unix) == ['Reputation']
    assert 'TIE' not in unix.to_markdown()


def test_awl_rules_windows():
    policy = load('sc_awl_rules_win_groups.xml', SCAWLPolicyRules)
    assert headings(policy) == ['Rule Groups', 'My Rules', 'Rule Group: Claude - RG Copy IE (Windows)',
                                'Rule Group: Claude - RG Lib AWL (Windows)',
                                'Rule Group: Internet Explorer (32 bit)']
    own = dict(policy.md_sections())['My Rules']
    assert own.index('### Updater Processes') < own.index('### Certificates') < \
        own.index('### Execution Control')
    assert '| MUSARUBRA US LLC | GlobalSign GCC R45 CodeSigning CA 2020 | 2025-04-05 07:50:45 UTC ' \
           '| Yes | E2ECert |' in own
    text = load('sc_awl_rules_win.xml', SCAWLPolicyRules).to_markdown()
    for row in ['| ClaudeUpdater | Name | C:\\\\Claude\\\\updater.exe | Parent | claudeparent.exe | Yes '
                '| Yes |',
                '| ClaudeBanSha | Ban | File SHA-1 | 1111111111111111111111111111111111111111 |',
                '| 2 | Program equals claude.exe AND File equals C:\\\\Temp\\\\claude.txt | Yes |',
                '| Claude exec rule | Monitor | claudeexec.exe | Equals : C:\\\\Claude\\\\claudeexec.exe '
                '|  | Equals : cmd.exe |  |']:
        assert row in text, row


def test_awl_rules_unix():
    policy = load('sc_awl_rules_unix.xml', SCAWLPolicyRules)
    own = dict(policy.md_sections())['My Rules']
    assert [line[4:] for line in own.splitlines() if line.startswith('### ')] == [
        'Updater Processes', 'Directories', 'Executable Files', 'Exclusions', 'Filters']
    assert '#### Events' in own and 'Inventory' not in own
    assert 'Rule Group: Global Rules' in headings(policy)


def test_cc_and_fim_rules():
    text = load('sc_cc_rules_win.xml', SCCCPolicyRules).to_markdown()
    for row in ['| Exclude | C:\\\\E2E\\\\Secrets\\\\public.txt |',
                '| Exclude | HKEY\\_LOCAL\\_MACHINE\\\\SOFTWARE\\\\E2E\\\\Cache |',
                '| User | LAB\\\\deployer | Deployer | E2EDeployer |  |']:
        assert row in text, row
    unix = load('sc_cc_rules_unix.xml', SCCCPolicyRules).to_markdown()
    assert 'Write-Protect Registry' not in unix and '### Users' not in unix
    assert '| Updater Label | Updater Type | File | Condition | Parent |' in unix
    text = load('sc_fim_rules_win.xml', SCFIMPolicyRules).to_markdown()
    for row in ['| Include | C:\\\\E2E\\\\watched.ini | Tracking:Enabled, Encoding:UTF-8, Directory:No |',
                '| Exclude | C:\\\\E2E\\\\Logs\\\\ | Tracking:Disabled |',
                'Tracking:Enabled, Encoding:Auto Detect, Directory:Yes, Recurse:Yes | {\\*.xml}, '
                '{\\*.ini} | {\\*.bak} |',
                '| 1 | Event equals File Modified AND Program ends with \\\\backup.exe |']:
        assert row in text, row
    assert '### Registry' not in load('sc_fim_rules_unix.xml', SCFIMPolicyRules).to_markdown()


def test_event_labels():
    assert SCAWLPolicyRules.md_event('FILE_MODIFIED') == 'File Modified'
    # Stored as WRITE_DENIED, shown "File Write Denied" by the console.
    assert SCAWLPolicyRules.md_event('WRITE_DENIED') == 'File Write Denied'
    assert SCAWLPolicyRules.md_event('UNKNOWN_CODE') == 'UNKNOWN_CODE'


@pytest.mark.parametrize('name', sorted(path.name for path in FIXTURES.glob('sc_*.xml')
                                        if 'rulegroups' not in path.name))
def test_every_fixture_renders(name):
    classes = {'Lockdown Rules': SCGENPolicyConfiguration,
               'Attr Rules': SCGENPolicyExceptionRules, 'AWL Options': SCAWLPolicyOptions,
               'AWL Rules': SCAWLPolicyRules, 'CC Rules': SCCCPolicyRules,
               'Mon Rules': SCFIMPolicyRules}
    policies = SCPolicies()
    policies.load_from_file(str(FIXTURES / name))
    for item in policies.list():
        cls = [c for prefix, c in classes.items() if item['typeid'].startswith(prefix)][0]
        assert cls(policies.get_policy(item['typeid'], item['name'])).to_markdown()
