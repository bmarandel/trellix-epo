"""
Markdown export (Policy.to_markdown / save_markdown), checked against the
console display of the same policies (ePO 5.10, screenshots kept in
scripts/estp/screenshots/).
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import (Policy, ESTPPolicyOnAccessScan, OASExclusionList, OASState,
                                 ESTPPolicyOnDemandScan, ESTPPolicyExploitPrevention,
                                 ESFWPolicyRules)

FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.fixture
def oas_policy():
    policy = ESTPPolicyOnAccessScan()
    policy.load_from_file(str(FIXTURES / 'oas_policy.xml'))
    return policy


def test_md_table_escaping():
    table = Policy.md_table(['A', 'B'], [['x|y', 'l1\nl2']], numbered=True)
    assert table == '| # | A | B |\n|---|---|---|\n| 1 | x\\|y | l1<br>l2 |\n'
    assert Policy.md_table(['A'], []) == '*None*\n'


def test_not_implemented():
    with pytest.raises(NotImplementedError):
        Policy(None).md_sections()


def test_oas_header_and_sections(oas_policy):
    text = oas_policy.to_markdown(author='Tester', reviewers=['CISO'])
    assert text.startswith('# Demo (ePO Server)\n')
    assert '| ePO server | W2022EPO510 |' in text
    assert '| Policy category | On-Access Scan |' in text
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. On-Access Scan', '## 2. Ransomware',
                        '## 3. Trellix GTI', '## 4. Antimalware Scan Interface (Windows only)',
                        '## 5. Threat Detection User Messaging (Windows only)',
                        '## 6. Process Settings', '## 7. ScriptScan (Windows only)',
                        '## 8. Document control']
    assert '| Reviewed/Approved by | CISO |  |  |' in text


def test_oas_values_match_console(oas_policy):
    text = oas_policy.to_markdown()
    for row in ['| On-Access Scan | Enable |',
                '| Specify maximum number of seconds for each file scan | Yes (45 seconds) |',
                '| Sensitivity level | Very high |',
                '| Message | Trellix Endpoint Security detected a threat. |',
                '| 1 | 4nt.exe | High Risk |',
                '| When to scan | Let Trellix decide |',
                '| Threat detection first response | Clean files |',
                '| On Timeout (Linux only) | Allow access to files |',
                '| On Scan Error (Linux only) | Deny access to files |',
                '| Enable ScriptScan | Yes |']:
        assert row in text
    for process_type in ['Standard', 'High Risk', 'Low Risk']:
        assert '### Process Type: {}\n'.format(process_type) in text


def test_oas_standard_settings_only(oas_policy):
    oas_policy.use_standard_settings_only = '1'
    text = oas_policy.to_markdown()
    assert '### Process Type: Standard' in text
    assert 'Process Type: High Risk' not in text
    assert '4nt.exe' not in text


def test_oas_exclusions(oas_policy):
    exclusions = OASExclusionList()
    exclusions.add_folder('C:\\Data\\', with_subfolders=True, notes='Backup share')
    exclusions.add_file_type('LOG', on_read=False)
    oas_policy.exclusion_list = exclusions.excl_list
    text = oas_policy.to_markdown()
    assert '| 1 | C:\\\\Data\\\\ | Yes | Read & Write | Backup share |' in text
    assert '| 2 | All files of type LOG | -- | Write |  |' in text


def test_save_markdown(oas_policy, tmp_path):
    md_file = tmp_path / 'oas.md'
    assert oas_policy.save_markdown(str(md_file))
    assert md_file.read_text(encoding='utf-8').startswith('# Demo (ePO Server)')


def test_oas_state(oas_policy):
    # Checked on the lab ePO 5.10 (policy "Claude - OAS State Test"): the
    # third radio button is stored as bOASEnabled = 0 + bUnregisterWithWSC = 1.
    assert oas_policy.get_setting_value('General', 'bUnregisterWithWSC') is None
    assert oas_policy.on_access_scan == OASState.ENABLED
    oas_policy.on_access_scan = OASState.DISABLED_UNREGISTER_WSC
    assert oas_policy.get_setting_value('General', 'bOASEnabled') == '0'
    assert oas_policy.get_setting_value('General', 'bUnregisterWithWSC') == '1'
    assert oas_policy.on_access_scan == OASState.DISABLED_UNREGISTER_WSC
    assert '| On-Access Scan | Disable and unregister with Windows Security Center |' \
        in oas_policy.to_markdown()
    oas_policy.on_access_scan = OASState.DISABLED
    assert oas_policy.get_setting_value('General', 'bUnregisterWithWSC') == '0'
    assert oas_policy.on_access_scan == OASState.DISABLED
    assert '| On-Access Scan | Disable |' in oas_policy.to_markdown()
    with pytest.raises(ValueError):
        oas_policy.on_access_scan = '3'


@pytest.fixture
def ods_policy():
    policy = ESTPPolicyOnDemandScan()
    policy.load_from_file(str(FIXTURES / 'ods_policy.xml'))
    return policy


def test_ods_sections(ods_policy):
    # Layout checked against the ePO 5.10 console (On-Demand Scan "My Default").
    text = ods_policy.to_markdown()
    assert text.startswith('# Ben-ODS\n')
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. Full Scan', '## 2. Quick Scan',
                        '## 3. Right-click Scan (Windows only)', '## 4. Document control']
    full, quick, right_click = [text.split(heading)[1].split('\n## ')[0]
                                for heading in headings[1:4]]
    assert [line for line in full.splitlines() if line.startswith('### ')] == [
        '### What to Scan', '### Additional Scan Options', '### Scan Locations',
        '### File Types to Scan', '### Trellix GTI', '### Exclusions', '### Actions',
        '### Scheduled Scan Options', '### Performance', '### Account (Windows only)']
    assert '| Boot sectors (Windows only) | Yes |' in full
    assert '| Sensitivity level | Medium |' in full
    assert '| 1 | Memory for rootkits |' in full
    assert '| 12 | Program Files folder |' in full
    assert '| 15 | C:\\\\TestBen |' in full
    assert '| # | Item | Exclude Subfolders | Notes |' in full
    assert '| 1 | All files of type LOG | -- |  |' in full
    assert '| When to scan | Scan anytime |' in full
    assert '| Maximum number of times user can defer for one hour | 23 |' in full
    assert '| Specify maximum number of seconds for each file scan (Linux only) | Yes (45) |' \
        in full
    assert '| Specify maximum number of threads allowed (Linux only) | Yes (5) |' in full
    assert '| Limit maximum CPU usage (Windows & Linux only) | 80% |' in full
    assert '| When to scan | Scan only when the system is idle (Windows & Mac only) |' in quick
    assert '| User can resume paused scans (Windows only) | Yes |' in quick
    assert '| User can defer scans |' not in quick
    assert '| System utilization (Windows only) | Below normal |' in quick
    # Right-click Scan: every box is Windows only; Subfolders is in What to
    # Scan; no locations, schedule or account; the second action is
    # "Continue scanning" in this export.
    assert '### What to Scan (Windows only)' in right_click
    assert '| Subfolders | Yes |' in right_click
    assert 'Scan Locations' not in right_click
    assert 'Scheduled Scan Options' not in right_click
    assert '### Account' not in right_click
    assert '| If first response fails | Continue scanning |' in right_click
    assert '| Use the scan cache | No |' in right_click
    assert '| System utilization | Below normal |' in right_click


def test_md_escape_markdown_chars():
    assert Policy.md_escape('**\\PresentationHost.exe') == '\\*\\*\\\\PresentationHost.exe'
    assert Policy.md_escape('a_b `c` <d>') == 'a\\_b \\`c\\` &lt;d&gt;'


@pytest.fixture
def ep_policy():
    policy = ESTPPolicyExploitPrevention()
    policy.load_from_file(str(FIXTURES / 'ep_policy.xml'))
    return policy


def test_ep_sections(ep_policy, capsys):
    text = ep_policy.to_markdown()
    assert capsys.readouterr().out == ''
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. Exploit Prevention (Windows & Linux only)',
                        '## 2. Generic Privilege Escalation Prevention (Windows only)',
                        '## 3. Windows Data Execution Prevention (Windows only)',
                        '## 4. Network Intrusion Prevention (Windows only)',
                        '## 5. Exclusions (Windows & Linux only)',
                        '## 6. Signatures (Windows & Linux only)',
                        '## 7. Application Protection Rules (Windows only)',
                        '## 8. Document control']
    assert '| Enable Windows Data Execution Prevention | No |' in text
    assert '| Automatically block network intruders | No |' in text
    assert 'Number of seconds' not in text
    # 416 Trellix signatures - 28 deleted ones + 2 Expert Rules.
    assert '| Total | 151 | 239 | 390 |' in text
    assert '| 3718 |' not in text  # SignatureIsDeleted = 1
    assert '| 20001 | Google Chrome Launch | High | Yes | Yes | Enabled | Processes | ' \
        'User-defined | Windows |' in text
    assert '| 1 | .Net Framework Host | Enabled | Include | \\*\\*\\\\PresentationHost.exe; |' \
        in text
    assert text.count('| Trellix-defined |\n') >= 179


def test_ep_nips_disabled(ep_policy):
    # Console (ePO 5.10): with Network Intrusion Prevention disabled, the
    # block options and the Network IPS signatures (24 here) aren't shown.
    ep_policy.nips = '0'
    text = ep_policy.to_markdown()
    assert '| Enable Network Intrusion Prevention | No |' in text
    assert 'Automatically block network intruders' not in text
    assert 'Network IPS signatures are not listed' in text
    assert '| Network IPS |' not in text
    assert '| Total | 141 | 225 | 366 |' in text


def test_ep_nips_block_time(ep_policy):
    ep_policy.nips_block_time = 600
    text = ep_policy.to_markdown()
    assert '| Automatically block network intruders | Yes |' in text
    assert '| Number of seconds (1-9999) to block | 600 |' in text


@pytest.fixture
def fw_policy():
    policy = ESFWPolicyRules()
    policy.load_from_file(str(FIXTURES / 'fw_policy_all.xml'))
    return policy


def test_fw_sections(fw_policy):
    # load_policy() is called by md_sections() when needed.
    text = fw_policy.to_markdown()
    assert text.startswith('# Demo\n')
    assert '| Product | Endpoint Security Firewall |' in text
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. Rules summary', '## 2. Rule details',
                        '## 3. Document control']
    assert '56 rule(s) in 10 group(s).' in text
    assert '| 1 | \\[Group\\] McAfee core networking | Enabled |  | Either | Any protocol | All Protocols |' in text
    assert '| 1.8 | Allow DNS traffic | Enabled | Allow | Out | Any protocol | UDP | ' \
        'Any (port Any) | Any (port 53) | All | No |' in text
    assert 'SYSTEM (path: \\*\\*\\\\SYSTEM)' in text
    assert 'McAfee signed executables 7 (signer: CN=McAfee VTP signed)' in text
    assert '### 1 McAfee core networking (group)\n' in text
    assert '### 1.8 Allow DNS traffic\n' in text
    # Detail cards: compact two-column tables, two settings per line.
    assert 'Treat match as intrusion and Schedule: Windows & Linux only. ' \
        'Applications: Windows & Mac only.' in text
    assert '### 1.8 Allow DNS traffic\n\n| Status: Enabled | Action: Allow |\n|---|---|\n' \
        '| **Direction:** Out | **Log:** No |\n' \
        '| **Treat match as intrusion:** No | **Connection types:** ' in text
    assert '| **Remote networks:** Any | **Remote port:** 53 |' in text
    assert '| **Notes:** | **Last changed:** By ' in text
    assert '### 1 McAfee core networking (group)\n\n| Status: Enabled | Direction: Either |\n' \
        '|---|---|\n| **Location:** None | **Rules:** 11 |\n' in text
    assert '| Location name |' not in text and '| Status | Enabled |' not in text
    assert '| 3.1 | Allow outbound ePolicy Orchestrator server - APACHE | Enabled | Allow | Out | ' \
        'IPv4 protocol, IPv6 protocol | All Protocols |' in text
    assert '| **Location:** LAN | **Rules:**' in text
    assert '**Default gateway:** 10.10.1.1<br>192.168.1.1' in text
    assert '**Last changed:** By admin on 2014/03/28 at 19:00:00 UTC+01:00 |' in text


def test_md_heading():
    assert Policy.md_heading('<b>x</b>\n# y') == '&lt;b&gt;x&lt;/b&gt; # y'
    assert Policy.md_heading(None) == ''


def test_md_escape_links_and_images():
    # A policy value must not become a link or a remote image (tracking pixel).
    assert Policy.md_escape('![x](https://a.example/p.png)') == \
        '!\\[x\\](https://a.example/p.png)'
    assert Policy.md_heading('[Approve](https://a.example/login)') == \
        '\\[Approve\\](https://a.example/login)'


def test_no_html_injection(oas_policy, fw_policy):
    # Names come from the policy (anyone allowed to edit it in ePO): they
    # must not inject HTML/Markdown in headings of the generated document.
    payload = '<img src=x onerror=alert(1)>'
    oas_policy.root.find('EPOPolicyObject').set('name', payload + '\n# Fake heading')
    text = oas_policy.to_markdown()
    assert text.startswith('# &lt;img src=x onerror=alert(1)&gt; # Fake heading\n')
    assert '\n# Fake heading' not in text
    fw_policy.load_policy()
    rule = next(rule for rule in fw_policy.rul.values() if rule['Name'] == 'Allow DNS traffic')
    rule['Name'] = payload
    text = fw_policy.to_markdown()
    assert '<img' not in text
    assert '### 1.8 &lt;img src=x onerror=alert(1)&gt;\n' in text


def test_no_html_injection_access_protection():
    from mcafee_epo_policies import ESTPPolicyAccessProtection, APRule, APSubRule, APTarget
    policy = ESTPPolicyAccessProtection()
    policy.load_from_file(str(FIXTURES / 'ap_policy_rules.xml'))
    rule = APRule('<img src=x onerror=alert(1)>', report=True)
    rule.add_subrule(APSubRule('<script>alert(1)</script>', APSubRule.FILES, ['read'],
                               targets=[APTarget('C:\\Data\\*')]))   # < > refused in a target
    policy.add_rule(rule)
    text = policy.to_markdown()
    assert '<img' not in text and '<script' not in text and '<b>' not in text
    assert '#### Subrule: &lt;script&gt;alert(1)&lt;/script&gt;\n' in text
