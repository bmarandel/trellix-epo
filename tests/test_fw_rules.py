"""
Ported from the user's own test-fw.py, run against a real ePO export
(fw_policy_all.xml) captured from a live ePO server. The original script only
printed the parsed policy; the exact counts/content observed during this
session's dry run are now asserted.
"""

from pathlib import Path

import pytest

from trellix_epo import ESFWPolicyRules

FIXTURE = Path(__file__).parent / 'fixtures' / 'fw_policy_all.xml'


@pytest.fixture
def fw_policy():
    policy = ESFWPolicyRules()
    policy.load_from_file(str(FIXTURE))
    policy.load_policy()
    return policy


def test_load_policy_counts(fw_policy):
    assert fw_policy.get_name() == 'Demo'
    assert len(fw_policy.seq) == 11
    assert len(fw_policy.rul) == 66
    assert len(fw_policy.agg) == 48


def test_get_content(fw_policy):
    content = fw_policy.get_content()
    assert content.startswith('# McAfee core networking/')
    assert 'Allow outbound System application' in content
    assert 'Action: ALLOW' in content


def test_icmp_message_type(fw_policy):
    # A lab ePO 5.10 policy had ICMP rules without MessageType setting (and
    # one with the code '255' = All): get_content() used to crash on them.
    rule = next(rul for rul in fw_policy.rul.values() if rul['Name'].strip() ==
                'Allow outbound ICMPv4  traffic'.strip())
    del rule['MessageType']
    assert 'Protocol: ICMP/Any\r\nMessage Type: All' in fw_policy.get_content()
    # '255' is "All" in the console rule editor (ePO 5.10).
    rule['MessageType'] = ['255']
    assert 'Protocol: ICMP/Any\r\nMessage Type: All' in fw_policy.get_content()
    rule['MessageType'] = ['254']
    assert 'Message Type: Type 254' in fw_policy.get_content()
    assert 'ICMP (Type 254)' in fw_policy.to_markdown()


def test_get_content_escapes_policy_values(fw_policy):
    # Names/notes from the policy must not become Markdown links or images.
    rule = next(rul for rul in fw_policy.rul.values() if rul['Name'] == 'Test All')
    rule['Name'] = '[Approve](https://a.example/login)'
    rule['Note'] = '![x](https://a.example/p.png)'
    content = fw_policy.get_content() + fw_policy.get_toc()
    assert '](https://a.example' not in content.replace('\\](', '')
    assert '\\[Approve\\](https://a.example/login)' in content
    assert '!\\[x\\](https://a.example/p.png)' in content
    # The Markdown export table escapes the user name once only.
    rule['LastModifyingUsername'] = 'trellix_epo'
    assert 'By trellix\\_epo on' in fw_policy.to_markdown()
