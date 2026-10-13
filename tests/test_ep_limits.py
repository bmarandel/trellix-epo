"""
ENS Threat Prevention Exploit Prevention: values accepted by the console
(Threat Prevention 26.8, checked on the lab).

The lengths come from the dialogs (maxlength), the patterns from their
scripts (EditXPExclusion.jsp, XPExclusion.js, EditAppProtectionExecutable.jsp,
EditExpertRule.jsp); the IP list cases were run through the console code
(validateArgumentIPList) with the same results.

ep_limits.xml: "Claude - ENS EP Test", written by the library with the
exclusions below (every one opened valid in the console), a user-defined
Application Protection Rule (name of 260 characters, executable name of
256), then saved in the console with an Expert Rule "Claude Long Rule" of
4688 characters (Base64 content split by the server in settings of 3072
characters). Only the signatures used by the exclusions are kept.
"""

import copy
from pathlib import Path

import pytest

from mcafee_epo_policies import (ESTPPolicyExploitPrevention, EPExclusion, EPExecutable,
                                 EPAppRule, APExecutable)
from mcafee_epo_policies.validators import is_ep_ip_list, is_ep_file_paths, is_linux_path

FIXTURE = Path(__file__).parent / 'fixtures' / 'ep_limits.xml'
LONG_RULE_LINES = ['\t\tInclude OBJECT_NAME { -v "C:\\\\ClaudeLongRuleTest\\\\folder' +
                   '{:03d}'.format(index) + '\\\\file.txt" }' for index in range(60)]
LONG_RULE = ('Rule {\r\n\tProcess {\r\n\t\tInclude OBJECT_NAME { -v cmd.exe }\r\n\t}\r\n'
             '\tTarget {\r\n\t\tMatch FILE {\r\n' + '\r\n'.join(LONG_RULE_LINES) +
             '\r\n\t\t\tInclude -access "CREATE"\r\n\t\t}\r\n\t}\r\n}')


@pytest.fixture(scope='module')
def loaded():
    policy = ESTPPolicyExploitPrevention()
    policy.load_from_file(str(FIXTURE))
    return policy


@pytest.fixture
def policy(loaded):
    return copy.deepcopy(loaded)


def test_console_policy(policy):
    exclusions = policy.get_exclusions()
    assert len(exclusions) == 8
    for exclusion in exclusions:
        exclusion.check()
    longest = [exclusion for exclusion in exclusions if exclusion.name == 'N' * 256][0]
    assert len(longest.processes) == 10
    rule = policy.get_application_rule('R' * 260)
    rule.check()
    assert len(rule.executables[0].name) == 256
    assert policy.nips_block_time == 9999


def test_long_expert_rule(policy, tmp_path):
    sig_id = [sig['SignatureID'] for sig in policy.eprules.values()
              if sig['SignatureName'] == 'Claude Long Rule'][0]
    assert policy.signatures_get(sig_id)['rule'] == LONG_RULE
    policy.signatures_add('Claude Long Rule 2', '3', '1', '1', 'Files', LONG_RULE)
    added = [key for key, sig in policy.eprules.items()
             if sig['SignatureName'] == 'Claude Long Rule 2'][0]
    console = [key for key, sig in policy.eprules.items()
               if sig['SignatureName'] == 'Claude Long Rule'][0]
    for setting in ['SignatureContent#0001', 'SignatureContent#0002', 'SignatureContent#0003',
                    'SignatureNodeCount']:
        assert policy.eprules[added][setting] == policy.eprules[console][setting], setting
    path = tmp_path / 'ep.xml'
    policy.save_to_file(str(path))
    reloaded = ESTPPolicyExploitPrevention()
    reloaded.load_from_file(str(path))
    new_id = policy.eprules[added]['SignatureID']
    assert reloaded.signatures_get(new_id)['rule'] == LONG_RULE


def test_expert_rule_checks(policy):
    policy.signatures_add('Règle (test): a_b-c.d/e \'f\'', '1', '0', '1', 'Files', 'Rule {}')
    policy.signatures_add('N' * 260, '4', '0', '1', 'Files', 'Rule {}', notes='n' * 256)
    for args in [('N' * 261, '4'), ('Rule;1', '4'), ('rule€', '4'), ('rule[1]', '4'),
                 ('  ', '4'), ('Claude long rule ', '4'),     # duplicate, case ignored
                 ('Severity', '0')]:
        with pytest.raises(ValueError):
            policy.signatures_add(args[0], args[1], '0', '1', 'Files', 'Rule {}')
    with pytest.raises(ValueError):
        policy.signatures_add('No content', '4', '0', '1', 'Files', ' \r\n')
    with pytest.raises(ValueError):
        policy.signatures_add('Long notes', '4', '0', '1', 'Files', 'Rule {}', notes='n' * 257)


# Results of validateArgumentIPList on the lab page (the console compares
# the ends of an IPv4 range as strings and stops checking at the first CIDR).
IP_LISTS = [('10.0.0.1', True), (' 10.0.0.1 , 10.0.0.2 ', True), ('10.0.0.9-10.0.0.10', False),
            ('10.0.0.1-10.0.0.9', True), ('192.168.1.1-192.168.1.16', True),
            ('10.0.0.0/8', True), ('10.0.0.0/33', False), ('10.0.0.0/0', False),
            ('2001:db8::/129', False), ('2001:db8::/64', True), ('fd00:::1', False),
            ('::ffff:10.0.0.1', True), ('2001-2003:0db8::1428-1434:57ab', True),
            ('2001:db8::1-2001:db8::5', False), ('2-1:db8::1', False), ('10.0.0.256', False),
            ('0010.0.0.1', False), ('host', False), ('', True), ('fe80::1%eth0', False),
            ('10.0.0.0/8, bogus', False), ('1.1.1.1,' * 383 + '1.1.1.1', True),
            ('1.1.1.1,' * 384 + '1.1.1.1', False)]


def test_ip_lists():
    for value, valid in IP_LISTS:
        assert is_ep_ip_list(value) == valid, value


# IsValidPath of VSECommon.js only refuses / * ? " | < >: C:\a\\b.exe passes.
FILE_PATHS = [('C:\\a\\b.txt,%TEMP%\\x.dll,data.bin', True), ('**\\c.exe', True),
              ('*\\c.exe', False), ('C:\\a\\\\b.exe', True), ('C:\\a\\b?.exe', True),
              ('a.exe,b|c.exe', False), ('C:/a/b.exe', False), ('?:\\a\\*.exe', True),
              ('cmd.exe', True)]


def test_file_paths():
    for value, valid in FILE_PATHS:
        assert is_ep_file_paths(value) == valid, value
    assert is_linux_path('/opt/a/*') and not is_linux_path('//opt/a') and \
        not is_linux_path('/opt\\a')


def test_exclusion_checks():
    process = [EPExecutable('a.exe')]
    EPExclusion.file_process_registry('x', process, user_name='CORP.LOCAL\\j doe',
                                      group_name='Domain Users', hostname='web-*.corp?')
    EPExclusion.file_process_registry('x', process, user_sid='S-1-5-21-1-2-3-500',
                                      group_sid='S-1-5-32-544')
    EPExclusion.file_process_registry('x', target_registry='HKCU\\Software\\{x} [1]*')
    for kwargs in [dict(user_name='a\\b\\c'), dict(user_name='j;doe'), dict(group_name='a@b'),
                   dict(hostname='a_b'), dict(user_sid='S-1-5'), dict(group_sid='s-1-5-32-544'),
                   dict(user_sid='S-1-5-21-1\n')]:
        with pytest.raises(ValueError):
            EPExclusion.file_process_registry('x', process, **kwargs)
    for kwargs in [dict(target_registry='HKEY_LOCAL\\x'), dict(target_registry='HKLM\\a"b'),
                   dict(target_file='*\\a.txt'), dict(target_file='a' * 257)]:
        with pytest.raises(ValueError):
            EPExclusion.file_process_registry('x', **kwargs)
    with pytest.raises(ValueError):                         # the name is required
        EPExclusion.file_process_registry('', target_file='a.txt')
    with pytest.raises(ValueError):                         # 10 processes max
        EPExclusion.file_process_registry('x', [EPExecutable('a.exe')] * 11)
    for executable in [EPExecutable('a.exe', md5='0' * 31), EPExecutable('a.exe', signer='x'),
                       EPExecutable('a.exe', signer='CN=' + 'a' * 1022)]:
        with pytest.raises(ValueError):
            EPExclusion.file_process_registry('x', [executable])
    EPExclusion.illegal_api('x', process, EPExecutable('%windir%\\x.dll', name='m'))
    with pytest.raises(ValueError):                         # isValidPath: no partial path
        EPExclusion.illegal_api('x', process, EPExecutable('dir\\x.dll', name='m'))
    with pytest.raises(ValueError):
        EPExclusion.linux('x', '/opt\\a')
    for kwargs in [dict(ip_addresses='10.0.0.9-10.0.0.10'), dict(signatures=['1a'])]:
        with pytest.raises(ValueError):
            EPExclusion.network_ips(**kwargs)
    for value in ['s' * 257, '']:
        with pytest.raises(ValueError):
            EPExclusion.service(value)
    with pytest.raises(ValueError):
        EPExclusion.service('svc', notes='n' * 257)


def test_application_rule_checks(policy):
    def rule(name='Claude Rule', notes='', **exe):
        return EPAppRule(name, [APExecutable(exe.pop('exe_name', 'Claude Exe'),
                                             **(exe or {'path': 'a.exe'}))], notes=notes)
    policy.add_application_rule(rule(path='?:\\Apps\\*.exe'))
    for bad in [rule('R' * 261), rule(notes='n' * 261), rule(exe_name='E' * 257),
                rule(path='%TEMP%\\a.exe'), rule(path='dir\\a.exe'), rule(md5='0' * 33),
                rule(signer='not a dn'), rule('claude rule ')]:
        with pytest.raises(ValueError):
            policy.add_application_rule(bad)
    duplicate = rule()
    duplicate.executables.append(APExecutable('claude exe', md5='a' * 32))
    with pytest.raises(ValueError):
        duplicate.check()
    # A Trellix-defined rule keeps its executables (without name) but a new
    # one is checked.
    trellix = policy.get_application_rule('.Net Framework Host')
    trellix.enabled = False
    assert policy.update_application_rule(trellix)
    trellix.executables.append(APExecutable('Claude Exe', path='dir\\a.exe'))
    with pytest.raises(ValueError):
        policy.update_application_rule(trellix)
