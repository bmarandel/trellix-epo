"""
ENS Adaptive Threat Protection: values accepted by the console (Adaptive
Threat Protection 26.8.0.15525, checked on the lab).

The rules come from the console pages (showGeneralPolicy.jsp and
showGeneralPolicyJS.js for the Options, EditDACExecutable.jsp and Validate.js
for the DAC exclusions) and from the server classes (GeneralPolicy,
DynamicApplicationContainmentActions); the path, hash, name and duplicate
checks were run on the lab page with the same results as below.

atp_limits.xml:
- "My Default" (Options).
- "Claude - ATP Options Console": a copy saved in the console with threat
  notifications on and a message typed with a line break and 170
  characters (the console keeps 160, the line break counts for one and is
  stored as \\n).
- "Claude - ATP Options Library" and "Claude - ATP DAC Library": copies
  written by the library at the limits (message 160 characters, timeout 1,
  sandbox 128 MB; DAC exclusions with a 256 characters name, path and
  notes, a 1024 characters signer that is not a distinguished name, a UNC
  path with an upper case hash and "Allow any signature", wildcards and a
  file name only), imported and opened valid in the console.
"""

from pathlib import Path

import pytest

from trellix_epo import ESATPPolicies, ESATPPolicyOptions, ESATPPolicyDAC, DACExclusion
from trellix_epo.validators import is_ens_executable_path

FIXTURE = Path(__file__).parent / 'fixtures' / 'atp_limits.xml'
DAC = ESATPPolicyDAC.TYPE


def load(cls, name):
    policies = ESATPPolicies()
    policies.load_from_file(str(FIXTURE))
    return cls(policies.get_policy(cls.TYPE, name))


# Results of validateExecutableFilePath (IsValidDriveLetterPath or
# IsValidFilename, wildcards allowed) on the lab page.
PATHS = [('C:\\Tools\\a.exe', True), ('?:\\a.exe', True), ('*:\\a.exe', True),
         ('**\\a.exe', True), ('\\\\srv\\share\\a.exe', True), ('a.exe', True), ('*.exe', True),
         ('C:\\Tools\\', True), ('C:\\\\a.exe', False), ('C:\\Tools\\\\a.exe', False),
         ('\\\\\\srv\\a', False), ('C:/a.exe', False), ('a/b', False), ('C:\\a"b', False),
         ('C:\\a|b', False), ('C:\\a<b', False), ('C:a.exe', True), ('C:\\a:b.exe', True),
         ('**\\\\a', False), ('%windir%\\a.exe', False), ('\\a.exe', False), (' a.exe', True),
         ('a.exe ', True), ('', False), ('C:\\', True), ('**\\', True), ('\\\\', True)]


@pytest.mark.parametrize('path,valid', PATHS)
def test_dac_path_rule(path, valid):
    assert is_ens_executable_path(path) is valid


def test_console_message():
    policy = load(ESATPPolicyOptions, 'Claude - ATP Options Console')
    message = policy.get_notifications()['message']
    assert message == 'Line one\n' + ('ABCDEFGHIJ' * 16)[:151]
    assert len(message) == 160


def test_library_copy():
    policy = load(ESATPPolicyOptions, 'Claude - ATP Options Library')
    notifications = policy.get_notifications()
    assert notifications['timeout'] == 1
    assert notifications['message'] == 'M' * 79 + '\n' + 'N' * 80
    assert policy.get_sandboxing() == {'enabled': '1', 'level': '15', 'size_limit': 128}


def test_options_limits():
    policy = load(ESATPPolicyOptions, 'My Default')
    for timeout in [1, '5', ' 3 ']:
        policy.set_notifications('1', timeout=timeout)
    assert policy.get_notifications()['timeout'] == 3
    for timeout in [0, 6, '3.0', '+3', '', 'abc']:
        with pytest.raises(ValueError):
            policy.set_notifications('1', timeout=timeout)
    for size in [1, '128', '064']:
        policy.set_sandboxing('1', size_limit=size)
    assert policy.get_sandboxing()['size_limit'] == 64
    for size in [0, 129, '64.5']:
        with pytest.raises(ValueError):
            policy.set_sandboxing('1', size_limit=size)
    # 160 characters, a Windows line break is stored as \n (one character).
    policy.set_notifications('1', message='A' * 80 + '\r\n' + 'B' * 79)
    assert policy.get_notifications()['message'] == 'A' * 80 + '\n' + 'B' * 79
    with pytest.raises(ValueError):
        policy.set_notifications('1', message='A' * 161)
    assert policy.get_notifications()['message'] == 'A' * 80 + '\n' + 'B' * 79
    # The console stores its default message as no custom message.
    policy.set_notifications('1', message=ESATPPolicyOptions.DEFAULT_MESSAGE)
    assert policy.get_option('customPromptTextEnabled') == '0'
    assert policy.get_option('customPromptText') == ''


def test_library_exclusions():
    policy = load(ESATPPolicyDAC, 'Claude - ATP DAC Library')
    exclusions = {exclusion.name: exclusion for exclusion in policy.get_exclusions()}
    assert len(exclusions) == 5
    longest = exclusions['N' * 256]
    assert (len(longest.path), longest.signer, len(longest.notes)) == (256, None, 256)
    assert len(exclusions['Any signer text'].signer) == 1024
    assert exclusions['UNC and hash'].signer == DACExclusion.ANY_SIGNATURE
    assert exclusions['UNC and hash'].notes == 'Notes \u00e9'
    for exclusion in exclusions.values():
        exclusion.check()
    policy.set_exclusions(list(exclusions.values()))


def test_exclusion_limits():
    for exclusion in [DACExclusion('N' * 256, 'a.exe'), DACExclusion('x', 'C:\\' + 'p' * 253),
                      DACExclusion('x', md5='D41D8CD98F00B204E9800998ECF8427E'),
                      DACExclusion('x', signer='Any text, not a DN' + 'z' * 1006),
                      DACExclusion('x', 'a.exe', notes='n' * 256)]:
        exclusion.check()
    for exclusion in [DACExclusion('N' * 257, 'a.exe'), DACExclusion('  ', 'a.exe'),
                      DACExclusion('x', 'C:\\' + 'p' * 254), DACExclusion('x', 'C:\\a\\\\b'),
                      DACExclusion('x', 'C:/a.exe'), DACExclusion('x', '  '),
                      DACExclusion('x', md5='d41d8cd98f00b204e9800998ecf8427'),
                      DACExclusion('x', signer='z' * 1025), DACExclusion('x', signer='  '),
                      DACExclusion('x', 'a.exe', notes='n' * 257)]:
        with pytest.raises(ValueError):
            exclusion.check()


def test_exclusion_names_unique():
    policy = load(ESATPPolicyDAC, 'Claude - ATP DAC Library')
    count = len(policy.get_exclusions())
    for name in [' wildcards ', 'WILDCARDS', 'any signer text']:
        with pytest.raises(ValueError):
            policy.add_exclusion(DACExclusion(name, 'x.exe'))
    assert len(policy.get_exclusions()) == count
    assert policy.add_exclusion(DACExclusion('Wildcards2', 'x.exe'))
