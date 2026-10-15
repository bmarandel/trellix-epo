"""
Tests for SCGENPolicyExceptionRules (Solidcore General > Exception Rules), using
two real ePO exports, both duplicated from "Trellix Default" in the ePO console:
  - sc_gen_exceptions_win.xml: 4 exclusions added (write-protection path,
    volume Z:, CASP for claudetest.exe, DLL Relocation for claudetest.dll);
  - sc_gen_exceptions_unix.xml: the 4 default LinuxShield exclusions, plus
    /opt/claudetest excluded from the allow list.
"""

import xml.etree.ElementTree as et
from pathlib import Path

import pytest

from trellix_epo import SCGENPolicyExceptionRules, SCException as exc

FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.fixture
def win_policy():
    return SCGENPolicyExceptionRules(et.parse(str(FIXTURES / 'sc_gen_exceptions_win.xml')).getroot())


@pytest.fixture
def unix_policy():
    return SCGENPolicyExceptionRules(et.parse(str(FIXTURES / 'sc_gen_exceptions_unix.xml')).getroot())


def test_metadata(win_policy, unix_policy):
    assert win_policy.get_type() == 'Attr Rules (Windows)'
    assert unix_policy.get_type() == 'Attr Rules (Unix)'
    assert not win_policy.is_unix()
    assert unix_policy.is_unix()
    # Own rules flagged readOnly="true" must not be taken for a shared Rule Group.
    assert win_policy.get_rule_groups()[0]['group_name'] == 'Attributes'
    assert win_policy.get_rule_group_names() == []


def test_windows_exception_list(win_policy):
    assert win_policy.get_exclusion_list() == [
        {'exclusion': exc.EXCLUDE_WRITE_PROTECTION, 'name': '\\ClaudeTest\\wp'},
        {'exclusion': exc.EXCLUDE_VOLUME, 'name': 'Z:'},
        {'exclusion': exc.CASP, 'name': 'claudetest.exe'},
        {'exclusion': exc.VASR_DLL_RELOCATION, 'name': 'claudetest.dll'},
    ]
    assert win_policy.contains_exclusion(exc.CASP, 'claudetest.exe')
    assert not win_policy.contains_exclusion(exc.NX, 'claudetest.exe')


def test_unix_exception_list(unix_policy):
    exceptions = unix_policy.get_exclusion_list()
    assert {'exclusion': exc.EXCLUDE_ALLOW_LIST, 'name': '/opt/claudetest'} in exceptions
    assert {'exclusion': exc.PROCESS_CONTEXT,
            'name': '/opt/NAI/LinuxShield/libexec/nailsd'} in exceptions
    assert len(exceptions) == 5


def test_add_windows_exception_like_the_console(win_policy):
    assert win_policy.add_exclusion(exc.NX, 'other.exe')
    assert not win_policy.add_exclusion(exc.NX, 'other.exe')
    rule = win_policy.get_rule('attr', {'file': 'other.exe'})
    # Same settings as the CASP rule created by the console, NX flag instead.
    reference = win_policy.get_rule('attr', {'file': 'claudetest.exe'})
    assert sorted(rule) == sorted(reference)
    assert rule['dep_bypass'] == 'true' and rule['casp_bypass'] == 'false'

    assert win_policy.add_exclusion(exc.IGNORE_FILE_OPERATIONS, 'C:\\Temp')
    rule = win_policy.get_rule('skiplist', {'path': 'C:\\Temp'})
    reference = win_policy.get_rule('skiplist', {'path': 'Z:'})
    assert sorted(rule) == sorted(reference)


def test_add_unix_exception(unix_policy):
    with pytest.raises(ValueError):
        unix_policy.add_exclusion(exc.CASP, '/usr/bin/foo')
    assert unix_policy.add_exclusion(exc.EXCLUDE_ALLOW_LIST, '/opt/other')
    assert unix_policy.get_rule('skiplist', {'path': '/opt/other'}) == {
        'path': '/opt/other', 'skipSolidification': 'true', 'type': 'skiplist'}
    assert unix_policy.add_exclusion(exc.PROCESS_CONTEXT, '/usr/bin/foo')
    reference = unix_policy.get_rule('attr', {'file': '/opt/NAI/LinuxShield/libexec/ods'})
    assert sorted(unix_policy.get_rule('attr', {'file': '/usr/bin/foo'})) == sorted(reference)


def test_remove_exclusion(win_policy):
    win_policy.add_exclusion(exc.NX, 'claudetest.exe')
    # Two rules now exist for claudetest.exe (CASP and NX): removing NX keeps CASP.
    assert win_policy.remove_exclusion(exc.NX, 'claudetest.exe')
    assert win_policy.contains_exclusion(exc.CASP, 'claudetest.exe')
    assert len(win_policy.get_rules('attr', {'file': 'claudetest.exe'})) == 1
    assert win_policy.remove_exclusion(exc.CASP, 'claudetest.exe')
    assert win_policy.get_rules('attr', {'file': 'claudetest.exe'}) == []
    assert not win_policy.remove_exclusion(exc.CASP, 'claudetest.exe')
    assert len(win_policy.get_exclusion_list()) == 3
