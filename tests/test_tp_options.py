"""
ENS Threat Prevention Options, against tp_options.xml: a copy of "My Default"
from the lab ePO 5.10 with one Detection Exclusion ("EICAR test file") and one
user-defined unwanted program ("claudetest.exe") added in the console, to
learn how those rows are stored.
"""

from pathlib import Path

import pytest

from mcafee_epo_policies import ESTPPolicyOptions

FIXTURE = Path(__file__).parent / 'fixtures' / 'tp_options.xml'


@pytest.fixture
def options_policy():
    policy = ESTPPolicyOptions()
    policy.load_from_file(str(FIXTURE))
    return policy


def test_read(options_policy):
    assert options_policy.get_name() == 'Claude - TP Options Test'
    assert options_policy.quarantine_folder == '<SYSTEM_DRIVE>\\Quarantine'
    assert options_policy.quarantine_age == 30
    assert options_policy.detection_exclusions == [['EICAR test file', 'Claude test exclusion']]
    assert options_policy.overwrite_detection_exclusions == '0'
    assert options_policy.pup_detections == [['claudetest.exe', 'Claude test PUP']]
    assert options_policy.gti_feedback == '1'
    assert options_policy.safety_pulse == '1'
    assert options_policy.amcore_reputation == '1'


def test_write(options_policy):
    options_policy.detection_exclusions = [['EICAR test file', ''], ['0123456789abcdef', 'hash']]
    options_policy.pup_detections = [['a.exe', 'Tool: A'], ['b.exe', '']]
    options_policy.quarantine_age = 60
    assert options_policy.detection_exclusions == [['EICAR test file', ''],
                                                   ['0123456789abcdef', 'hash']]
    assert options_policy.pup_detections == [['a.exe', 'Tool: A'], ['b.exe', '']]
    assert options_policy.get_setting_value('DetectionItems', 'UserDefinedDetection_0') == \
        'a.exe:Tool: A'
    assert options_policy.get_setting_value('SpyExclItems', 'dwSpywareExclCount') == '2'
    assert options_policy.quarantine_age == 60


def test_markdown(options_policy):
    text = options_policy.to_markdown()
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. Quarantine Manager (Windows & Linux only)',
                        '## 2. Detection Exclusion (Windows only)',
                        '## 3. Potentially Unwanted Program Detections (Windows only)',
                        '## 4. Proactive Data Analysis (Windows & Linux only)',
                        '## 5. Document control']
    assert '| Quarantine folder | &lt;SYSTEM\\_DRIVE&gt;\\\\Quarantine |' in text
    assert '| Specify the maximum number of days to keep quarantine data (Windows only) | ' \
        'Yes (30 days) |' in text
    assert '| 1 | EICAR test file | Claude test exclusion |' in text
    assert '| 1 | claudetest.exe | Claude test PUP |' in text
    assert '| Check AMCore Content before installation: AMCore Content Reputation ' \
        '(Windows only) | Yes |' in text


# ------------------------------ Values accepted by the console ------------------------------
# validateQuarantineFilePath of the Options page (Threat Prevention 26.8.0.16045) run on the
# lab, without prefix and with the <SYSTEM_DRIVE> prefix.
from mcafee_epo_policies.es.tp.options import check_quarantine_folder

QUARANTINE_FOLDERS = [('C:\\Quarantine', True), ('C:\\Q\\sub', True), ('**\\Q', True),
                      ('C:\\Q\\\\x', False), ('C:Q', False), ('Q', False), ('C:\\Q?', False),
                      ('C:\\a:b', False), ('/var/quarantine', True), ('?:\\Q', True), ('C:\\', True),
                      ('C:\\Q\\', True), ('<SYSTEM_DRIVE>\\Quarantine', True),
                      ('<SYSTEM_DRIVE>\\Q\\sub', True), ('<SYSTEM_DRIVE>\\Q:x', False),
                      ('<SYSTEM_DRIVE>\\Q*', False), ('<SYSTEM_DRIVE>\\', False),
                      ('<SYSTEM_DRIVE>\\  ', False), ('<SYSTEM_DRIVE>\\Q.d', True),
                      ('<SYSTEM_DRIVE>\\Q-1', True)]


def test_console_values(options_policy):
    for folder, valid in QUARANTINE_FOLDERS:
        if valid:
            check_quarantine_folder(folder)
        else:
            with pytest.raises(ValueError):
                check_quarantine_folder(folder)
    options_policy.set_quarantine_folder('<TEMP_DIR>\\' + 'Q' * 190)
    with pytest.raises(ValueError):
        options_policy.set_quarantine_folder('<TEMP_DIR>\\' + 'Q' * 191)
    for days in (0, 1, 999):
        options_policy.set_quarantine_age(days)
    for days in (-1, 1000, 'x'):
        with pytest.raises(ValueError):
            options_policy.set_quarantine_age(days)
    options_policy.set_detection_exclusions([['N' * 259, 'D' * 256]])
    for table in ([['', '']], [['N' * 260, '']], [['n', 'D' * 257]], [['x', ''], [' x ', '']]):
        with pytest.raises(ValueError):
            options_policy.set_detection_exclusions(table)
    options_policy.set_pup_detections([['remoteadmin.exe', 'Remote admin tool: blocked']])
    for table in ([['a/b.exe', '']], [['a:b.exe', '']], [['P' * 260, '']], [['p.exe', 'D' * 257]]):
        with pytest.raises(ValueError):
            options_policy.set_pup_detections(table)
