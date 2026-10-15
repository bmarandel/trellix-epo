"""
Solidcore exclusions (Exclusions tab / Exception Rules): every exclusion type
of the "Add exclusion rules" dialog of the ePO 5.10 console.

sc_exclusions_win.xml is the "Claude - SC Exclusions Test" Application Control
Rules (Windows) policy of the lab, where the 15 exclusion types were added in
the console (the other rules of the copied policy were removed):
"Allow uninstallations" and "Exclude file from write-protection rules..."
with a Parent Process Name, "Disable ROP protection ... Forced Relocation"
with a Library Name, and the paths, volume and registry path exclusions.
"""

from pathlib import Path

import pytest

from trellix_epo import SCPolicies, SCAWLPolicyRules, SCException as exc

FIXTURE = Path(__file__).parent / 'fixtures' / 'sc_exclusions_win.xml'


@pytest.fixture
def policy():
    policies = SCPolicies()
    policies.load_from_file(str(FIXTURE))
    return SCAWLPolicyRules(policies.get_policy('AWL Rules (Windows)',
                                                'Claude - SC Exclusions Test'))


def test_all_exclusion_types(policy):
    exclusions = {item['exclusion']: item for item in policy.get_exclusion_list()}
    assert set(exclusions) == set(policy.EXCLUSIONS)
    assert exclusions[exc.ALLOW_UNINSTALLATIONS] == {
        'exclusion': exc.ALLOW_UNINSTALLATIONS, 'name': 'claudesetup.exe', 'parent': 'msiexec.exe'}
    assert exclusions[exc.PROCESS_CONTEXT]['parent'] == 'explorer.exe'
    assert exclusions[exc.VASR_FORCED_RELOCATION] == {
        'exclusion': exc.VASR_FORCED_RELOCATION, 'name': 'claudevf.exe', 'library': 'claudelib.dll'}
    assert exclusions[exc.SKIP_REGISTRY]['name'] == 'HKEY_LOCAL_MACHINE\\SOFTWARE\\ClaudeTest'
    assert exclusions[exc.SKIP_CHANGE_TRACKING]['name'] == 'C:\\ClaudeTest\\Track'
    assert exclusions[exc.EXCLUDE_VOLUME]['name'] == 'D:'
    assert policy.contains_exclusion(exc.ALLOW_UNINSTALLATIONS, 'claudesetup.exe', 'msiexec.exe')
    assert not policy.contains_exclusion(exc.ALLOW_UNINSTALLATIONS, 'claudesetup.exe', 'other.exe')


def test_add_exclusions_as_the_console(policy):
    """
    The library writes the same settings as the console.
    """
    console = {(item['exclusion'], item['name']): item for item in policy.get_exclusion_list()}
    for (exclusion, name), item in console.items():
        assert policy.remove_exclusion(exclusion, name)
    assert policy.get_exclusion_list() == []
    for (exclusion, name), item in console.items():
        assert policy.add_exclusion(exclusion, name, item.get('parent'), item.get('library'))
    assert {(item['exclusion'], item['name']): item for item in policy.get_exclusion_list()} == \
        console
    rule = policy.get_rules('attr', {'file': 'claudevf.exe'})[0]
    assert (rule['module'], rule['vasr_force_reloc_bypass']) == ('claudelib.dll', 'true')
    rule = policy.get_rules('attr', {'file': 'claudesetup.exe'})[0]
    assert (rule['parent'], rule['uninstall_bypass']) == ('msiexec.exe', 'true')
    rule = policy.get_rules('skiplist', {'path': 'C:\\ClaudeTest\\Track'})[0]
    assert rule['skipChangeTracking'] == 'true'


def test_parent_and_library_checks(policy):
    with pytest.raises(ValueError):     # the console requires the parent
        policy.add_exclusion(exc.ALLOW_UNINSTALLATIONS, 'setup.exe')
    with pytest.raises(ValueError):     # no parent field for this exclusion
        policy.add_exclusion(exc.CASP, 'app.exe', parent='explorer.exe')
    with pytest.raises(ValueError):     # no library field for this exclusion
        policy.add_exclusion(exc.CASP, 'app.exe', library='lib.dll')
    assert policy.add_exclusion(exc.PROCESS_CONTEXT, 'tool.exe')     # parent optional
    assert policy.add_exclusion(exc.VASR_FORCED_RELOCATION, 'app.exe')     # library optional


def test_markdown(policy):
    text = policy.to_markdown()
    assert '| Exclusion Type | Process Name | Parent Process Name | Library Name |' in text
    assert '| Bypass uninstaller detection | claudesetup.exe | msiexec.exe |  |' in text
    assert '| Disable ROP protection (Forced Relocation VASR) | claudevf.exe |  | claudelib.dll |' \
        in text
    assert '| Skip registry protection | HKEY\\_LOCAL\\_MACHINE\\\\SOFTWARE\\\\ClaudeTest |' in text
    assert '| Skip Change Tracking | C:\\\\ClaudeTest\\\\Track |' in text
