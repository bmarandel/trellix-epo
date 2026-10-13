"""
ENS Threat Prevention Access Protection.

- ap_policy.xml: the lab ePO 5.10 policy "Standard Policy ON - V1.01" (32
  Trellix-defined rules, 23 user-defined rules, 3 exclusions). Rule names,
  order, subrule types, operations and target labels checked in the console.
- ap_policy_rules.xml: a copy of "My Default" where the console was used to
  create one rule of each kind (a Windows rule with executables, user names
  and a subrule of each type, a Linux rule), change a Trellix-defined rule
  and add an exclusion - the reference of the storage format.

A policy built with the library (same objects as below) was also imported
into ePO, displayed as expected in the console and exported back unchanged.
"""

import re
from pathlib import Path

import pytest

from mcafee_epo_policies import (ESTPPolicyAccessProtection, APRule, APSubRule,
                                 APTarget, APExecutable, APUserName)

FIXTURES = Path(__file__).parent / 'fixtures'
GUID = re.compile(r'^[0-9a-f-]{36}$')


def load(name):
    policy = ESTPPolicyAccessProtection()
    policy.load_from_file(str(FIXTURES / name))
    return policy


@pytest.fixture
def ap_policy():
    return load('ap_policy.xml')


@pytest.fixture
def rules_policy():
    return load('ap_policy_rules.xml')


def console_rule():
    """
    The rule created in the console (ap_policy_rules.xml), built with the API.
    """
    rule = APRule('Claude AP Test Rule', block=True, report=True, notes='Claude test notes')
    rule.add_executable(APExecutable('Claude Exe Include', path='**\\claudeinc.exe',
                                     md5='0123456789ABCDEF0123456789ABCDEF',
                                     signer='CN=CLAUDE TEST SIGNER, O=CLAUDE TEST, C=US',
                                     notes='Exe include notes'))
    rule.add_executable(APExecutable('Claude Exe Exclude', signer=APExecutable.ANY_SIGNATURE,
                                     inclusion='exclude'))
    rule.add_user_name(APUserName('Local\\System', inclusion='exclude'))
    rule.add_user_name(APUserName('CLAUDETEST\\user1'))
    rule.add_subrule(APSubRule('Claude Sub Value', APSubRule.REGISTRY_VALUE, ['write', 'read'],
                               targets=[APTarget('HKLM\\SOFTWARE\\ClaudeTest\\Value1',
                                                 inclusion='exclude')]))
    rule.add_subrule(APSubRule('Claude Sub Rename', APSubRule.FILES, ['rename'],
                               targets=[APTarget('C:\\ClaudeSrc\\*.doc'),
                                        APTarget('*.claudelocked', APTarget.DESTINATION_FILE)]))
    process = APSubRule('Claude Sub Process', APSubRule.PROCESSES,
                        ['ex_proc_open_terminate', 'ex_proc_run_target'])
    process.add_executable(APExecutable('Claude Target Exe', path='claudetarget.exe',
                                        notes='Target exe notes'))
    rule.add_subrule(process)
    rule.add_subrule(APSubRule('Claude Sub Key', APSubRule.REGISTRY_KEY,
                               ['write', 'delete', 'restore_key', 'set_security'],
                               targets=[APTarget('HKLM\\SOFTWARE\\ClaudeTest\\**')]))
    rule.add_subrule(APSubRule('Claude Sub Files', APSubRule.FILES,
                               ['create', 'rename', 'write_attribute'],
                               targets=[APTarget('*.claudetest'),
                                        APTarget('C:\\ClaudeExcl\\**', inclusion='exclude'),
                                        APTarget(APTarget.DRIVE_REMOVABLE, APTarget.DRIVE_TYPE)]))
    rule.add_subrule(APSubRule('Claude Sub Service', APSubRule.SERVICES,
                               ['srv_stop', 'srv_delete', 'srv_startup'],
                               targets=[APTarget('ClaudeSvc', APTarget.SERVICE_NAME),
                                        APTarget('Claude Test Service',
                                                 APTarget.SERVICE_DISPLAY_NAME,
                                                 inclusion='exclude')]))
    return rule


def without_ids(values):
    return {name: '<id>' if GUID.match(value or '') else value for name, value in values.items()}


# ------------------------------------------------------------------- read
def test_rules(ap_policy):
    assert ap_policy.access_protection == '1'
    rules = ap_policy.get_rules()
    assert len(rules) == 55
    assert [rule.origin for rule in rules].count(APRule.USER) == 23
    # Console order: User-defined first, then by name (case-insensitive).
    assert rules[0].name == "Autoprotection améliorée - Empêcher l'arrêt des processus " \
        "McAfee (KB88263)"
    assert rules[23].name == 'Altering user rights policies'
    assert rules[-1].name == 'Unauthorized execution of EsConfigTool'
    linux = [rule.name for rule in rules if rule.os == 'LINUX']
    assert len(linux) == 7
    assert 'Modify or remove the "passwd" or "shadow" files by a process other than passwd' in linux
    lockbit = ap_policy.get_rule('LockBit 2.0')
    assert lockbit.notes == 'LockBit 2.0 ransomware'
    assert [(sub.type, sub.operations) for sub in lockbit.subrules] == [
        ('VALUE', ['create']), ('FILE', ['create']), ('KEY', ['create'])]
    assert (lockbit.subrules[1].targets[0].name, lockbit.subrules[1].targets[0].value) == \
        ('OBJECT_NAME', '*.lockbit')
    assert ap_policy.get_rule('PREVENT_MIMIKATZ_CREATION').name == 'Executing Mimikatz malware'
    assert ap_policy.get_rule('unknown') is None


def test_exclusions(ap_policy):
    exclusions = ap_policy.get_exclusions()
    assert [exe.name for exe in exclusions] == [
        'Yara32.exe', 'Yara32.exe V 4.5.2', 'Client_Edrf_Exclusion_Access_Protection']
    assert (exclusions[1].path, exclusions[1].md5, exclusions[1].inclusion) == \
        ('**\\yara32.exe', '197A9A2A8CFA2E479D8BD5A66E35F530', 'exclude')
    assert exclusions[2].signer == 'C=US, S=CALIFORNIA, O=MUSARUBRA US LLC, CN=MUSARUBRA US LLC'


def test_read_console_rules(rules_policy):
    rule = rules_policy.get_rule('Claude AP Test Rule')
    assert rule.section_name() == 'APRule102'
    assert [user.name for user in rule.user_names] == ['Local\\System', 'CLAUDETEST\\user1']
    assert rule.executables[1].signer == APExecutable.ANY_SIGNATURE
    assert [(sub.type, sub.get_kind()) for sub in rule.subrules] == [
        ('VALUE', 'SubRule'), ('FILE', 'SubRule102'), ('PROCESS', 'SubRule102'),
        ('KEY', 'SubRule102'), ('FILE', 'SubRule102'), ('SERVICE', 'SubRule105')]
    linux = rules_policy.get_rule('Claude Linux Rule')
    assert (linux.os, linux.section_name(), linux.subrules[0].operations) == \
        ('LINUX', 'APLinuxRule', ['chown', 'hardlink', 'write'])
    canned = rules_policy.get_rule('ALTER_USERRIGHTPOLICY')
    assert (canned.block, canned.report, canned.notes) == (True, False, 'Claude canned notes')
    assert canned.executables[0].path == 'claudecanned.exe'


# ------------------------------------------------------------------- write
@pytest.mark.parametrize('fixture', ['ap_policy.xml', 'ap_policy_rules.xml'])
def test_lossless(fixture):
    # Every rule read then written back gives exactly the ePO settings.
    policy = load(fixture)
    for settings in policy.root.findall('EPOPolicySettings'):
        section = settings.find('Section')
        if section.get('name') in ['APRule', 'APRule102', 'APLinuxRule']:
            rule = APRule.from_section(section, policy.RULE_NAMES)
            assert rule.to_values() == {s.get('name'): s.get('value') for s in section}
            assert rule.section_name() == section.get('name')


def test_build_like_console(rules_policy):
    # The API builds the same settings as the console (IDs aside).
    built, stored = console_rule(), rules_policy.get_rule('Claude AP Test Rule')
    assert built.section_name() == stored.section_name() == 'APRule102'
    assert without_ids(built.to_values()) == without_ids(stored.to_values())


def test_add_update_remove(ap_policy):
    count = len(ap_policy.get_rules())
    rule = console_rule()
    ap_policy.add_rule(rule)
    assert len(ap_policy.get_rules()) == count + 1
    reference = ap_policy.root.find('EPOPolicyObject')[-1].text
    assert reference.startswith('AccessProtectionSettings_Rule_{} ('.format(rule.id))
    assert ap_policy.root.find('./EPOPolicySettings[@name="{}"]'.format(reference)) is not None
    with pytest.raises(ValueError):
        ap_policy.add_rule(rule)
    saved = ap_policy.get_rule(rule.id)
    assert without_ids(saved.to_values()) == without_ids(rule.to_values())
    saved.block = False
    saved.subrules.pop()
    assert ap_policy.update_rule(saved)
    saved = ap_policy.get_rule(rule.id)
    assert (saved.block, len(saved.subrules)) == (False, 5)
    assert ap_policy.remove_rule(rule.id)
    assert ap_policy.get_rule(rule.id) is None
    assert len(ap_policy.get_rules()) == count
    with pytest.raises(ValueError):
        ap_policy.remove_rule('PREVENT_MIMIKATZ_CREATION')


def test_new_policy_round_trip(rules_policy, tmp_path):
    # The fixture holds the console-saved rule: the console refuses a second rule
    # with the same name, so the copy is added after removing it.
    rules_policy.remove_rule(rules_policy.get_rule('Claude AP Test Rule').id)
    rules_policy.add_rule(console_rule())
    linux = APRule('Linux', report=True, linux=True)
    linux.add_executable(APExecutable('Linux exe', path='/usr/bin/tool'))
    linux.add_subrule(APSubRule('Linux files', APSubRule.FILES, ['symlink'], linux=True,
                                targets=[APTarget('/etc/tool/**')]))
    rules_policy.add_rule(linux)
    rules_policy.save_to_file(str(tmp_path / 'ap.xml'))
    reloaded = ESTPPolicyAccessProtection()
    reloaded.load_from_file(str(tmp_path / 'ap.xml'))
    assert len([rule for rule in reloaded.get_rules() if rule.name == 'Claude AP Test Rule']) == 1
    with pytest.raises(ValueError):
        reloaded.add_rule(console_rule())                     # same name, refused as in the console
    stored = reloaded.get_rule('Linux')
    # Linux executables only have a file name or path.
    values = stored.to_values()
    assert values['Executable#0_ParameterCount'] == '1'
    assert values['SubRuleCount'] == '1' and 'SubRule102Count' not in values


def test_trellix_rule(ap_policy):
    rule = ap_policy.get_rule('ALTER_USERRIGHTPOLICY')
    with pytest.raises(ValueError):
        rule.add_user_name(APUserName('DOMAIN\\user'))
    with pytest.raises(ValueError):
        rule.add_subrule(APSubRule('x', APSubRule.FILES, ['read'], targets=[APTarget('a')]))
    rule.add_executable(APExecutable('Tool', path='tool.exe'))
    rule.notes = 'Changed'
    assert ap_policy.update_rule(rule)
    rule = ap_policy.get_rule('ALTER_USERRIGHTPOLICY')
    assert (rule.notes, rule.executables[-1].path, rule.name) == \
        ('Changed', 'tool.exe', 'Altering user rights policies')
    values = rule.to_values()
    assert values['RuleName'] == 'IDS_AP_RULE_ALTER_USERRIGHTPOLICY'
    assert values['RuleType'] == 'Canned'


def test_set_actions_and_legacy_mask(ap_policy):
    # The console keeps the Block/Report mask of the legacy "APRules"
    # section in sync (1 = Block, 2 = Report).
    assert ap_policy.set_rule_block('ALTER_USERRIGHTPOLICY', '1')
    assert ap_policy.set_rule_report('ALTER_USERRIGHTPOLICY', '1')
    assert ap_policy.get_setting_value('APRules', 'Rule_1') == 'ALTER_USERRIGHTPOLICY|3|'
    assert ap_policy.set_rule_report('ALTER_USERRIGHTPOLICY', '0')
    assert ap_policy.get_setting_value('APRules', 'Rule_1') == 'ALTER_USERRIGHTPOLICY|1|'
    rule = ap_policy.get_rule('ALTER_USERRIGHTPOLICY')
    assert (rule.block, rule.report, rule.is_enabled()) == (True, False, True)
    assert not ap_policy.set_rule_block('UNKNOWN_RULE', '1')
    ap_policy.access_protection = '0'
    assert ap_policy.access_protection == '0'


def test_set_exclusions(ap_policy):
    exclusions = ap_policy.get_exclusions()[:1]
    assert ap_policy.add_exclusion(APExecutable('New', path='C:\\Tools\\new.exe',
                                                inclusion='include')) is True
    assert [exe.inclusion for exe in ap_policy.get_exclusions()] == ['exclude'] * 4
    ap_policy.set_exclusions(exclusions)
    assert ap_policy.get_setting_value('BehaviorBlockAP', 'szGlobalExcludedProcesses') == \
        'C:\\Windows\\Temp\\dispatcher-*\\tmp\\working\\yara\\archive\\yara32.exe'
    assert ap_policy.get_setting_value('BehaviorBlockAP', 'ExecutableCount') == '1'


def test_validation():
    with pytest.raises(ValueError):
        APExecutable('No path')
    with pytest.raises(ValueError):
        APExecutable('x', path='a', inclusion='maybe')
    with pytest.raises(ValueError):
        APSubRule('x', APSubRule.FILES, [])
    with pytest.raises(ValueError):
        APSubRule('x', APSubRule.FILES, ['enum'])
    with pytest.raises(ValueError):
        APSubRule('x', APSubRule.SERVICES, ['srv_stop'], linux=True)
    with pytest.raises(ValueError):
        APSubRule('x', APSubRule.FILES, ['hardlink'])
    with pytest.raises(ValueError):
        APSubRule('x', APSubRule.FILES, ['read', 'rename'],
                  targets=[APTarget('*.x', APTarget.DESTINATION_FILE)])
    with pytest.raises(ValueError):
        APSubRule('x', APSubRule.REGISTRY_KEY, ['read'],
                  targets=[APTarget(APTarget.DRIVE_FIXED, APTarget.DRIVE_TYPE)])
    with pytest.raises(ValueError):
        APSubRule('x', APSubRule.FILES, ['read']).add_executable(APExecutable('e', path='e'))
    rule = APRule('Empty')
    policy = load('ap_policy_rules.xml')
    with pytest.raises(ValueError):
        policy.add_rule(rule)
    rule.add_subrule(APSubRule('No target', APSubRule.FILES, ['read']))
    with pytest.raises(ValueError):
        policy.add_rule(rule)
    with pytest.raises(ValueError):
        rule.add_subrule(APSubRule('Linux', APSubRule.FILES, ['read'], linux=True))


def test_subrule_kind():
    assert APSubRule('x', APSubRule.FILES, ['create', 'write'],
                     targets=[APTarget('a')]).get_kind() == 'SubRule'
    assert APSubRule('x', APSubRule.FILES, ['execute'],
                     targets=[APTarget(APTarget.DRIVE_NETWORK, APTarget.DRIVE_TYPE)]).get_kind() == \
        'SubRule102'
    assert APSubRule('x', APSubRule.PROCESSES, ['ex_proc_open_any']).get_kind() == 'SubRule102'
    assert APSubRule('x', APSubRule.SERVICES, ['srv_stop']).get_kind() == 'SubRule105'
    assert APRule('x').section_name() == 'APRule'


# ------------------------------------------------------------------- markdown
def test_markdown(ap_policy):
    text = ap_policy.to_markdown()
    headings = [line for line in text.splitlines() if line.startswith('## ')]
    assert headings == ['## Contents', '## 1. Access Protection', '## 2. Exclusions',
                        '## 3. Rules', '## 4. Rule details', '## 5. Document control']
    assert '| Enable Access Protection | Yes |' in text
    assert '| 2 | Yara32.exe V 4.5.2 | \\*\\*\\\\yara32.exe | 197A9A2A8CFA2E479D8BD5A66E35F530 |' \
        in text
    assert 'Deselecting both Block and Report will disable the Rule.' in text
    assert '| 14 | Yes | Yes | LockBit 2.0 | LockBit 2.0 ransomware | User-defined | WINDOWS |' \
        in text
    assert '### 14. LockBit 2.0\n' in text
    assert '| Subrule type | Registry value |' in text
    assert '| 1 | Include | File, folder name, or file path | \\*.lockbit |' in text
    assert '| 1 | Include | Registry key path | HKEY\\_CURRENT\\_USER' in text
    assert '| Subrule type | Processes |\n| Operations | Any access |' in text


def test_markdown_console_rule(rules_policy):
    text = rules_policy.to_markdown()
    assert '| 1 | Local\\\\System | Exclude |' in text
    assert '| 2 | Claude Exe Exclude |  |  | Any | Exclude |  |' in text
    assert '| 3 | Include | Drive type | Removable |' in text
    assert '| 2 | Include | Destination file | \\*.claudelocked |' in text
    assert '| 2 | Exclude | Service display name | Claude Test Service |' in text
    assert '| Operations | Change owner, Hard Link, Write |' in text


# ------------------------------ Values accepted by the console ------------------------------
# Cases run on the lab (Threat Prevention 26.8.0.16045): the signer check of the ePO server
# (ExecutableValidateSignerName.do) and the dialog scripts (VSECommon_CustomForAP.js,
# EditSubruleParameter.jsp, EditUserName.jsp).
from mcafee_epo_policies.validators import (is_x500_name, is_ens_executable_path,
                                            is_ens_parameter_path, ENS_USER_NAME)

SIGNERS = [('CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US', True),
           ('CN=Microsoft Corporation', True), ('Microsoft Corporation', False), ('CN=', True),
           ('CN=a, X=b', False), ('CN="Quoted, Inc", O=Q', True), ('cn=lower', True),
           ('CN=a; O=b', True), ('CN=a, O=b\\, c', True), ('CN=a,', False), ('2.5.4.3=x', True),
           ('CN=a+OU=b', True), ('OID.2.5.4.3=x', True), ('CN=a,,O=b', False), ('CN=a=b', True)]
EXECUTABLE_PATHS = [('C:\\Tools\\app.exe', True), ('app.exe', True), ('*\\app.exe', False),
                    ('**\\Tools\\app.exe', True), ('\\\\server\\share\\a.exe', True),
                    ('?:\\x\\*.exe', True), ('C:\\\\Tools\\a.exe', False), ('C:/Tools/a.exe', False),
                    ('Tools\\app.exe', False), ('a<b.exe', False), ('C:', True)]
PARAMETER_PATHS = [('C:\\Data\\*', True), ('**\\secret.txt', True), ('*\\x.txt', False),
                   ('%windir%\\x', True), ('a?.txt', True), ('C:/x', False), ('x|y', False),
                   ('\\\\srv\\share\\', True)]
USER_NAMES = [('LAB\\jdoe', True), ('Local\\System', True), ('lab.example.com\\svc', True),
              ('jdoe', False), ('LAB\\j:doe', False), ('-LAB\\x', False), ('LAB\\', False),
              ('LAB x\\y', True)]


def test_console_validators():
    for function, cases in [(is_x500_name, SIGNERS), (is_ens_executable_path, EXECUTABLE_PATHS),
                            (is_ens_parameter_path, PARAMETER_PATHS),
                            (lambda value: ENS_USER_NAME.match(value), USER_NAMES)]:
        for value, valid in cases:
            assert bool(function(value)) is valid, value


def test_console_values(ap_policy):
    rule = APRule('R' * 128, report=True, notes='N' * 256)
    rule.add_executable(APExecutable('E' * 256, path='**\\Tools\\app.exe',
                                     md5='44D88612FEA8A8F36DE82E1278ABB02F',
                                     signer='CN=Example, O=Example, C=US', notes='n' * 256))
    rule.add_user_name(APUserName('LAB\\svc_backup'))
    rule.add_subrule(APSubRule('S' * 100, APSubRule.FILES, ['read'],
                               targets=[APTarget('C:\\' + 'd' * 253),
                                        APTarget(APTarget.DRIVE_NETWORK, APTarget.DRIVE_TYPE)]))
    rule.add_subrule(APSubRule('Key', APSubRule.REGISTRY_KEY, ['write'],
                               targets=[APTarget('HKLM\\' + 'k' * 250)]))
    ap_policy.add_rule(rule)

    def files(saved):
        return [subrule for subrule in saved.subrules if subrule.type == APSubRule.FILES][0]

    def key(saved):
        return [subrule for subrule in saved.subrules if subrule.type == APSubRule.REGISTRY_KEY][0]
    bad = [lambda r: setattr(r, 'name', 'R' * 129), lambda r: setattr(r, 'notes', 'N' * 257),
           lambda r: r.executables.append(APExecutable('e' * 256, path='x.exe')),   # duplicate
           lambda r: setattr(r.executables[0], 'md5', 'XYZ'),
           lambda r: setattr(r.executables[0], 'signer', 'Example Corp'),
           lambda r: setattr(r.executables[0], 'path', 'Tools\\app.exe'),
           lambda r: r.user_names.append(APUserName('svc_backup')),
           lambda r: setattr(files(r), 'name', 'S' * 101),
           lambda r: files(r).targets.append(APTarget('C:\\' + 'd' * 254)),
           lambda r: files(r).targets.append(APTarget('*\\x.txt')),
           lambda r: key(r).targets.append(APTarget('HKLM\\' + 'k' * 251))]
    # The subrules are read back sorted (registry first): pick them by type.
    for change in bad:
        saved = ap_policy.get_rule(rule.id)
        change(saved)
        with pytest.raises(ValueError):
            ap_policy.update_rule(saved)
    copy = APRule(' r' * 64, report=True)            # same name, case and spaces ignored
    copy.name = ('R' * 128).lower() + ' '
    copy.add_subrule(APSubRule('S', APSubRule.FILES, ['read'], targets=[APTarget('a.txt')]))
    with pytest.raises(ValueError):
        ap_policy.add_rule(copy)
    with pytest.raises(ValueError):
        ap_policy.set_exclusions([APExecutable('X', path='a.exe'), APExecutable(' x ', path='b.exe')])
