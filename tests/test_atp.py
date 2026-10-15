"""
Endpoint Security Adaptive Threat Protection (es/atp): Options and Dynamic
Application Containment policies.

atp_policies.xml is an export of the lab ePO 5.10 (productId TIEClientMETA)
with the "My Default" policies, "Demo (Monitoring)" (Options in Observe
mode) and two test copies changed in the console:

- "Claude - ATP Options Test": Adaptive Threat Protection disabled, users
  allowed to disable it from the tray icon, sensitivity High, threat
  notifications at Might be Trusted with default action Block, 3 minutes
  and a custom message, notifications kept when the TIE server is not
  reachable, reputation source "Use only Trellix GTI", sandboxing at Most
  Likely Trusted limited to 12 MB, Story Graph off.
- "Claude - ATP DAC Test": Block on "Terminating another process" and
  "Accessing user cookie locations", "Executing any child process"
  disabled (no Block, no Report) and 3 exclusions: name + hash; name +
  path + hash + signed by + notes; name + path + any signature.
"""

from pathlib import Path

import pytest

from trellix_epo import ESATPPolicies, ESATPPolicyOptions, ESATPPolicyDAC, DACExclusion

FIXTURE = Path(__file__).parent / 'fixtures' / 'atp_policies.xml'
DAC = ESATPPolicyDAC.TYPE


def load_policies():
    policies = ESATPPolicies()
    policies.load_from_file(str(FIXTURE))
    return policies


def load(cls, name):
    return cls(load_policies().get_policy(cls.TYPE, name))


def test_policies():
    policies = load_policies()
    assert [(item['typeid'], item['name']) for item in policies.list()] == [
        ('General', 'Claude - ATP Options Test'), ('General', 'Demo (Monitoring)'),
        ('General', 'My Default'), (DAC, 'Claude - ATP DAC Test'), (DAC, 'My Default')]
    with pytest.raises(ValueError):
        ESATPPolicyOptions(policies.get_policy(DAC, 'My Default'))
    with pytest.raises(ValueError):
        ESATPPolicyDAC(policies.get_policy('General', 'My Default'))


def test_options_read():
    default = load(ESATPPolicyOptions, 'My Default')
    assert (default.operation_mode, default.atp, default.observe_mode) == ('1', '1', '0')
    assert (default.telemetry, default.network_scan, default.prevent_changes,
            default.allow_disable_from_tray) == ('1', '0', '1', '0')
    assert (default.client_scanning, default.offline_scanning, default.sensitivity_level,
            default.cloud_scanning) == ('1', '0', '1', '1')
    assert (default.script_scanning, default.script_scanning_observe) == ('1', '1')
    assert (default.credential_theft_protection,
            default.credential_theft_protection_observe) == ('1', '0')
    assert default.rule_group == 'Medium'
    assert [default.get_action(action) for action in ['contain', 'block', 'clean', 'notify']] \
        == [('1', '30'), ('1', '15'), ('1', '1'), ('0', '50')]
    assert (default.enhanced_remediation, default.remediation_monitoring) == ('1', '0')
    assert default.get_notifications()['message'] == ''
    assert (default.reputation_source, default.story_graph) == ('1', '1')
    assert default.get_sandboxing() == {'enabled': '0', 'level': '50', 'size_limit': 5}

    monitoring = load(ESATPPolicyOptions, 'Demo (Monitoring)')
    assert (monitoring.operation_mode, monitoring.atp, monitoring.observe_mode) == ('2', '1', '1')
    assert monitoring.credential_theft_protection_observe == '1'

    test = load(ESATPPolicyOptions, 'Claude - ATP Options Test')
    assert (test.operation_mode, test.atp, test.observe_mode) == ('0', '0', '0')
    assert (test.allow_disable_from_tray, test.sensitivity_level) == ('1', '2')
    assert test.get_notifications() == {'enabled': '1', 'level': '70', 'default_action': '0',
                                        'timeout': 3, 'message': 'Claude custom message',
                                        'disable_offline': '0'}
    assert test.reputation_source == '2'
    assert test.get_sandboxing() == {'enabled': '1', 'level': '85', 'size_limit': 12}
    assert test.story_graph == '0'


def test_options_operation_mode():
    policy = load(ESATPPolicyOptions, 'My Default')
    policy.observe_mode = '1'
    assert policy.operation_mode == ESATPPolicyOptions.OBSERVE
    # The console locks the Observe mode of the script scanning and of the CTP.
    assert (policy.script_scanning_observe, policy.credential_theft_protection_observe) == (
        '1', '1')
    with pytest.raises(ValueError):
        policy.credential_theft_protection_observe = '0'
    policy.atp = '1'
    assert policy.operation_mode == ESATPPolicyOptions.OBSERVE
    policy.atp = '0'
    assert (policy.operation_mode, policy.observe_mode) == ('0', '0')
    with pytest.raises(ValueError):
        policy.observe_mode = '1'
    policy.atp = '1'
    assert policy.operation_mode == ESATPPolicyOptions.ENABLED
    policy.credential_theft_protection_observe = '0'
    with pytest.raises(ValueError):
        policy.operation_mode = '3'


def test_options_write():
    policy = load(ESATPPolicyOptions, 'My Default')
    policy.telemetry = '0'
    policy.sensitivity_level = '0'
    policy.rule_group = 'High'
    policy.reputation_source = '0'
    policy.story_graph = '0'
    with pytest.raises(ValueError):
        policy.rule_group = 'Balanced'
    with pytest.raises(ValueError):
        policy.sensitivity_level = '3'
    with pytest.raises(ValueError):
        policy.telemetry = 'yes'
    policy.set_action('contain', '1', '50')
    policy.set_notifications('1', '85', default_action='0', timeout=2, message='Call the SOC',
                             disable_offline='0')
    policy.set_sandboxing('1', '15', 64)
    assert (policy.get_option('telemetry'), policy.get_option('rpSensitivityLevel'),
            policy.get_option('securityPosture'), policy.get_option('reputationSelector'),
            policy.get_option('StoryGraphEnabled')) == ('0', '0', 'High', '0', '0')
    assert (policy.get_option('containLevel'), policy.get_option('promptEnabled'),
            policy.get_option('promptLevel'), policy.get_option('promptDefault'),
            policy.get_option('promptTimeout'), policy.get_option('customPromptText'),
            policy.get_option('customPromptTextEnabled'),
            policy.get_option('offlinePromptingDisabled')) == (
                '50', '1', '85', '0', '2', 'Call the SOC', '1', '0')
    assert policy.get_sandboxing() == {'enabled': '1', 'level': '15', 'size_limit': 64}
    policy.set_notifications('1', message='')
    assert policy.get_option('customPromptTextEnabled') == '0'
    with pytest.raises(ValueError):
        policy.set_notifications('1', timeout=7)
    with pytest.raises(ValueError):
        policy.set_sandboxing('1', size_limit=129)
    with pytest.raises(ValueError):
        policy.set_sandboxing('1', level='30')
    with pytest.raises(ValueError):
        policy.set_action('clean', '1', '50')


def test_options_thresholds():
    """
    The console refuses Clean > Block, Block > Contain and Contain > Notify
    for enabled actions: the library leaves the policy unchanged.
    """
    policy = load(ESATPPolicyOptions, 'My Default')   # contain 30, block 15, clean 1
    with pytest.raises(ValueError):
        policy.set_action('block', '1', '50')
    assert policy.get_action('block') == ('1', '15')
    with pytest.raises(ValueError):
        policy.set_action('notify', '1', '15')
    assert policy.get_action('notify') == ('0', '50')
    policy.set_action('contain', '0')
    policy.set_action('block', '1', '50')
    assert policy.check_thresholds() == []
    with pytest.raises(ValueError):
        policy.set_action('contain', '1')
    assert policy.get_action('contain') == ('0', '30')


def test_dac_rules():
    default = load(ESATPPolicyDAC, 'My Default')
    rules = default.get_rules()
    assert len(rules) == 42 == len(ESATPPolicyDAC.RULES)
    assert rules[0] == {'id': 'DAC_BLOCK_MODIFY_CACHED_PASSWORDS',
                        'name': 'Accessing insecure password LM hashes',
                        'block': '0', 'report': '1', 'note': ''}
    assert rules[-1]['name'] == 'Writing to files commonly targeted by ransomware-class malware'
    assert all((rule['block'], rule['report']) == ('0', '1') for rule in rules)

    test = load(ESATPPolicyDAC, 'Claude - ATP DAC Test')
    changed = {rule['name']: (rule['block'], rule['report']) for rule in test.get_rules()
               if (rule['block'], rule['report']) != ('0', '1')}
    assert changed == {'Accessing user cookie locations': ('1', '1'),
                       'Executing any child process': ('0', '0'),
                       'Terminating another process': ('1', '1')}

    default.set_rule('DAC_BLOCK_PROCESS_TERMINATE', block='1')
    default.set_rule('Executing any child process', report='0')
    assert default.get_rule('Terminating another process')['block'] == '1'
    assert default.get_rule('DAC_BLOCK_CHILD_PROC_EXEC')['report'] == '0'
    with pytest.raises(ValueError):
        default.set_rule('No such rule', block='1')
    with pytest.raises(ValueError):
        default.set_rule('DAC_BLOCK_PROCESS_TERMINATE', block='2')
    default.set_all_rules(block='1')
    assert all(rule['block'] == '1' for rule in default.get_rules())


def test_dac_exclusions_read():
    exclusions = load(ESATPPolicyDAC, 'Claude - ATP DAC Test').get_exclusions()
    assert exclusions == [
        DACExclusion('Claude excl hash', md5='fedcba9876543210fedcba9876543210'),
        DACExclusion('Claude excl full', path='C:\\Tools\\claude*.exe',
                     md5='0123456789abcdef0123456789abcdef',
                     signer='C=US, O=CLAUDE TEST, CN=CLAUDE TEST SIGNER', notes='Note line 1'),
        DACExclusion('Claude excl any signer', path='claude.exe',
                     signer=DACExclusion.ANY_SIGNATURE)]
    assert exclusions[2].id == '9471a703-87a6-4538-8083-5d474bad94e3'
    assert [exclusion.signer_label for exclusion in exclusions] == [
        '', 'C=US, O=CLAUDE TEST, CN=CLAUDE TEST SIGNER', 'Any signature']
    assert load(ESATPPolicyDAC, 'My Default').get_exclusions() == []


def test_dac_exclusions_write():
    policy = load(ESATPPolicyDAC, 'Claude - ATP DAC Test')
    before = policy.get_exclusions()
    new = DACExclusion('Backup agent', path='**\\backup.exe', signer='CN=Example Corp')
    assert policy.add_exclusion(new)
    assert not policy.add_exclusion(DACExclusion('Backup agent', path='**\\backup.exe',
                                                 signer='CN=Example Corp'))
    assert policy.get_exclusions() == before + [new]
    # IDs are kept, the new exclusion gets a GUID.
    assert {e.name: e.id for e in policy.get_exclusions()}['Claude excl hash'] == \
        {e.name: e.id for e in before}['Claude excl hash']
    assert len(new.id) == 36
    # Raw storage, as written by the console.
    count = policy.get_setting_value('dacGeneral', 'ExecutableCount')
    assert count == '4'
    row = [n for n in range(4) if policy.get_setting_value(
        'dacGeneral', 'Executable#{}_Name'.format(n)) == 'Backup agent'][0]
    raw = lambda key: policy.get_setting_value('dacGeneral', 'Executable#{}_{}'.format(row, key))
    assert (raw('IncludeStatus'), raw('ParameterCount'), raw('Parameter#0_Name'),
            raw('Parameter#0_Value'), raw('Parameter#2_Name'), raw('Parameter#2_Value')) == (
                'exclude', '3', 'OBJECT_NAME', '**\\backup.exe', 'CERT_NAME', 'CN=Example Corp')
    assert policy.remove_exclusion('Claude excl hash')
    assert not policy.remove_exclusion('Claude excl hash')
    assert policy.remove_exclusion(new)
    assert [e.name for e in policy.get_exclusions()] == ['Claude excl full',
                                                         'Claude excl any signer']
    for bad in [DACExclusion(''), DACExclusion('No criteria'), DACExclusion('x', md5='abc'),
                DACExclusion('x', path='a' * 257)]:
        with pytest.raises(ValueError):
            policy.add_exclusion(bad)


def test_new_policy_gets_new_exclusion_ids():
    policies = load_policies()
    copy = ESATPPolicyDAC(policies.new_policy(DAC, 'Copy', 'Claude - ATP DAC Test'))
    original = load(ESATPPolicyDAC, 'Claude - ATP DAC Test')
    assert [e.name for e in copy.get_exclusions()] == [e.name for e in original.get_exclusions()]
    assert not {e.id for e in copy.get_exclusions()} & {e.id for e in original.get_exclusions()}


def test_markdown():
    text = load(ESATPPolicyOptions, 'Claude - ATP Options Test').to_markdown()
    assert 'Endpoint Security Adaptive Threat Protection - Options policy' in text
    for heading in ['Adaptive Threat Protection', 'ML Protect Scanning (Windows only)',
                    'Rule Assignment', 'Action Enforcement', 'Threat Detection User Messaging',
                    'Reputation Source', 'Sandboxing', 'Story Graph']:
        assert '. {}\n'.format(heading) in text
    assert '| Enable Adaptive Threat Protection | No |' in text
    assert 'Enable Observe mode (Events are generated but actions are not enforced) ' \
           '(Windows only)' not in text
    assert '| Sensitivity level | High |' in text
    assert '| Notify the user when reputation threshold reaches | Might be Trusted |' in text
    assert '| Message | Claude custom message |' in text
    assert '| Reputation source | Use only Trellix GTI |' in text
    assert '| Limit size (MB) to | 12 |' in text
    assert '| Select the rule group for this policy | Balanced |' in text

    default = load(ESATPPolicyOptions, 'Demo (Monitoring)').to_markdown()
    assert '| Enable Observe mode (Events are generated but actions are not enforced) ' \
           '(Windows only) | Yes |' in default
    assert '| Trigger Dynamic Application Containment when reputation threshold reaches ' \
           '(Windows only) | Unknown |' in default
    assert 'Display threat notifications to user | No |' in default
    assert 'Default Action' not in default

    text = load(ESATPPolicyDAC, 'Claude - ATP DAC Test').to_markdown()
    assert 'Endpoint Security Adaptive Threat Protection - Dynamic Application ' \
           'Containment policy' in text
    assert '| 1 | Accessing insecure password LM hashes | No | Yes | Enabled |' in text
    assert '| Executing any child process | No | No | Disabled |' in text
    assert '| 3 | Claude excl any signer | claude.exe |  | Any signature |  |' in text
    assert '| 2 | Claude excl full | C:\\\\Tools\\\\claude\\*.exe | ' \
           '0123456789abcdef0123456789abcdef | C=US, O=CLAUDE TEST, CN=CLAUDE TEST SIGNER | ' \
           'Note line 1 |' in text
