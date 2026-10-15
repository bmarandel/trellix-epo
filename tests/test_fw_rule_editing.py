"""
ENS Firewall Rules: rule tree editing (FWRule, FWGroup, FWNetwork,
FWApplication, FWExecutable, FWLocation).

- fw_console.xml: a copy of "My Default" (lab ePO 5.10) where the console was
  used to add the group "Claude Group" (Out, notes, timed group 30 min,
  location "Claude Office": DNS suffix + default gateway, ePO reachable)
  holding the rules "Claude Rule In Group" (Allow, Out, UDP, remote port
  53) and "Claude FW Rule Full" (Block, intrusion, log, In, IPv4 + IPv6,
  wired + wireless, TCP local ports 1000-2000/3389 remote port 443, a local
  and a remote network, an application with two executables, schedule
  Tuesday/Thursday/Saturday/Sunday 08:30-18:15) - the reference of the
  storage format.
- fw_policy_all.xml: an older export with a console-made rule ("Test All")
  and a location ("Test CAG").
"""

from pathlib import Path

import pytest

from trellix_epo import (ESFWPolicyRules, FWRule, FWGroup, FWNetwork, FWApplication,
                                 FWExecutable, FWLocation, FWAddress)

FIXTURES = Path(__file__).parent / 'fixtures'


def load(name):
    policy = ESFWPolicyRules()
    policy.load_from_file(str(FIXTURES / name))
    policy.load_policy()
    return policy


def settings(policy, guid):
    for settings_obj in policy.root.findall('EPOPolicySettings'):
        section_obj = settings_obj.find('Section')
        values = {setting.get('name'): setting.get('value')
                  for setting in section_obj.findall('Setting')}
        if values.get('GUID') == guid:
            return settings_obj.get('name'), values
    return None, None


def sequence(policy, key):
    for settings_obj in policy.root.findall('EPOPolicySettings[@param_int="100"]'):
        values = {setting.get('name'): setting.get('value')
                  for setting in settings_obj.find('Section').findall('Setting')}
        if values.get('RuleListID', 'root') == key:
            count = int(values.get('_RuleIDSequence', '0'))
            return [values['+RuleIDSequence#{}'.format(row)] for row in range(count)]
    return None


def test_addresses():
    for console, stored in [
            ('10.1.2.3', '0000:0000:0000:0000:0000:ffff:0a01:0203'),
            ('192.168.50.0/24', '0000:0000:0000:0000:0000:ffff:c0a8:3200/120'),
            ('10.20.0.1-10.20.0.50', '0000:0000:0000:0000:0000:ffff:0a14:0001-'
                                     '0000:0000:0000:0000:0000:ffff:0a14:0032'),
            ('server.claude.test', 'server.claude.test'),
            (FWAddress.ANY_IPV6, '0000:0000:0000:0000:0000:0000:0000:0000-'
                                 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
            (FWAddress.TRUSTED, '[trusted]'),
            ('2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001')]:
        assert FWAddress.to_epo(console) == stored
        assert FWAddress.from_epo(stored) == console


def test_read_console_rules():
    policy = load('fw_console.xml')
    group = policy.get_rule('Claude Group')
    assert group.is_group and (group.direction, group.notes, group.timed_minutes) == (
        FWRule.OUT, 'Claude group notes', 30)
    assert [rule.name for rule in group.rules] == ['Claude Rule In Group', 'Claude FW Rule Full']
    location = group.location
    assert (location.name, location.isolated, location.require_epo_reachable,
            location.dns_suffixes, location.default_gateways) == (
        'Claude Office', False, True, ['claude.test'], ['10.0.0.1'])
    rule = group.rules[1]
    assert (rule.action, rule.direction, rule.intrusion, rule.log, rule.notes) == (
        FWRule.BLOCK, FWRule.IN, True, True, 'Claude rule notes')
    assert rule.network_protocols == [FWRule.IPV4, FWRule.IPV6]
    assert rule.connection_types == [FWRule.WIRED, FWRule.WIRELESS]
    assert (rule.transport_protocol, rule.local_ports, rule.remote_ports) == (
        FWRule.TCP, ['1000-2000', '3389'], ['443'])
    assert (rule.schedule_enabled, rule.schedule_days, rule.schedule_start,
            rule.schedule_end) == (True, ['Sunday', 'Tuesday', 'Thursday', 'Saturday'],
                                   '08:30', '18:15')
    assert [(net.name, net.addresses) for net in rule.local_networks] == [
        ('Claude Local Net', ['10.20.0.1-10.20.0.50', '10.1.2.3'])]
    assert [(net.name, net.addresses) for net in rule.remote_networks] == [
        ('Claude Remote Net', ['server.claude.test', '192.168.50.0/24',
                               FWAddress.ANY_IPV6])]
    app = rule.applications[0]
    assert (app.name, app.notes) == ('Claude App', 'Claude app notes')
    assert [(exe.name, exe.path, exe.md5, exe.signer, exe.description, exe.notes)
            for exe in app.executables] == [
        ('Claude Exe Two', r'**\claude2.exe', '', '', '', ''),
        ('Claude Exe', r'C:\Claude\claudefw.exe', 'abcdefabcdefabcdefabcdefabcdefab',
         'CN=Claude Signer, O=Claude, C=US', 'Claude exe description', 'Claude exe notes')]
    assert policy.get_rules()[0].view_only


def test_round_trip_is_lossless():
    for name in ['fw_console.xml', 'fw_policy_all.xml']:
        policy = load(name)
        for rule in policy.get_all_rules():
            assert rule.to_values() == settings(policy, rule.id)[1]
            for obj, kind in rule.all_aggregates():
                values = obj.to_values(kind) if isinstance(obj, FWNetwork) else obj.to_values()
                assert values == settings(policy, obj.id)[1]


def test_update_without_change_keeps_the_tree():
    policy = load('fw_console.xml')
    before = [(rule.id, rule.name) for rule in policy.get_all_rules()]
    rule = policy.get_rule('Claude FW Rule Full')
    old = settings(policy, rule.id)[1]
    assert policy.update_rule(rule)
    new = settings(policy, rule.id)[1]
    assert {key: value for key, value in new.items() if not key.startswith('LastModif')} == \
        {key: value for key, value in old.items() if not key.startswith('LastModif')}
    assert new['LastModifyingUsername'] == FWRule.MODIFIED_BY
    assert [(rule.id, rule.name) for rule in policy.get_all_rules()] == before


def new_group():
    rule = FWRule('Lib Rule', FWRule.ALLOW, FWRule.OUT, log=True, notes='lib notes',
                  network_protocols=[FWRule.IPV4, FWRule.IPV6],
                  connection_types=[FWRule.WIRED], transport_protocol=FWRule.TCP,
                  local_ports=['8080'], remote_ports=['443', '8443'],
                  local_networks=[FWNetwork('Lib Local', [FWAddress.LOCAL_SUBNET,
                                                          '10.1.0.0/16'])],
                  remote_networks=[FWNetwork('Lib Remote', ['lib.example.com',
                                                            '10.2.0.1-10.2.0.9'])],
                  applications=[FWApplication('Lib App', [
                      FWExecutable('Lib Exe', path=r'**\lib.exe', signer='CN=Lib'),
                      FWExecutable('Lib Exe 2', md5='0123456789abcdef0123456789abcdef')])])
    rule.set_schedule(['Monday', 'Friday'], '07:00', '19:30')
    sub = FWGroup('Lib Sub Group', rules=[FWRule('Lib Sub Rule', FWRule.BLOCK,
                                                 transport_protocol=FWRule.ICMP)])
    return FWGroup('Lib Group', FWRule.EITHER, notes='group notes', timed_minutes=15,
                   location=FWLocation('Lib Office', isolated=True,
                                       dns_suffixes=['lib.example.com'],
                                       default_gateways=['10.0.0.254']),
                   rules=[rule, sub])


def test_add_group_with_rules():
    policy = load('fw_console.xml')
    group = new_group()
    assert policy.add_rule(group, position=1)
    # Stored as the console does.
    assert sequence(policy, 'root')[1] == group.id
    rule, sub = group.rules
    assert sequence(policy, group.id) == [rule.id, sub.id]
    assert sequence(policy, sub.id) == [sub.rules[0].id]
    name, values = settings(policy, group.id)
    assert name == 'Claude - FW Rules Test:Group:{}'.format(group.id)
    assert (values['Action'], values['ClickTimeout'], values['ViewOnly']) == ('JUMP', '15', '0')
    name, values = settings(policy, rule.id)
    assert name == 'Claude - FW Rules Test:Rule:{}'.format(rule.id)
    assert (values['WeekMask'], values['ScheduleStartHours'], values['ScheduleEndMinutes'],
            values['+RemotePort#0'], values['+AppExeSet#0']) == ('34', '7', '30', '443, 8443',
                                                               '0-1')
    exe = rule.applications[0].executables[1]
    assert settings(policy, exe.id)[1]['+AppHash#0'] == '0123456789abcdef0123456789abcdef'
    assert settings(policy, rule.applications[0].executables[0].id)[1]['+AppHash#0'] == '0' * 32
    remote = rule.remote_networks[0]
    name, values = settings(policy, remote.id)
    assert name == 'Claude - FW Rules Test:NamedNetwork:{}:Remote'.format(remote.remote_id)
    assert (values['Type'], values['+RemoteAddress#1']) == (
        '65546', '0000:0000:0000:0000:0000:ffff:0a02:0001-0000:0000:0000:0000:0000:ffff:0a02:0009')
    assert settings(policy, rule.local_networks[0].id)[1]['+LocalAddress#0'] == \
        '0000:0000:0000:0000:0000:ffff:0000:0000'
    assert settings(policy, group.location.id)[1]['Type'] == '65543'
    # Read back.
    read = policy.get_rule('Lib Group')
    assert [item.name for item in read.walk()] == ['Lib Rule', 'Lib Sub Group', 'Lib Sub Rule']
    assert read.location.default_gateways == ['10.0.0.254']
    read_rule = read.rules[0]
    assert read_rule.schedule_days == ['Monday', 'Friday']
    assert [exe.name for exe in read_rule.applications[0].executables] == ['Lib Exe', 'Lib Exe 2']
    assert read_rule.local_networks[0].addresses == [FWAddress.LOCAL_SUBNET, '10.1.0.0/16']
    # The legacy dictionaries and the Markdown export see it.
    assert read_rule.id in policy.rul and group.id in policy.seq
    assert 'Lib Sub Rule' in policy.to_markdown()


def test_add_checks():
    policy = load('fw_console.xml')
    with pytest.raises(ValueError):
        policy.add_rule(FWRule(''))
    with pytest.raises(ValueError):
        policy.add_rule(FWRule('ports', local_ports=['80']))
    with pytest.raises(ValueError):
        policy.add_rule(FWRule('x', remote_networks=[FWNetwork('empty')]))
    with pytest.raises(ValueError):
        rule = FWRule('x')
        rule.set_schedule(['Monday'], '25:00')
        policy.add_rule(rule)
    # The content of a view only group can't be changed.
    with pytest.raises(ValueError):
        policy.add_rule(FWRule('x'), group='Trellix core networking')
    with pytest.raises(ValueError):
        policy.add_rule(FWRule('x'), group='Allow SNMP traffic')
    # A network already used by a rule must be copied.
    network = policy.get_rule('Claude FW Rule Full').local_networks[0]
    with pytest.raises(ValueError):
        policy.add_rule(FWRule('x', local_networks=[network]))
    rule = FWRule('x', local_networks=[network.copy()])
    assert policy.add_rule(rule)
    assert rule.local_networks[0].id != network.id
    with pytest.raises(ValueError):
        policy.add_rule(rule)


def test_update_rule():
    policy = load('fw_console.xml')
    rule = policy.get_rule('Claude FW Rule Full')
    old_exe = rule.applications[0].executables[0].id
    old_remote = rule.remote_networks[0].id
    rule.enabled = False
    rule.remote_networks = []
    rule.applications[0].executables.pop(0)
    rule.applications.append(FWApplication('Other', [FWExecutable('o', path='o.exe')]))
    rule.schedule_enabled = False
    assert policy.update_rule(rule)
    _, values = settings(policy, rule.id)
    assert (values['Enabled'], values['ScheduleEnabled'], values['_AggRef'],
            values['+AppExeSet#0'], values['+AppExeSet#1']) == ('0', '0', '3', '0', '1')
    # The aggregates not used any more are removed.
    assert settings(policy, old_exe) == (None, None)
    assert settings(policy, old_remote) == (None, None)
    read = policy.get_rule('Claude FW Rule Full')
    assert [app.name for app in read.applications] == ['Claude App', 'Other']
    assert read.remote_networks == []
    # View only rules and a rule turned into a group are refused.
    core = policy.get_rule('Allow DNS traffic')
    assert core.view_only
    with pytest.raises(ValueError):
        policy.update_rule(core)
    group = FWGroup('g', group_id=rule.id)
    with pytest.raises(ValueError):
        policy.update_rule(group)
    assert not policy.update_rule(FWRule('unknown'))


def test_update_group_location():
    policy = load('fw_console.xml')
    group = policy.get_rule('Claude Group')
    group.location.dns_servers = ['10.0.0.53']
    group.timed_minutes = 0
    assert policy.update_rule(group)
    _, values = settings(policy, group.location.id)
    assert values['+DnsServer#0'] == '0000:0000:0000:0000:0000:ffff:0a00:0035'
    assert settings(policy, group.id)[1]['ClickTimeout'] == '0'
    old = group.location.id
    group.location = None
    assert policy.update_rule(group)
    assert settings(policy, old) == (None, None)
    assert '_AggRef' not in settings(policy, group.id)[1]
    # The rules of the group are kept.
    assert len(policy.get_rule('Claude Group').rules) == 2


def test_remove_rule_and_group():
    policy = load('fw_console.xml')
    group = policy.get_rule('Claude Group')
    rule = group.rules[1]
    exe = rule.applications[0].executables[0].id
    count = len(policy.root.findall('EPOPolicySettings'))
    assert policy.remove_rule('Claude FW Rule Full')
    assert sequence(policy, group.id) == [group.rules[0].id]
    assert settings(policy, rule.id) == (None, None) and settings(policy, exe) == (None, None)
    # Rule + 2 executables + 2 networks.
    assert len(policy.root.findall('EPOPolicySettings')) == count - 5
    names = set(ref.text for ref in policy.root.find('EPOPolicyObject').findall('PolicySettings'))
    assert names == set(obj.get('name') for obj in policy.root.findall('EPOPolicySettings'))
    assert policy.remove_rule(group)
    assert group.id not in sequence(policy, 'root') and sequence(policy, group.id) is None
    assert policy.get_rule('Claude Rule In Group') is None
    assert not policy.remove_rule('unknown')
    with pytest.raises(ValueError):
        policy.remove_rule('Allow DNS traffic')


def test_move_rule():
    policy = load('fw_console.xml')
    group = policy.get_rule('Claude Group')
    snmp = policy.get_rule('Allow SNMP traffic')
    assert policy.move_rule(snmp, group, 0)
    assert sequence(policy, group.id)[0] == snmp.id
    assert snmp.id not in sequence(policy, 'root')
    assert policy.move_rule('Claude FW Rule Full', position=0)
    assert sequence(policy, 'root')[0] == group.rules[1].id
    assert policy.move_rule(group, position=0)
    assert sequence(policy, 'root')[0] == group.id
    sub = FWGroup('Sub')
    policy.add_rule(sub, group)
    with pytest.raises(ValueError):
        policy.move_rule(group, sub)
    with pytest.raises(ValueError):
        policy.move_rule(group, group)
    with pytest.raises(ValueError):
        policy.move_rule('Allow DNS traffic', group)
    with pytest.raises(ValueError):
        policy.move_rule(snmp, 'Trellix core networking')


def test_empty_group():
    # An empty group has a sequence without _RuleIDSequence (console export).
    policy = load('fw_console.xml')
    group = FWGroup('Empty')
    policy.add_rule(group)
    assert sequence(policy, group.id) == []
    _, values = settings(policy, group.id)
    assert '_RuleIDSequence' not in [setting.get('name') for setting in policy.root.find(
        'EPOPolicySettings[@name="Claude - FW Rules Test:Sequence:{}"]/Section'.format(
            group.id))]
    assert policy.get_rule('Empty').rules == []
    assert group.id in policy.seq and policy.seq[group.id] == []


def test_schedule_markdown():
    # WeekMask Sunday is 1; the times are ScheduleStart/End*, not StartTime/EndTime.
    text = load('fw_console.xml').to_markdown()
    assert 'Tuesday, Thursday, Saturday, Sunday from 08:30 to 18:15' in text
    old = load('fw_policy_all.xml').to_markdown()
    assert 'Monday, Tuesday, Wednesday, Thursday, Friday from 08:00 to 20:00' in old


def test_console_field_lengths():
    # A 101 characters rule name was imported by ePO 5.10 but the console then
    # failed to open the policy; the other limits are the console fields'.
    policy = load('fw_console.xml')
    assert policy.add_rule(FWRule('N' * 100))
    for rule in [FWRule('N' * 101), FWRule('x', notes='n' * 3001),
                 FWRule('x', local_networks=[FWNetwork('N' * 101, ['10.0.0.1'])]),
                 FWRule('x', applications=[FWApplication('a', [
                     FWExecutable('e', path='p' * 258)])]),
                 FWRule('x', applications=[FWApplication('a', [
                     FWExecutable('e', signer='s' * 1025)])]),
                 FWGroup('g', timed_minutes=100),
                 FWGroup('g', location=FWLocation('l', dns_suffixes=['d' * 101]))]:
        with pytest.raises(ValueError):
            policy.add_rule(rule)
