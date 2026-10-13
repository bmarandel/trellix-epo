# McAfee ePolicy Orchestrator Policies Python Class Library

![PyPI](https://img.shields.io/pypi/v/mcafee_epo_policies)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![License](https://img.shields.io/github/license/bmarandel/mcafee-epo-policies)
![Top language](https://img.shields.io/github/languages/top/bmarandel/mcafee-epo-policies)

## Overview

This package provides a set of Python classes to read, inspect, and modify policy
documents exported from the Policy Catalog of McAfee ePolicy Orchestrator (ePO),
without needing to know the underlying XML schema. Each supported policy is
exposed as an object with named properties (e.g. `policy.asci = 15`) instead of
raw Section/Setting XML lookups. Policies can also be exported as a Markdown
document (`to_markdown()` / `save_markdown()`, see "Policy documentation"
below) to keep a documentation of the enforced security policies.

## Supported policies

| Product | Policy | Status | Markdown report |
|---|---|---|---|
| McAfee Agent | General | Full read/write | Yes |
| McAfee Agent | Repository | Full read/write | Yes |
| McAfee Agent | Troubleshooting | Full read/write | Yes |
| McAfee Agent | Custom Properties | Full read/write | Yes |
| McAfee Agent | Product Improvement Program (Telemetry) | Full read/write | Yes |
| ENS Common | Options | Full read/write (passwords: see the note below) | Yes |
| ENS Threat Prevention | On-Access Scan | Full read/write | Yes |
| ENS Threat Prevention | On-Demand Scan | Full read/write | Yes |
| ENS Threat Prevention | Exploit Prevention | Full read/write: signatures/expert rules, exclusions, Application Protection Rules (user-defined created/edited/removed, Trellix-defined status/inclusion/executables/notes) | Yes |
| ENS Threat Prevention | Access Protection | Full read/write: rules (user-defined created/edited/removed, Trellix-defined Block/Report/executables/notes), subrules, exclusions | Yes |
| ENS Threat Prevention | Options | Full read/write | Yes |
| ENS Firewall | Rules | Full read/write: rules, groups (sub groups, location, timed group), networks, applications, schedule | Yes |
| ENS Firewall | Options | Full read/write | Yes |
| ENS Storage Protection | ICAP Policies | Full read/write: connection list, ICAP server, scan items, performance, actions, reports | Yes |
| ENS Storage Protection | NetApp Policies | Full read/write: filers, filer account, scan items, exclusions, performance, actions, reports | Yes |
| ENS Adaptive Threat Protection | Options | Full read/write | Yes |
| ENS Adaptive Threat Protection | Dynamic Application Containment | Full read/write: containment rules (Block/Report), exclusions | Yes |
| ENS Web Control | Options | Full read/write (Web Reporter password: kept, never set) | Yes |
| ENS Web Control | Enforcement Messaging | Full read/write (15 languages) | Yes |
| ENS Web Control | Block and Allow List | Full read/write: sites, file download rating actions | Yes |
| ENS Web Control | Content Actions | Full read/write: web category blocking, rating actions | Yes |
| ENS Web Control | Browser Control | Full read/write | Yes |
| System Information Reporter | Collect Data - General | Full read/write: collected items, custom environment variable, registry queries, schedule, file and folder search | Yes |
| System Information Reporter | Set Registry - Registry General | Full read/write: registry values (create/delete), backup files, registry restore | Yes |
| Solidcore - General | Configuration (Client) | Full read/write (CLI password: raw hashes only) | Yes |
| Solidcore - General | Exception Rules (Windows/Unix) | Full read/write | Yes |
| Solidcore - Application Control | Application Control Options (Windows/Unix) | Full read/write | Yes |
| Solidcore - Application Control | Application Control Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed | Yes |
| Solidcore - Change Control | Change Control Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed | Yes |
| Solidcore - Integrity Monitor | Integrity Monitoring Rules (Windows/Unix) | Full read/write (all tabs); Rule Groups added/removed | Yes |
| Solidcore | Rule Groups (Application Control, Change Control, Integrity Monitor) | Full read/write of the `scor.rulegroup.export` / `import` files | Not yet |
| Trellix EDR with Forensics | General | Full read/write, "Show Advanced" settings included (passwords, Forensics(HX) server: see below) | Yes |
| Trellix EDR with Forensics | Streaming | Full read/write: Trace, exclusions, Event streamer (event logs, file events, filters, OS events, DXL, Helix, syslog servers), Alerts, Process Tracker, Logon Tracker (S3 keys: see below) | Yes |
| Trellix EDR with Forensics | Detection | Full read/write: events, exclusions, registry key exclusions | Yes |
| Trellix EDR with Forensics | Investigation | Full read/write: Real-Time Search, Network Flow, File Hashing, exclusions | Yes |
| Trellix EDR with Forensics | Remediation | Full read/write: Host Remediation, containment page (by hand with title and logo, or from URL), messages and exclusions, allowed IP addresses (password: see below) | Yes |
| Trellix EDR with Forensics | Protection | Not supported (removed by the extension 50.3) | No |

The "Markdown report" column tells which policy types support the Markdown
export (`to_markdown()` / `save_markdown()`); for the other policy classes
these methods raise `NotImplementedError` for now (`SCRuleGroups` has no
Markdown export method yet).

McAfee Agent policy coverage is complete - all 5 McAfee Agent policy types are implemented.

Endpoint Security (ENS) policy coverage is complete - all 15 ENS policy types
of the ePO Policy Catalog are implemented: Common (Options), Threat Prevention
(On-Access Scan, On-Demand Scan, Exploit Prevention, Access Protection,
Options), Firewall (Rules, Options), Adaptive Threat Protection (Options,
Dynamic Application Containment) and Web Control (Options, Enforcement
Messaging, Block and Allow List, Content Actions, Browser Control), in the
`es` subpackage (`es.cm`, `es.tp`, `es.fw`, `es.atp`, `es.wc`). ENS
Storage Protection, a separate product, is supported too (`es.sp`).

Solidcore (Trellix Application and Change Control) policy coverage is complete -
all 13 Solidcore policy types of the ePO Policy Catalog are implemented, in the
`sc` subpackage (`sc.gen`, `sc.awl`, `sc.cc`, `sc.fim`, named after the ePO
feature IDs SCOR_GEN, SCOR_AWL, SCOR_CC and SCOR_FIM).

Trellix EDR with Forensics (ePO product XCLIENT_META, extension 50.3; the
policies of the extension 2.1.2 are read too) is supported in the `edrf`
subpackage: all policy types except Protection.

## Installation

```
pip install mcafee_epo_policies
```

## Usage

```python
from mcafee_epo_policies import McAfeeAgentPolicies, McAfeeAgentPolicyGeneral

# Load a Policies export (XML) from the ePO Policy Catalog
with open('EPOAGENTMETA_policies.xml', 'rb') as f:
    policies = McAfeeAgentPolicies(f.read())

# List the policies contained in the export
print(policies.list())

# Extract one policy and wrap it for editing
policy_xml = policies.get_policy('General', 'My Custom Policy')
policy = McAfeeAgentPolicyGeneral(policy_xml)

# Read and change a setting through a property, instead of raw XML
print(policy.asci)
policy.asci = 15

# Save the edited policy, ready to re-import into ePO
policy.save_to_file('My Custom Policy - edited.xml')
```

The setters refuse what the ePO console refuses: number ranges and text
lengths of the console fields (e.g. `policy.asci = 3000` raises `ValueError`,
the console accepts 5 to 2880 minutes), and the console rules for paths and
addresses. They are checked against the lab console, product by product
(Trellix Agent: extension 5.8.6 - repository paths with their macros, relay
servers, IP reporting mode; ENS Common: Endpoint Security Platform 26.8 -
log files location, proxy address, Self Protection exclusions; ENS Threat
Prevention 26.8 - scan, exclusion and quarantine paths, file types, Access
Protection rules and executables, Exploit Prevention exclusions with their
IP lists, Application Protection Rules and Expert Rules; ENS Firewall 26.8 -
rule network addresses, ports, executables, locations, Options Defined
Networks, DNS Blocking and Trusted Executables). Whatever the
product, a setting value longer than 3072 characters is refused: the ePO
server keeps 3072 characters per setting and truncates the rest, even on
import (a long Exploit Prevention Expert Rule is split over several
settings, as the console does).

### Policy documentation (Markdown)

Most companies must keep a documentation of the security policies they
enforce (audits, compliance). `to_markdown()` returns a Markdown document of a
policy, as close as possible to the ePO console: a metadata header (product,
policy category, name, ePO server and version, date), a table of contents,
one section per console tab with the console labels, settings as
"Setting | Value" tables, lists (exclusions, signatures, firewall rules...)
as numbered tables, and a document control section (review/approval
sign-off, change history) to fill in. `save_markdown()` writes it to a file.

```python
policy.save_markdown('On-Access Scan - My Custom Policy.md',
                     author='Jane Doe', reviewers=['CISO'])
```

Available for all McAfee (Trellix) Agent policy types (General, Repository,
Troubleshooting, Custom Properties, Product Improvement Program), System
Information Reporter (Collect Data, Set Registry), all Solidcore
policy types (the rules policies list their Rule Groups, then the tabs of My
Rules and of each shared Rule Group) and all ENS
policy types: Threat Prevention (On-Access Scan,
On-Demand Scan, Exploit Prevention, Access Protection, Options), Adaptive
Threat Protection (Options, Dynamic Application Containment), Web Control
(all 5 policy types), Storage Protection (ICAP, NetApp) and Firewall
(Options, and Rules documented as a firewall review: a rule summary numbered
in evaluation order, then one detail card per group/rule). Labels, order and
displayed items were checked against the ePO 5.10 console (e.g. Exploit
Prevention lists the same 486 signatures as the console). See
`examples/policy_documentation.py`.

### ENS Access Protection rules

```python
from mcafee_epo_policies import (ESTPPolicyAccessProtection, APRule, APSubRule, APTarget,
                                 APExecutable, APUserName)

rule = APRule('Block ransomware extensions', block=True, report=True)
rule.add_executable(APExecutable('Backup agent', path='**\\backupagent.exe', inclusion='exclude'))
rule.add_user_name(APUserName('Local\\System', inclusion='exclude'))
rule.add_subrule(APSubRule('Ransomware extensions', APSubRule.FILES, ['create', 'rename'],
                           targets=[APTarget('*.locky'), APTarget('*.lockbit')]))
policy.add_rule(rule)                                  # policy: ESTPPolicyAccessProtection
policy.set_rule_block('PREVENT_MIMIKATZ_CREATION', '1')  # Trellix-defined rule
```

Subrule types and operation codes are listed in `APSubRule.OPERATIONS` (Windows)
and `APSubRule.LINUX_OPERATIONS` (Linux rules), with the console labels.

### ENS Storage Protection

```python
from mcafee_epo_policies import ESSPPolicies, ESSPPolicyNetApp, SPExclusion

policies = ESSPPolicies(xml_export)               # policy.export productId=VSESTOMD1300
policy = ESSPPolicyNetApp(policies.get_policy('VSES1000_Netapp_Policies', 'My Default'))
policy.overwrite_filer_list = '1'
policy.filer_list = ['nas01.example.com', '10.0.0.20']
policy.set_file_types_to_scan(ESSPPolicyNetApp.SPECIFIED_ONLY, ['doc', 'pdf'], no_extension=True)
policy.add_exclusion(SPExclusion.pattern('D:\\Backup\\', subfolders=True))
policy.add_exclusion(SPExclusion.file_age(30, SPExclusion.CREATED))
policy.set_threat_actions(ESSPPolicyNetApp.CLEAN, ESSPPolicyNetApp.DELETE)
```

`ESSPPolicyICAP` handles the ICAP Policies (connection list, ICAP server bind
address and port) with the same Scan Items, Performance, Actions and Reports
methods.

### ENS Common

```python
from mcafee_epo_policies import ESCommonPolicies, ESCommonPolicyOptions, AACExclusion

policies = ESCommonPolicies(xml_export)           # policy.export productId=ENDP_GS_1000
policy = ESCommonPolicyOptions(policies.get_policy(ESCommonPolicyOptions.TYPE, 'My Default'))
policy.interface_language = '040C'                # French (see ESCommonPolicyOptions.LANGUAGES)
policy.set_option('ipv6', '1')                    # see options() and number_options()
policy.set_sp_action('files', '3')                # Self Protection: Block and report
policy.add_aac_exclusion(AACExclusion('C:\\Tools\\agent.exe', md5='0123456789abcdef0123456789abcdef'))
policy.set_event_level('FW', '3')                 # Firewall events: Critical and Alert
policy.set_proxy('2', 'proxy.example.com', 8080, ['*.example.com'])
```

**Passwords are not in the export.** ePO doesn't export the client interface
administrator password, the uninstall password, the HTTP proxy password nor the
time of the time-based password (checked on the ePO 5.10 lab), and importing an
exported Common policy - with this library or with the console Import - erases
the passwords defined in the console. After importing a policy in Standard
access or Lock client interface mode, or with "Require password to uninstall
the client", define its passwords again in the ePO console. The library never
sets them; the Markdown export only says they are defined in the console.

### ENS Adaptive Threat Protection

```python
from mcafee_epo_policies import ESATPPolicies, ESATPPolicyOptions, ESATPPolicyDAC, DACExclusion

policies = ESATPPolicies(xml_export)              # policy.export productId=TIEClientMETA
options = ESATPPolicyOptions(policies.get_policy('General', 'My Default'))
options.observe_mode = '1'                        # operationMode 2
options.rule_group = 'High'                       # Security
options.set_action('block', '1', '30')            # Block at Might be Malicious
options.set_notifications('1', '50', default_action='0', timeout=5,
                          message='Contact the service desk.')
options.set_sandboxing('1', '50', size_limit=10)

dac = ESATPPolicyDAC(policies.get_policy(ESATPPolicyDAC.TYPE, 'My Default'))
dac.set_rule('DAC_BLOCK_PROCESS_TERMINATE', block='1')
dac.set_rule('Executing any child process', block='0', report='0')   # disabled
dac.add_exclusion(DACExclusion('Backup agent', path='**\\backup.exe',
                               signer='C=US, O=Example Corp, CN=Example Corp'))
```

As in the console, `set_action()` refuses reputation thresholds of enabled
actions out of order (Clean <= Block <= Contain <= Notify). Containment rules
are given by their RuleID or console label (`ESATPPolicyDAC.RULES`).

### ENS Web Control

```python
from mcafee_epo_policies import (ESWCPolicies, ESWCPolicyOptions, ESWCPolicyBlockAllowList, WCSite,
                                 ESWCPolicyContentActions, ESWCPolicyMessaging, RatingActions)

policies = ESWCPolicies(xml_export)               # policy.export productId=ENDP_WP_1000
options = ESWCPolicyOptions(policies.get_policy('EWC_General', 'My Default'))
options.set_option('bGtiFailClose', '1')          # see ESWCPolicyOptions.options()
options.excluded_ips = ['10.0.0.0/8', '192.168.56-68.1-5']

lists = ESWCPolicyBlockAllowList(policies.get_policy('EWC_BlockAndAllowList', 'My Default'))
lists.add_site(WCSite('example.com', WCSite.BLOCK, 'Not work related'))

content = ESWCPolicyContentActions(policies.get_policy('EWC_ContentFiltering', 'My Default'))
content.set_category('Gambling', '1')             # code or console label
content.site_actions = RatingActions(red=RatingActions.BLOCK, yellow=RatingActions.BLOCK,
                                     unrated=RatingActions.WARN)

messages = ESWCPolicyMessaging(policies.get_policy('EWC_EnforcementMessaging', 'My Default'))
messages.set_message('szBlock', 'Ce site est interdit.', 'fr')
messages.md_languages = ['en', 'fr']              # languages of the Markdown export
```

`ESWCPolicyBrowserControl` blocks browsers by ID (`set_block('OPERA', '1')`).
The Web Reporter password is encrypted by the ePO server: it must be defined
in the console, the library keeps it and never writes it in the Markdown export.

### System Information Reporter

```python
import datetime
from mcafee_epo_policies import (SIRPolicies, SIRPolicyCollectData, SIRPolicySetRegistry,
                                 SIRRegistryValue)

policies = SIRPolicies(xml_export)                # policy.export productId=SIR_____1000
collect = SIRPolicyCollectData(policies.get_policy(SIRPolicies.COLLECT_DATA, 'My Default'))
collect.set_collect('software', '1')              # see SIRPolicyCollectData.ITEMS
collect.registry_queries = ['[HKLM]\\SOFTWARE\\Example\\Version']
collect.files = ['[PROGRAMFILES]\\Example\\example.exe']
collect.start_datetime = datetime.datetime(2026, 11, 1, 6, 0)

registry = SIRPolicySetRegistry(policies.get_policy(SIRPolicies.SET_REGISTRY, 'My Default'))
registry.set_values([SIRRegistryValue.create('Enabled', '[HKLM]\\SOFTWARE\\Example\\Enabled',
                                             'REG_DWORD', '1', overwrite=True)],
                    backup_file='Example-1')      # required by the console
```

The two SIR policy categories share the typeid "General": `SIRPolicies` uses
the feature IDs (`SIRPolicies.COLLECT_DATA`, `SIRPolicies.SET_REGISTRY`) as
policy types. Paths are checked as in the console: registry paths start with
a hive (`[HKLM]\\`...), files and folders with `[SYSTEMDRIVE]\\`,
`[SystemRoot]\\`, `[PROGRAMFILES]\\`, `[COMMONPROGRAMFILES]\\` or `{A}\\` to `{Z}\\`.

### ENS Firewall rules

```python
from mcafee_epo_policies import (FWRule, FWGroup, FWNetwork, FWApplication, FWExecutable,
                                 FWLocation, FWAddress)

rule = FWRule('Allow backup server', FWRule.ALLOW, FWRule.OUT, log=True,
              transport_protocol=FWRule.TCP, remote_ports=['443', '8400-8410'],
              remote_networks=[FWNetwork('Backup servers', ['10.10.0.0/24', 'backup.example.com'])],
              applications=[FWApplication('Backup agent', [
                  FWExecutable('agent', path='**\\backupagent.exe', signer='CN=Example Corp')])])
rule.set_schedule(['Monday', 'Friday'], '20:00', '23:59')
group = FWGroup('Office', location=FWLocation('Office LAN', dns_suffixes=['corp.example.com'],
                                             default_gateways=['10.0.0.1']),
                rules=[rule])
policy.add_rule(group, position=1)                    # policy: ESFWPolicyRules
policy.move_rule('Allow SNMP traffic', group, 0)
snmp = policy.get_rule('Allow SNMP traffic')
snmp.enabled = False
policy.update_rule(snmp)
policy.remove_rule('Allow all outbound traffic on high UDP ports')
```

Addresses are written as in the console (single IP, subnet, range, FQDN, IPv6,
or `FWAddress.LOCAL_SUBNET`, `TRUSTED`, `ANY_IPV4`, `ANY_IPV6`). Rules and groups
locked by the catalog (shown with a "View" link in the console, e.g. "Trellix
core networking") can't be changed. See `examples/firewall_rule_editing.py`.

### Solidcore

Solidcore policies are exported all together, for every Solidcore feature
(`policy.export productId=SOLIDCORE_META` with the ePO API). Unlike the other
products, a Solidcore policy is a list of rules, plus references to shared Rule
Groups: each tab of the ePO console has its own list methods.

```python
from mcafee_epo_policies import SCPolicies, SCAWLPolicyRules, SCException

with open('SOLIDCORE_META_policies.xml', 'rb') as f:
    policies = SCPolicies(f.read())

# Copy an Application Control Rules policy (shared Rule Groups are kept)
policy = SCAWLPolicyRules(policies.new_policy('AWL Rules (Windows)', 'My Copy',
                                              template='My Rules Policy'))
print(policy.get_rule_group_names())

policy.add_updater('C:\\Program Files\\MyApp\\updater.exe', 'MyApp updater')
policy.add_exclusion(SCException.CASP, 'legacy.exe')
policy.add_execution_control_rule('powershell.exe', 'block',
                                  [('command_line', 'matches', '.*-enc.*')])
policy.save_to_file('My Copy.xml')
```

#### Solidcore Rule Groups

Rule Groups (Menu > Configuration > Solidcore Rules) are exported and imported
with their own ePO API commands, `scor.rulegroup.export` and
`scor.rulegroup.import` (without a Rule Group name, the export only contains
the user defined Rule Groups). `SCRuleGroups` reads and writes those files, and
each Rule Group is edited with the same methods as the matching policy tabs.

```python
from mcafee_epo_policies import SCRuleGroups, SCAWLPolicyRules

rule_groups = SCRuleGroups()   # or SCRuleGroups(<scor.rulegroup.export output>)
group = rule_groups.new_rule_group('My Apps', SCRuleGroups.APPLICATION_CONTROL,
                                   SCRuleGroups.WINDOWS)
group.add_updater('C:\\Program Files\\MyApp\\updater.exe', 'MyApp updater')
rule_groups.save_to_file('rule_group.xml')   # scor.rulegroup.import file=rule_group.xml

policy = SCAWLPolicyRules(policies.get_policy('AWL Rules (Windows)', 'My Policy'))
policy.add_rule_group(group)                 # policy.importPolicy, after the Rule Group
```

ePO links a policy to a Rule Group by its name: import the Rule Group before
the policy that uses it. An existing Rule Group is only replaced by
`scor.rulegroup.import` with `override=true` (otherwise the import fails, even
though the API answers success - check the "Import Solidcore Rule Groups"
server task).

Not tested: the Users tab of Application Control and Change Control was only
checked with single users (`add_trusted_user()`); the Active Directory groups
imported with "AD Import" (and their "Include Subgroups" column) are kept as
they are but were not tested.

To rename a Rule Group in ePO, use `scor.rulegroup.rename <WIN|UNIX>
<APPLICATION_CONTROL|CHANGE_CONTROL|INTEGRITY_MONITOR> <old name> <new name>`:
ePO renames it in the policies using it too. `SCRuleGroups.rename_rule_group()`
renames a user defined Rule Group in an export file (importing it creates a new
Rule Group), and `SCPolicy.rename_rule_group()` updates a policy export taken
before the rename.

Note: ePO stores some Solidcore policies under an internal type name, used as
`type_id` (e.g. `Lockdown Rules` for Configuration (Client), `Attr Rules
(Windows)` for Exception Rules (Windows), `Mon Rules (Unix)` for Integrity
Monitoring Rules (Unix)); `SCPolicies.list()` shows them.

### Trellix EDR with Forensics

```python
from mcafee_epo_policies import (EDRFPolicies, EDRFPolicyGeneral, EDRFPolicyStreaming,
                                 EDRFEventLog, EDRFSyslogServer, EDRFPolicyDetection,
                                 EDRFRegistryExclusion, EDRFPolicyInvestigation,
                                 EDRFPolicyRemediation, EDRFAllowedIP)

policies = EDRFPolicies(xml_export)               # policy.export productId=XCLIENT_META
general = EDRFPolicyGeneral(policies.get_policy(EDRFPolicies.GENERAL, 'My Default'))
general.set_option('self_protection', '1')        # see EDRFPolicyGeneral.options()
general.set_option('health_interval', 15)         # "Show Advanced" settings too (minutes)
general.set_option('storage_mode', 'mmapio')      # also sets the SQLite settings
general.set_log_storage('days', 30)
general.set_proxy('manual', host='proxy.example.com', port=8080, exclude_hosts=['*.example.com'])

streaming = EDRFPolicyStreaming(policies.get_policy(EDRFPolicies.STREAMING, 'My Default'))
streaming.add_to_list('windows_process_exclusions', ['FOLDERID_ProgramFiles\\Example\\agent.exe'])
streaming.set_option('logon_tracker', '1')
streaming.set_option('event_streamer', '1')       # Event streamer (extension 50.3)
streaming.add_to_table('event_logs', EDRFEventLog('Sysmon', 'Microsoft-Windows-Sysmon/Operational',
                                                  '1, 3, 11'))
streaming.set_option('events_to_syslog', '1')
streaming.set_table('syslog_servers', [EDRFSyslogServer('SIEM', 'siem.example.com', 6514,
                                                        tls=True)])

detection = EDRFPolicyDetection(policies.get_policy(EDRFPolicies.DETECTION, 'My Default'))
detection.add_registry_exclusion(EDRFRegistryExclusion('LocalMachine', 'SOFTWARE\\Example',
                                                       ['Version']))
investigation = EDRFPolicyInvestigation(policies.get_policy(EDRFPolicies.INVESTIGATION,
                                                            'My Default'))
investigation.set_option('hash_strategy', 'low')
investigation.add_to_list('windows_hashing_extensions', ['.iso', '.vhdx'])

remediation = EDRFPolicyRemediation(policies.get_policy(EDRFPolicies.REMEDIATION, 'My Default'))
remediation.set_option('containment_title', 'Security alert')      # containment page "by hand"
remediation.set_option('containment_message', 'Contained by the SOC.\nCall the help desk.')
remediation.set_containment_image('logo.png', open('logo.png', 'rb').read())
remediation.add_allowed_ip(EDRFAllowedIP('vpn.example.com', 'VPN gateway'))
```

Each class lists its settings in `options()` (name -> console label, all of
them or one kind: `CHECK`, `NUMBER`, `SELECT`, `TEXT`, `LIST`); `get_option()` /
`set_option()` read and write them with the console checks (number ranges,
drop-down values), checkboxes as `'1'` / `'0'`, numbers in the console unit
(minutes where the console shows minutes, even when ePO stores seconds), lists
as Python lists (`get_list()`, `set_list()`, `add_to_list()`,
`remove_from_list()`); the Event streamer tables are lists of objects
(`get_table()`, `set_table()`, `add_to_table()`, `remove_from_table()`). The
classes encode the text values as the console does (semicolon separated lists,
doubled backslashes and escaped double quotes where the console stores them
so), checked against the ePO 5.10 lab with the extensions XCLIENT_META 2.1.2
and 50.3. Notes:

- **Field lengths**: the classes refuse what the console fields refuse
  (maxlength read on the console pages: 100 characters for most text fields,
  e.g. proxy name, containment title and URL, allowed IP address and
  description; 128 for the Helix settings; 260 for the registry key paths and
  value names; 256 for the Event streamer dialog fields; 200000 for the
  exclusion lists, 3072 for the General proxy exclusions). The ePO server
  keeps 3072 characters per setting: since the extension 50.3 it splits the
  exclusion lists and the containment page settings in parts (`name`,
  `name_1`, `name_2`...), as the library does, and the library refuses any
  other value longer than that once stored. The console only shows an Event
  streamer table whose JSON is shorter than 2820 characters (it drops the
  last rows of a longer one): the library refuses it.
- **Double quotes (extension 50.3)**: the server no longer escapes them in
  the split settings, and the Investigation and Remediation pages cannot
  open a policy with such a `"` (a bug of the extension, seen on the lab after
  typing one in a containment message): the library refuses `"` in their
  lists and messages. In the Streaming text fields (Helix, S3) the console
  shows a `"` as `\"` and adds a backslash at each save: refused too.

- **Passwords and keys are not set by the library**: the uninstall and
  uncontainment passwords are hashed with a random salt and the S3 bucket keys
  are encrypted by the ePO server. Enabling "Enable password to uninstall",
  "Enable password to uncontain the endpoint" or "Send traces to S3 bucket"
  is refused until they are defined in the console; unchecking "Send traces to
  S3 bucket" clears the S3 settings, as the console does.
- **Forensics(HX) server**: selecting a server in the console copies its
  configuration (certificates, private key, server names) from the ePO server
  settings into the policy. Use `copy_hx_server(policy)` to copy it from a
  policy where the server was selected in the console, or `clear_hx_server()`
  for "No HX server".
- The console cannot open a General policy with `\`, `"`, `` ` `` or `${` in a
  text setting (proxy user name...) nor a Remediation policy with `"` or `\`
  in an allowed IP description: the library refuses them.
- **Containment page** (extension 50.3): "Enter by hand" stores the title,
  message, logo (JPG, PNG or GIF, 1000 KB max) and the HTML page built from
  them, as the console does (`get_containment_page()`); "From URL"
  (`set_option('message_source', 'url')`) resets the title and message and
  clears the logo and page. The console also stores its favicon: the library
  keeps the one of the policy.
- The console saves the hidden setting `mxa/EventStreamer/dxl/compression` as
  `dxl/compressioned` (a bug of the extension 50.3): the library leaves both
  untouched.
- The Protection policy is not supported (the extension 50.3 removed it).
- Policies are saved with the characters out of ASCII as XML character
  references (`&#233;`): the policy import of the ePO Web API
  (`policy.importPolicy`) reads a UTF-8 file as ISO-8859-1 whatever the
  charset sent (`é` imported as `Ã©`); the Policy Catalog import of the
  console reads both forms right.

### Address checks

`mcafee_epo_policies.validators` holds address checks shared by the policy
classes, written as the regular expressions of the ePO console extensions so
that a class refuses exactly what its console refuses: `is_ipv4()`,
`is_ipv6()` (every short form, link-local zone, IPv4 mapped), `is_hostname()`
(a DNS name with a domain) and `is_ip_or_hostname()`.

```python
from mcafee_epo_policies.validators import is_ip_or_hostname

is_ip_or_hostname('fd00::10')       # True
is_ip_or_hostname('localhost')      # False: the console wants a domain
```

## Examples

The [`examples/`](examples/) directory has short, runnable scripts covering
McAfee Agent (General/Repository), ENS Threat Prevention (On-Access Scan,
On-Demand Scan, process exclusions), ENS Firewall (Rules reporting and editing), and
Solidcore (Application Control, Integrity Monitor and Change Control policies,
Rule Groups - some of them working directly against an ePO server) and Trellix
EDR with Forensics (best practices and example exclusions applied to copies of
the policies).

## Documentation

There is no separate documentation site yet; every class and method has a
docstring describing which ePO UI setting it maps to.

## Requirements

Python 3.8 or later.

## History

### 1.2.0 - 2026-10-05

**Added**
- Endpoint Security Common (ENS Common), new `es/common` module:
  `ESCommonPolicies` (`policy.export productId=ENDP_GS_1000`),
  `ESCommonPolicyOptions` (client interface, uninstallation, language, Self
  Protection and its process exclusions, AAC exclusions with `AACExclusion`,
  client logging, event and EDR levels, proxy, IPv6, default client update,
  managed tasks) with the Markdown export; ENS policy coverage is now
  complete. Checked on the ePO 5.10 lab (the policy changed by the library is
  identical to the one saved by the console). The passwords are not exported
  by ePO and are erased by an import (see "ENS Common" above). The trusted
  vendor Certificates list is not supported (no certificate on the lab).

### 1.1.0 - 2026-10-04

**Added**
- Solidcore exclusions (Exclusions tab, Exception Rules): Parent Process Name
  ("Allow uninstallations", "Exclude file from write-protection rules and
  allow script execution") and Library Name ("Disable ROP protection ...
  Forced Relocation (VASR)") in `get_exclusion_list()`, `add_exclusion()`,
  `contains_exclusion()`, `remove_exclusion()` and the Markdown export (new
  columns); new exclusion types `SCException.SKIP_REGISTRY` and
  `SCException.SKIP_CHANGE_TRACKING`. All the exclusion types of the console
  dialog checked on the ePO 5.10 lab.

**Changed**
- Solidcore certificates: comments on the Friendly Name column (always empty
  in the console, not exported) and on Issued To (the console cuts the name
  at the first comma, the export keeps the full certificate name).

### 1.0.1 - 2026-10-04

**Changed**
- Project status: Stable (README badge and PyPI classifier "Development
  Status :: 5 - Production/Stable").
- ENS Firewall Rules Markdown export: each rule or group detail card is one
  compact two-column table: "Status: Enabled | Action: Allow" (group:
  "Status | Direction") in its header line, then the other settings two per
  line as "**Label:** value" (e.g. Local networks | Local port), the group
  Location and number of Rules included; the platform notes (Windows & Linux
  only...) are given once before the cards. About 38 % fewer lines.

### 1.0.0 - 2026-10-04

**Added**
- System Information Reporter (SIR), new `sir` module: `SIRPolicies`
  (`policy.export productId=SIR_____1000`), `SIRPolicyCollectData` (Collect
  Data > General), `SIRPolicySetRegistry` and `SIRRegistryValue` (Set
  Registry > Registry General, with the registry backup bookkeeping of the
  console), with the Markdown export. Storage and labels checked on the ePO
  5.10 lab.
- `Policies.TYPE_ATTRIBUTE`: the EPOPolicyObject attribute used as policy
  type (`typeid`, or `featureid` for products whose categories share a
  typeid).

### 0.9.0 - 2026-10-04

**Added**
- Endpoint Security Web Control (ENS WC), new `es/wc` module:
  `ESWCPolicies` (`policy.export productId=ENDP_WP_1000`),
  `ESWCPolicyOptions`, `ESWCPolicyMessaging` (Enforcement Messaging),
  `ESWCPolicyBlockAllowList` and `WCSite`, `ESWCPolicyContentActions`,
  `ESWCPolicyBrowserControl` and `RatingActions` (Red/Yellow/Unrated
  actions), with the Markdown export. Storage and labels checked on the ePO
  5.10 lab (test policies changed in the console, then changed by the
  library and opened in the console).

### 0.8.0 - 2026-10-04

**Added**
- Endpoint Security Adaptive Threat Protection (ENS ATP), new `es/atp`
  module: `ESATPPolicies` (`policy.export productId=TIEClientMETA`),
  `ESATPPolicyOptions` (Options), `ESATPPolicyDAC` and `DACExclusion`
  (Dynamic Application Containment: containment rules, exclusions), with
  the Markdown export. Storage and labels checked on the ePO 5.10 lab (test
  policies changed in the console, then changed by the library and opened in
  the console).
- `Policies.new_policy()` also gives new IDs to the Dynamic Application
  Containment exclusions of a copy.
- Solidcore Rule Groups renaming: `SCRuleGroups.rename_rule_group()` (export
  files, user defined Rule Groups only) and `SCPolicy.rename_rule_group()`
  (reference in a policy export). Checked on the ePO 5.10 lab: a Rule Group
  renamed with `scor.rulegroup.rename` is renamed by ePO in the policies
  using it too.

### 0.7.0 - 2026-10-04

**Added**
- Markdown export of the Solidcore policies: Configuration (Client),
  Exception Rules, Application Control Options and Rules, Change Control
  Rules, Integrity Monitoring Rules (Windows and Unix), with the tabs,
  columns and labels of the ePO 5.10 console (exclusion types, filter
  conditions and events, Execution Control actions). The rules policies
  document their own rules (My Rules) and each shared Rule Group they use.
  Certificates show Issued To / Issued By / Expiration Date decoded from the
  PEM; the CLI password hashes are never written.
  `examples/policy_documentation.py` handles Solidcore exports too.

### 0.6.0 - 2026-10-04

**Added**
- Markdown export of the McAfee (Trellix) Agent policies: General (General,
  SuperAgent, Events, Logging, Updates, Peer-to-Peer, Deployment tabs),
  Repository (repository list, proxy - passwords are never written, only
  whether one is set), Troubleshooting, Custom Properties and Product
  Improvement Program, with the labels of the ePO 5.10 console. When a
  setting is stored twice, the value shown by the console is used (the
  section named after the console fields, e.g. AgentListenServer, rather than
  the "service" section, e.g. HttpServerService - checked on lab policies
  where they differ). `examples/policy_documentation.py` handles Trellix
  Agent exports too.

- Endpoint Security Storage Protection (ENSSP), new `es/sp` module: ICAP
  Policies (`ESSPPolicyICAP`: connection list, ICAP server configuration) and
  NetApp Policies (`ESSPPolicyNetApp`: filers list, administrator account,
  exclusions as `SPExclusion` by pattern/file type/file age), both with the
  Scan Items (file types to scan, options, heuristics), Performance, Actions
  and Reports tabs, and their Markdown export (console labels). The filer
  account must be defined in the console: ePO encrypts its password with
  the server key ("EPOAES128:..."), which the library can't decrypt nor
  produce; the library keeps it and can only enable/disable the account. Storage learnt from test policies changed in
  the ePO 5.10 console; a NetApp policy built by the library was imported
  and displayed as expected. `examples/policy_documentation.py` handles
  ENSSP exports too.

**Fixed**
- McAfee Agent General: 19 getters read the "service" section first (e.g.
  `get_relay_client()` read RelayService.EnableClient) and could return the
  opposite of what the console shows when the two sections differ; they now
  read the section of the console first (AgentListenServer, General,
  Network...). `set_sa_lazy_caching()` also writes
  AgentListenServer.bEnableLazyCaching (read by the console).
  `get_policy_enforcement_interval()` and `get_asci()` return an int.

**Security**
- Markdown export: `[` and `]` are now escaped too (`Policy.md_escape()`,
  `md_heading()`), and the ENS Firewall `get_content()`/`get_toc()` reports
  (used by `examples/firewall_rules.py`) escape the policy values (names,
  notes, networks, addresses, location criteria, ports). In 0.5.0 a policy
  value such as `![x](https://...)` or `[text](https://...)`, written in ePO
  by someone allowed to edit the policy, was rendered as a remote image
  (tracking pixel) or a link in the generated document.

### 0.5.0 - 2026-10-03

**Added**
- Exploit Prevention exclusions, full read/write: `EPExclusion` (one class
  method per Exclusion Type of the console: `illegal_api()`,
  `file_process_registry()`, `service()`, `network_ips()`, `linux()`, with
  the console checks) and `EPExecutable` (process / caller module: path, MD5,
  signer); `get_exclusions()`, `set_exclusions()`, `add_exclusion()`,
  `remove_exclusion()` on `ESTPPolicyExploitPrevention`. Every section kept
  by ePO for current and older clients is written. Storage learnt from
  exclusions created in the ePO 5.10 console; a policy built by the library
  was imported, displayed and exported back unchanged.
- Exploit Prevention Application Protection Rules, full read/write:
  `EPAppRule` (Name, Status, Inclusion Status, Executables as
  `APExecutable`, Notes) and `get_application_rules()`,
  `get_application_rule()`, `add_application_rule()`,
  `update_application_rule()`, `remove_application_rule()`. User-defined
  rules can be created and removed; for Trellix-defined rules, as in the
  console, everything but the name can be changed. Storage learnt from rules
  created in the ePO 5.10 console; a policy with a rule added and a
  Trellix-defined rule changed by the library was imported, displayed as
  expected and both rules were exported back unchanged (on import ePO gives
  new executable IDs and dates to the untouched Trellix-defined rules). See
  `examples/exploit_prevention.py`.
- ENS Firewall Rules, full read/write: the rule tree as objects (`FWRule`,
  `FWGroup` with its rules, location `FWLocation` and timed group setting,
  `FWNetwork` local/remote networks, `FWApplication` and `FWExecutable`,
  schedule, `FWAddress` for the console address forms) and `get_rules()`,
  `get_all_rules()`, `get_rule()`, `add_rule()`, `update_rule()`,
  `remove_rule()`, `move_rule()` on `ESFWPolicyRules`. Storage learnt from a
  rule, a group and a location created in the ePO 5.10 console; a policy
  built by the library (a group with a sub group, rules with networks,
  applications and schedule; console-made and Trellix rules changed, moved
  and removed) was imported, displayed as expected and exported back
  unchanged. The lengths are checked against the console fields (rule name
  100 characters...): ePO imports a longer rule name but the console then
  fails to open the policy. See `examples/firewall_rule_editing.py`.
- `examples/firewall_recon_detection.py`: adds network reconnaissance
  detection rules to an ENS Firewall Rules policy (MITRE ATT&CK T1046 /
  T1595.001): Block + "Treat match as intrusion" + Log rules at the end of the
  policy for the ports of the usual Windows Server, third-party and Linux
  services not already allowed, so that a port scan raises intrusion events
  in ePO without changing what the firewall blocks.
- Markdown export: the Exploit Prevention Exclusions table (console columns)
  and the details of each exclusion, instead of a count; the Executables
  column of the Application Protection Rules now shows the paths as the
  console does (`path;path;`).

**Fixed**
- ENS Firewall Rules: `load_policy()` crashed on an empty group (its sequence
  has no rule count); the schedule of the Markdown export and of
  `get_content()` showed Sunday when it wasn't selected (Sunday is the first
  bit of the WeekMask, not the last) and always 0:00 - 23:59 (the times are
  stored in ScheduleStart/End Hours/Minutes).
- `Policies.new_policy()`: a copy of an Exploit Prevention policy with
  exclusions kept their IDs, and the ePO console then failed to open the
  imported copy ("An unexpected error occurred."). The copy now gets new
  exclusion IDs.

**Security**
- Markdown export: policy, section, rule and subrule names written in headings
  are now escaped (new `Policy.md_heading()`), like the table cells already
  were. In 0.4.0 a name containing HTML (e.g. a rule named
  `<img src=x onerror=...>` by someone allowed to edit the policy in ePO)
  could be rendered as HTML by Markdown viewers that allow raw HTML.

### 0.4.0 - 2026-10-03

**Added**
- Markdown documentation of policies: `Policy.to_markdown()` /
  `save_markdown()` with Markdown helpers (`md_table`, `md_settings`...), for
  all ENS policy types; `examples/policy_documentation.py`.
- `ESTPPolicyAccessProtection` (ENS TP Access Protection) with an object model
  following the console workflow: `APRule`, `APSubRule`, `APTarget`,
  `APExecutable`, `APUserName` - rules are created, edited and removed
  (`add_rule()`, `update_rule()`, `remove_rule()`), exclusions too; checked end
  to end (built with the library, imported into ePO, shown as expected in the
  console, exported back unchanged); `examples/access_protection.py`.
  `ESTPPolicyOptions` (ENS TP Options: Quarantine Manager,
  Detection Exclusion, custom unwanted programs, Proactive Data Analysis) and
  `ESFWPolicyOptions` (ENS Firewall Options, including DNS Blocking, Defined
  Networks and Trusted Executables).
- `OASState` constants: the On-Access Scan "Disable and unregister with
  Windows Security Center" option (stored by ePO as `bOASEnabled` = 0 plus
  `bUnregisterWithWSC` = 1), supported by the `on_access_scan` property.

**Fixed**
- On-Demand Scan: the GTI sensitivity level getters/setters (`fs_`, `qs_`,
  `rs_gti_level`) looked for the setting in the wrong section (returned None,
  setter failed).
- ENS Firewall: `get_content()` crashed on ICMP rules without message type.
- Exploit Prevention: debug messages printed when loading a policy or applying
  a `SearchFilter`.

### 0.3.0 - 2026-10-03

**Added**
- Solidcore (Trellix Application and Change Control) support, in the new `sc`
  subpackage - all 13 Solidcore policy types:
  - `sc.gen`: `SCGENPolicyConfiguration` (Configuration (Client)) and
    `SCGENPolicyExceptionRules` (Exception Rules, Windows/Unix);
  - `sc.awl`: `SCAWLPolicyOptions` and `SCAWLPolicyRules` (Application
    Control Options and Rules, Windows/Unix);
  - `sc.cc`: `SCCCPolicyRules` (Change Control Rules, Windows/Unix);
  - `sc.fim`: `SCFIMPolicyRules` (Integrity Monitoring Rules, Windows/Unix);
  - `SCPolicies` (Solidcore export), whose `new_policy()` keeps the shared Rule
    Groups referenced by the template, and the `SCPolicy` base class giving
    generic access to Solidcore rules and Rule Groups;
  - `sc.rulegroups`: `SCRuleGroups` for the Solidcore Rule Groups files of the
    `scor.rulegroup.export` / `scor.rulegroup.import` API commands (create,
    copy, edit user defined Rule Groups), with `SCAWLRuleGroup`,
    `SCCCRuleGroup` and `SCFIMRuleGroup` sharing the policy tab methods, and
    `add_rule_group()` / `remove_rule_group()` to make a policy use a Rule Group.
- `SCException` and `SCReputation` constants classes.
- `SCPolicies.new_empty_policy()`: a new policy without any rule or Rule Group
  (the ePO "Blank Template" can't be exported).
- `examples/solidcore_application_control.py` and
  `examples/solidcore_rule_groups.py`, and three examples working directly
  against an ePO server with the "mcafee-epo" API client (optional dependency
  `pip install mcafee_epo_policies[examples]`): Application Control policy
  with one item per tab and a database Rule Group, Integrity Monitor policy
  with a "Windows Critical Config Files" Rule Group, and Change Control
  policy protecting some of those files.
- Tests built from real ePO 5.10 exports, each policy type also checked end to
  end: edited with the library, imported into ePO, exported back unchanged and
  displayed as expected in the ePO console.

### 0.2.0 - 2026-08-28

**Added**
- Full support for the remaining McAfee Agent policies: Troubleshooting,
  Custom Properties, and Product Improvement Program (Telemetry) - McAfee
  Agent policy coverage is now complete.
- `Language` constants class for the Troubleshooting policy's agent
  language selection (21 languages, LCID codes).
- Two new "Ransomware" options on the On-Access Scan policy:
  `detect_unknown_ransomware` and `ransomware_bait_files`.
- Read support and enable/disable control for Exploit Prevention
  Application Protection Rules (`application_rules_list`,
  `application_rule_get`, `get/set_application_rule_status`,
  `get/set_application_rule_inclusion_status`).
- `signatures_delete()` on the Exploit Prevention policy now actually
  removes an Expert Rule (previously a no-op).
- Validation when `signatures_add()` is called with an explicit `sig_id`:
  rejects IDs that are already in use or outside the valid range.
- Generic `get_indexed_list`/`set_indexed_list`/`get_indexed_table`/
  `set_indexed_table` helpers on the base `Policy` class, replacing eight
  independent hand-written implementations of the same
  "count + indexed settings" XML pattern.
- A `tests/` suite (pytest, 52 tests) built from real ePO policy exports,
  including two structural tests that check the whole package for
  property-wiring and mutable-default-argument mistakes.
- An `examples/` directory with runnable scripts for McAfee Agent,
  On-Access Scan, On-Demand Scan, and Firewall Rules reporting.

**Changed**
- Migrated packaging from `setup.py` to `pyproject.toml` (PEP 621), with an
  SPDX license expression.
- `mcafee_epo_policies.__version__` now reads the installed package
  version via `importlib.metadata`, instead of accidentally reporting the
  version of `setuptools`.

**Fixed**
- Six mismatched `property(getter, setter)` declarations in the McAfee
  Agent General policy that made several settings silently unreadable,
  unwritable, or both.
- `test_cert_authentication` is now correctly read-only, and its
  certificate files are located relative to the package instead of the
  caller's working directory.
- Shared mutable default arguments in `ExclusionList`, `OASProcessList`,
  `OASURLList`, and `ODSLocationList` that could leak state between
  unrelated instances.
- On-Access Scan `process_list`: a key mismatch (`TypeItem_x{row}` vs
  `TypeItem_{row}`) meant a process's risk level set via
  `set_process_list()` could never be read back.
- On-Access Scan `set_process_list([])` no longer leaves the policy in a
  state that crashes the next `get_process_list()` call.
- On-Demand Scan `fs_performance_level`/`qs_performance_level`: a typo
  (`_Performace`) meant the setting was never actually persisted.
- Saving a policy containing any non-ASCII character (accents, curly
  quotes, etc.) produced XML that neither this library nor ePO could
  reliably read back, due to an invalid encoding name.
- `signatures_get()` on the Exploit Prevention policy, previously
  non-functional for any signature.
- The indexed-list/table helpers could leave stale, duplicate settings
  behind when an ePO export already contained orphaned entries beyond
  their declared count - now cleaned up correctly on every write.

### 0.0.6 - 2020-11-25

Starting point for this changelog.

## Bugs and Feedback

For bugs, questions and discussions please use the [GitHub Issues](https://github.com/bmarandel/mcafee-epo-policies/issues).

## License

Copyright 2020 Benjamin Marandel

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License. 
