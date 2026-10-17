# Trellix ePolicy Orchestrator Python Library (trellix-epo)

![PyPI](https://img.shields.io/pypi/v/trellix-epo)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Status](https://img.shields.io/badge/status-stable-brightgreen)
![License](https://img.shields.io/github/license/bmarandel/trellix-epo)
![Top language](https://img.shields.io/github/languages/top/bmarandel/trellix-epo)

## Overview

This library was created on 2020-10-26 and published on PyPI as
`mcafee-epo-policies` (18 releases, 0.0.1 to 1.2.0, 2020-10-26 to
2026-10-05); it continues as `trellix-epo` (`pip install trellix-epo`,
`import trellix_epo`) from version 2.0.0, with the whole History below.

This package provides a set of Python classes to read, inspect, and modify policy
documents exported from the Policy Catalog of Trellix (formerly McAfee)
ePolicy Orchestrator (ePO),
without needing to know the underlying XML schema. Each supported policy is
exposed as an object with named properties (e.g. `policy.asci = 15`) instead of
raw Section/Setting XML lookups. Policies can also be exported as a Markdown
document (`to_markdown()` / `save_markdown()`, see "Policy documentation"
below) to keep a documentation of the enforced security policies. A client of
the ePO Web API (`EPOClient`, see "ePO Web API" below) exports and imports the
policies directly from the ePO server.

## Supported policies

| Product | Policy | Status | Markdown report |
|---|---|---|---|
| Trellix Agent | General | Full read/write | Yes |
| Trellix Agent | Repository | Full read/write | Yes |
| Trellix Agent | Troubleshooting | Full read/write | Yes |
| Trellix Agent | Custom Properties | Full read/write | Yes |
| Trellix Agent | Product Improvement Program (Telemetry) | Full read/write | Yes |
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

Trellix Agent policy coverage is complete - all 5 Trellix Agent policy types are implemented.

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
pip install trellix-epo
```

## Usage

```python
from trellix_epo import TAPolicies, TAPolicyGeneral

# Load a Policies export (XML) from the ePO Policy Catalog
with open('EPOAGENTMETA_policies.xml', 'rb') as f:
    policies = TAPolicies(f.read())

# List the policies contained in the export
print(policies)                 # <TAPolicies: 5 policies>
print(policies.list())

# Extract one policy and wrap it for editing
policy_xml = policies.get_policy('General', 'My Custom Policy')
policy = TAPolicyGeneral(policy_xml)
print(policy)                   # <TAPolicyGeneral 'My Custom Policy'>
policy.get_info()               # name, product, category, typeid, server (+ counts)

# Read and change a setting through a property, instead of raw XML
print(policy.asci)
policy.asci = 15

# Save the edited policy, ready to re-import into ePO
policy.save_to_file('My Custom Policy - edited.xml')
```

Every policy object shows what it holds: its representation gives the name
and, for the policies with lists, their counts (e.g. `<ESFWPolicyRules 'Demo':
10 groups, 56 rules>`, `<ESTPPolicyExploitPrevention 'My Default': 653
signatures, 186 application rules, 0 exclusions>`), and `get_info()` returns
the same as a dictionary (name, product and category as the console shows
them, typeid, featureid, ePO server and the counts), to check a policy right
after a load. The full human view is the Markdown export (`to_markdown()`).

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

The Trellix Agent General policy also holds the TLS cipher suites of the
agent 5.8.7 (extension 5.8.7), which no console page shows:
`TAPolicyGeneral.cipher_suites` (TLS 1.2) and `tls13_cipher_suites` read
them, and the Markdown export lists them. They are read only: the ePO
server manages them.

### ePO Web API

`EPOClient` connects to the ePO Web API (`https://<server>:8443/remote/...`)
with the Python standard library only, so that policies can be exported,
edited and imported back from the same script. The password stays in
memory: the library never writes it.

```python
from trellix_epo import EPOClient, EPOError

epo = EPOClient('https://epo.example.com:8443', 'admin', password)
# or EPOClient.from_environment() with EPO_URL, EPO_USER and EPO_PASSWORD;
# verify=False skips the certificate check (lab servers only), verify='ca.pem'
# uses a CA file.

# Export all the policies of a product: the policy class of the product comes
# back (ESTPPolicies for ENDP_AM_1000, SCPolicies for SOLIDCORE_META...)
policies = epo.export_policies('ENDP_AM_1000')
policy = ESTPPolicyOnAccessScan(policies.get_policy('EAM_General_Policies', 'My Default'))
# ... edit it, then import it back (force=True replaces a policy with the same name)
print(epo.import_policies(policies, force=True))

# Any Web API command, the JSON answers decoded; an ePO error raises EPOError
epo.find_policies('Threat Prevention')
epo.query('EPOLeafNode', '(select EPOLeafNode.NodeName)', '(eq EPOLeafNode.ManagedState 1)')
epo.call('system.find', 'W2022', searchNameOnly=True)
print(epo.help('policy.find'))

# Solidcore Rule Groups (scor.rulegroup.* commands)
group = epo.export_rule_group(SCRuleGroups.WINDOWS, SCRuleGroups.APPLICATION_CONTROL, 'Docker')
```

The client handles the ePO answers: the status line (`OK:` / `Error <n> :`),
the commands that ignore `:output=json` (`policy.export`, `scor.*`), the
`scor.*` errors sent in an `OK:` answer, and the file uploads of
`policy.importPolicy` and `scor.rulegroup.import`.

### ePO tags

The ePO Web API spreads the tags over many commands (`system.findTag`,
`system.exportTag`, `system.importTag`, `system.applyTag`,
`ComputerMgmt.createTagGroup`...) and has no command to create or edit a
tag. `epo.tags` gives one method per task, by tag and group names:

```python
from trellix_epo import EPOClient, Tag, TagCriteria

epo = EPOClient.from_environment()

# A manual tag, in a tag group (created with its parents if missing)
epo.tags.groups.create('Policy Management')
epo.tags.create(Tag('OFF', 'Systems that get the OFF policies', group='Policy Management'))
epo.tags.apply('OFF', ['W10ENTB01', 'W2022CORE'])     # names, IP addresses or ids
epo.tags.systems('OFF')                 # {'tagged': [...], 'excluded': [...]}
epo.tags.clear('OFF', 'W2022CORE')

# A criteria tag, written as in the console builder: the conditions on
# different properties are all required, the ones on the same property are
# joined with "and" or "or"
criteria = TagCriteria()
criteria.add('OS Platform', 'eq', 'Server').add('OS Platform', 'eq', 'Workstation')
criteria.set_grouping('OS Platform', 'or')
criteria.add('Free Disk Space', 'Greater than', '10 GB')
criteria.add('Last System Boot Time', 'olderThan', '2 weeks')
criteria.add('IP address', 'match_any', ['192.168.100.0/24', '10.0.0.1-10.0.0.9'])
criteria.add('Is 64-bit OS', 'eq', 'Yes')
epo.tags.save(Tag('Old servers', 'Not rebooted for 2 weeks', criteria,
                  evaluate_on_asci=True))
epo.tags.run_criteria('Old servers')    # number of systems affected

for tag in epo.tags.list():             # name, notes, criteria, group path, type...
    print(tag.name, tag.group, tag.tag_type, tag.criteria)
```

- **Criteria**: prefer the properties of the "Computer Properties" category
  (`EPOComputerProperties.*`): the product properties depend on the
  extensions installed on the server. The 120 system properties of the
  console builder are available (by key, by label, or "category: label"
  when several products share a label) with the operators of each
  property (`eq` or `Equals`...). The values are
  given as in the console and converted as the server does: sizes (`'10
  GB'`), durations (`'2 weeks'`, a month is 30 days), dates (`datetime`),
  IPv4/IPv6 addresses, ranges, subnets and lists, versions, languages and
  Yes/No lists by their label. `TagCriteria.from_squid()` reads the criteria
  of an existing tag back.
- **Checks** as in the console: tag name of 50 characters (unique, case
  ignored), text values of 100 or 255 characters, number of digits per
  size unit, durations from 1 to 9999, address lists of 2048 characters,
  tag group names without ``\/"[]:|<>+=;?*@`` and 5 levels at most.
- **Server pitfalls handled**: `save()` imports the tag, places it with the
  group id (the import file only has a group name, and an update without it
  moves the tag back to "My Tags") and reads it back, since the import
  answers "true" even when it ignored the tag. A tag can't be renamed (ePO
  has no command for it). `run_criteria(name, reset=True)` also removes the
  manual additions and exclusions.

### Policy Assignment Rules

The ePO Web API has no command for the Policy Assignment Rules: the console
only imports and exports them as an XML file (Policy > Policy Assignment
Rules > Actions > Import / Export). `trellix_epo.assignmentrules` reads that
file and writes it, byte for byte as the console exports it, so that a rule
can be written in code and imported by hand:

```python
from trellix_epo import AssignmentRule, AssignmentRuleList, PolicyAssignment, EPOClient

# Every system with the "Suspicious" tag (set by the helpdesk) gets harder policies
rule = AssignmentRule('Suspicious systems', 'My Organization',     # and its subgroups
                      tags=['Suspicious'],               # or [('OFF', False)], joiner 'and'/'or'
                      notes='Harder policies for the systems tagged by the helpdesk.')
rule.add_policy(PolicyAssignment.from_console('Endpoint Security Threat Prevention',
                                              'On-Access Scan', 'Suspicious'))
rule.add_policy('Suspicious EP', 'EAM_BufferOverflow_Policies', 'ENDP_AM_1000')
# or rule.add_policy(policy): a Policy of the library (typeid and featureid of the export)

rules = AssignmentRuleList()
rules.add(rule)
print(rules.check_server(EPOClient.from_environment()))   # [] or the problems found
rules.save_to_file('suspicious_rule.xml')                 # to import in the console

rules = AssignmentRuleList.load_from_file('Policy_Assignment_Rules.xml')   # console export
print(rules.to_markdown())
```

- **System Based rules**: System Tree groups by path (`'Workstations'`,
  `'My Organization\\Lost and Found\\(none)'`), with their subgroups or not
  (`subgroups=False`), any of the groups; tags "Has tag" / "Does not have
  tag" (by name, without the tag group), all of them or any. The rule name
  (128 characters), the notes (1024) and the policies are checked as in the
  wizard: one policy per category, several for the "Multi-slot" categories
  (Exploit Prevention, Web Control Block and Allow List and Content Actions,
  Solidcore rules, Configuration and Exception Rules).
- **Import behavior** (ePO 5.10 Update 7): a rule is matched by name; a new
  rule is added at the end (lowest priority) and enabled, an existing one is
  replaced and keeps its priority and its enabled or disabled state (the
  file has neither). Move a new rule with Actions > Edit Priority. A file
  with an unknown group or policy is refused as a whole; **a rule with an
  unknown tag is imported without its tag criteria** and then applies to
  every system of its groups: `check_server()` reads the groups, tags and
  policies of the server (read only) before the import.
- **User Based rules** (LDAP users and groups, ENS Firewall and Web Control
  only) are read and written back unchanged, not created: they need an LDAP
  server registered in ePO, not available on the test server.

### Client tasks

`epo.client_tasks` finds, exports, imports and runs the tasks of the Client
Task Catalog (`clienttask.*` commands). Each supported task type is an
object with the options of its console page and the console checks:

```python
from trellix_epo import (EPOClient, ClientTaskList, DeploymentItem, TADeploymentTask,
                         TAUpdateTask, SCBeginUpdateTask, SCRunCommandsTask)

epo = EPOClient.from_environment()

# Install the current System Information Reporter package of the repository
sir = epo.repository.get('SIR_____1000')         # Package of the Current branch
deploy = TADeploymentTask('Install SIR', [DeploymentItem.from_package(sir)],
                          platforms=['Windows'], allow_postpone=True, max_postpones=3)
update = TAUpdateTask('Update DAT', ['VSCANDAT1000', 'AMCORDAT2000'])     # None: all packages
window = SCBeginUpdateTask('SC: Begin Update Mode CHG0012345', workflow_id='CHG0012345')
status = SCRunCommandsTask('SC: Status', ['status'], requires_response=True)

tasks = ClientTaskList()
for task in (deploy, update, window, status):
    tasks.add(task)                       # checked as in the console
print(tasks.check_server(epo))            # [] or the problems found (read only)
epo.client_tasks.import_tasks(tasks)      # 4: a task of the same name is replaced
epo.client_tasks.run(window, ['W10ENTB01', 'W2022CORE'])     # "Run Client Task Now"

epo.client_tasks.applied('W10ENTB01')     # tasks applied to a system (up to date or not)
print(epo.client_tasks.export('SOLIDCORE_META').to_markdown())
```

- **Task types**: Trellix Agent Product Deployment (`TADeploymentTask`:
  target platforms, Install/Remove lines with language, branch and command
  line, automatic update, postpone) and Product Update (`TAUpdateTask`: all
  or selected packages, "Update in Progress" dialog, postpone), System
  Information Reporter File Assembly (`SIRFileRetrievalTask`), and the 11
  Solidcore tasks (`SCEnableTask` with the Windows, NT/2000 and Unix pages,
  `SCDisableTask`, `SCBeginUpdateTask` / `SCEndUpdateTask`,
  `SCBeginInventoryTask` / `SCEndInventoryTask`, `SCObserveModeTask`,
  `SCPullInventoryTask`, `SCCLIAccessTask`, `SCDebugInfoTask`,
  `SCRunCommandsTask`). Another task type is read and written back
  unchanged (`ClientTask`, sections and settings).
- **Checks** as in the console: task name of 149 characters, description of
  250, command line of 254, 1 to 999 postpones and seconds, postpone text of
  2047, the Engine with the DAT only, automatic update without Remove line
  and on the Current branch only, Workflow ID and comments of 100 characters
  (no comment without Workflow ID), Solidcore commands of 3000 characters,
  and the options of the Solidcore Enable page that need Application
  Control (scan priority, MP/SAU, limited activation, Inventory and Observe
  Mode, Pull Inventory).
- **Server behaviours handled** (ePO 5.10 Update 7): the Web API has no
  command to create, delete, assign or schedule a task: a task is created
  or replaced by an import (it keeps its id and assignments), assigned and
  scheduled in the console. The import skips without an error a task of an
  unknown type and a task whose name differs by case only: `import_tasks()`
  raises `EPOError` when fewer tasks were imported than sent, and
  `check_server()` finds the names that differ by case and the deployment
  packages missing from the repository or not made for the target
  platforms. The export keeps the sections of the deleted deployment lines:
  the library reads the counts and writes the lines again from scratch.
  `export()` gives the file byte for byte (Markdown with `to_markdown()`).

### Main Repository

`epo.repository` works on the packages of Software > Main Repository and on
the repositories (`repository.*` and `RepositoryMgmt.*` commands). The
packages are `Package` objects with the columns of the page (name, type,
version, minor version, check-in date, distribution type, branch), plus the
product id, language, platforms and the package they depend on.

```python
from trellix_epo import EPOClient, packages_to_markdown

epo = EPOClient.from_environment()

epo.repository.packages(branch='Current', package_type='DAT')   # [Package...]
platform = epo.repository.get('ENDP_GS_1070')     # Package of the Current branch, or None
platform.build_version                            # '26.8.022584' (Product Deployment tasks)
platform.dependency, platform.platform_labels     # None, ['Windows']
print(packages_to_markdown(epo.repository.packages()))

epo.repository.check_in('Stinger64-ePO.zip', branch='Evaluation')   # True
stinger = epo.repository.get('STIN_W649001', branch='Evaluation')
epo.repository.change_branch(stinger, 'Current', move=True)          # copy without move
epo.repository.delete(epo.repository.get('STIN_W649001'))
epo.repository.pull('Trellix HTTPS', ['AMCORDAT2000'])               # ['Current\\AMCORDAT2000\\...']
epo.repository.repositories(kind='mirror')        # source sites (Repository objects)
```

- `packages()` leaves out the ExtraDAT and SuperDAT entries of the Web API
  (no branch: they are not packages of the page); `get()` asks for the
  language when a package has several in the branch.
- `check_in()` uploads a ZIP (or takes a path on the server), replaces the
  package of the branch unless `force=False` (then EPOError); `pull()` is
  synchronous and returns the packages updated (`[]` for an unknown product
  id); `replicate()` needs a distributed repository.
- `repository.changeBranch` doesn't check the version it is given: the
  package of the source branch is copied or moved.
- `export_sites()` / `import_sites()` read and write the site list (a site
  of the same name is skipped without `overwrite`);
  `create_http_repository()` / `create_unc_repository()` create a
  distributed repository with its download and replication accounts.

### Policy assignments

`epo.policies` finds the policies of the Policy Catalog (`PolicyRef`: id,
name, product, category, the typeid of the export), exports and imports
them (`epo.export_policies()` / `epo.import_policies()` are shortcuts),
assigns them to System Tree groups and systems and reads the assignments,
as the Assigned Policies page of the System Tree.

```python
from trellix_epo import EPOClient, assignments_to_markdown, applied_to_markdown

epo = EPOClient.from_environment()

epo.policies.find(product_id='ENDP_AM_1000', category='Exploit Prevention')   # [PolicyRef...]
policy = epo.policies.get('Demo (Ransomware)')          # by name; give the category
                                                        # for "My Default"
epo.policies.assign(policy, group='My Organization\\Workstations')
epo.policies.assign(policy, systems=['PC01', 'PC02'])
epo.policies.reset('On-Access Scan', 'ENDP_AM_1000', group='Workstations')   # inherit again
print(assignments_to_markdown(epo.policies.assignments()))   # groups and systems that
                                                             # don't inherit a category
print(applied_to_markdown(epo.policies.applied('PC01')))     # policies the system has
```

- Assigning a policy breaks the inheritance of its category; in a
  multi-slot category (Exploit Prevention, Solidcore rules...) it adds a
  policy to the ones already assigned. `reset()` inherits the whole
  category again (every policy of a multi-slot one), and refuses a
  category the group or system already inherits (the server would answer
  "Invalid product ID").
- The Web API can't lock the inheritance, remove one policy of a
  multi-slot category, or read the policies of My Organization: use the
  console for these.
- `applied()` is empty for a system that never connected to the server.
- The policy categories (`policycatalog.CATEGORIES`, `MULTI_SLOT`) are the
  reference shared with the Policy Assignment Rules.

### Users and permission sets

`epo.users` lists, adds, changes and removes the ePO users (`User`: ePO
password, Windows account or certificate, administrator, disabled, allowed
IPs) and gives or takes their permission sets; `epo.permission_sets`
exports the permission sets with their roles (`PermissionSetList`, written
back as the server writes it) and imports new or changed sets.

```python
from trellix_epo import EPOClient, users_to_markdown

epo = EPOClient.from_environment()

epo.users.add('helpdesk', windows=('LAB', 'helpdesk'), full_name='Helpdesk',
              allowed_ips=['192.168.100.0/24'])
epo.users.add_permission_sets('helpdesk', ['Global Reviewer'])
epo.users.update('helpdesk', disabled=True, email='')      # '' clears a field
print(users_to_markdown(epo.users.list(with_permission_sets=True)))

sets = epo.permission_sets.export()
helpdesk = sets.get('Global Reviewer').copy('Helpdesk')
helpdesk.remove_role('role:softman.viewOnly')
epo.permission_sets.import_sets([helpdesk])                # checked in a new export
print(sets.to_markdown())                                  # roles by product
```

- A role is kept as its URI (`role:<product>.<category>.<right>`; the System
  Tree access `role:epo.dir.access` with its groups): the Web API doesn't
  give the console labels of the rights.
- The Web API can't delete a permission set (console only).
  `import_sets()` refuses a set whose name exists unless `overwrite=True`
  (the server would import it as "<name> (imported)").
- The server saves any text as allowed IPs: the library checks them
  (addresses or CIDR subnets). `remove_permission_sets()` refuses a set the
  user doesn't have (the server answers true).

### Queries

`squid.Query` builds the SQUID queries of `core.executeQuery` step by step
(a column without a table name is a column of the target), and
`epo.queries` runs them, runs the saved queries of Queries & Reports by name
or id, and reads the console labels of the columns.

```python
from trellix_epo import EPOClient, Query, rows_to_markdown
from trellix_epo.squid import eq, older_than, contains

epo = EPOClient.from_environment()

query = (Query('EPOLeafNode').select('NodeName', 'EPOComputerProperties.OSType', 'LastUpdate')
         .where(eq('ManagedState', 1), older_than('LastUpdate', days=30)).order('NodeName'))
rows = epo.queries.run(query)                          # or epo.query(query)
print(rows_to_markdown(rows, epo.queries.labels(query), 'Inactive systems'))

by_os = Query('EPOLeafNode').select('EPOComputerProperties.OSType') \
    .group('EPOComputerProperties.OSType').count()     # [{..., 'count': 2}, ...]
epo.queries.list(group='Agent Management')             # [SavedQuery...]
epo.queries.run('Inactive Agents')                     # a saved query, its own columns
```

- The Web API runs a saved query but doesn't give its SQUID (only the
  condition as the console writes it), and can't export, import or delete
  saved queries.
- The queries of another database (TIE Server) fail while that server is
  down ("The connection attempt failed.").
- The syntax, the operators of each column type and the traps are in the
  ePO Web API guide; only the common
  operators have a helper (`eq`, `ne`, `contains`, `starts_with`,
  `is_blank`, `newer_than`, `older_than`, `and_`, `or_`, `not_`), the others
  are written with `Condition(operator, column, *values)`.

### Server tasks

`epo.server_tasks` lists the server tasks (`ServerTask`: name, schedule
status, next run), runs one and waits for its end, enables or disables its
schedule, cancels a run and reads the Server Task Log (`TaskLogEntry` with
its subtasks and messages), the latest entries first.

```python
from trellix_epo import EPOClient, server_tasks_to_markdown, task_log_to_markdown

epo = EPOClient.from_environment()

print(server_tasks_to_markdown(epo.server_tasks.list()))
entry = epo.server_tasks.run('Update Main Repository', wait=True, timeout=1800)
entry.succeeded, entry.status_label, [message.text for message in entry.messages]
epo.server_tasks.disable('Inactive Agent Cleanup Task')       # the task read back
epo.server_tasks.cancel(entry.id)                             # a running task
print(task_log_to_markdown(epo.server_tasks.log(status='Failed', days=7)))
```

- The Web API can't create, change, import or delete a server task: the
  schedule and the actions are set in the console. A disabled task can
  still be run.
- `log()` reads the latest entries (`tasklog.listTaskHistory` gives the
  50 oldest of the period). A cancelled task ends with the status "Ended",
  after "Pending Termination" (from a few seconds to about half a minute on
  the lab, depending on what the task is doing).
- The library doesn't purge the Server Task Log (`tasklog.purge` without
  an age purges all of it).

### System Tree

`epo.systems` and `epo.groups` work on the System Tree (`system.*`,
`epogroup.findSystems` commands). A `System` has the 56 properties of
`system.find` under readable names (`name`, `description`, `custom1` to
`custom8`, `ip_address`, `os_type`, `tags`, `last_communication`,
`agent_version`, `group_id`...), each with its console label; a `Group` has
its id, path from My Organization, parent, type and notes.
`systemtree.PROPERTIES` is the reference for the system properties (SQUID
key, console label, kind, drop-down values): the Computer Properties of the
tag criteria are built from it, and `criteria_property('custom1')` gives the
`TagProperty` to tag the systems on that field.

```python
from trellix_epo import EPOClient, systems_to_markdown, groups_to_markdown

epo = EPOClient.from_environment()

epo.systems.find('W2022')                         # [System...], name, IP, MAC, user, tag...
system = epo.systems.get('PC01')                  # by name or id, or None
system.tags, system.managed, system.last_communication
print(systems_to_markdown(epo.systems.find()))    # the columns of the Systems page
for system in epo.systems.all():                  # every system, by batches (fewer fields)
    print(system.name, system.os_type)

servers = epo.groups.create('My Organization\\Servers\\Paris')     # Group, parents too
epo.systems.add(['SRV01', 'SRV02'], servers)      # unmanaged until an agent connects
epo.systems.set_properties('SRV01', description='SQL Server', custom1='PROD')
epo.systems.move('SRV02', 'My Organization\\Servers')
epo.systems.delete('SRV02')

epo.groups.systems('Workstations', subgroups=True)                 # [System...]
print(groups_to_markdown(epo.groups.list()))
```

- Nothing is added to or moved into Lost and Found (or its subgroups):
  the server fills it with the systems deployed outside the console at
  their first connection; `add()`, `move()` and `groups.create()` refuse it.
- The Web API has no command to create, rename or delete a group:
  `groups.create()` imports a text file as New Systems > Import systems and
  System Tree structure does (a line ending with a backslash creates the
  group without a system); rename and delete groups in the console.
- `add()` refuses a name already in the System Tree (the server would
  ignore it without a message) and checks the systems are in the group
  after the import; it doesn't deploy the agent.
- `set_properties()` sets the Description and Custom 1 to 4: the Web API
  can't clear a field (the server ignores an empty value).
- A system id and a group id are two separate numbers: system 13 and group
  13 can both exist.
- `resort()` sends a system whose sorting is enabled (`move(...,
  auto_sort=True)`) and that matches no sorting criteria to Lost and Found:
  sort only the systems the criteria of the groups cover.

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

Available for all Trellix (McAfee) Agent policy types (General, Repository,
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
from trellix_epo import (ESTPPolicyAccessProtection, APRule, APSubRule, APTarget,
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
from trellix_epo import ESSPPolicies, ESSPPolicyNetApp, SPExclusion

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
from trellix_epo import ESCommonPolicies, ESCommonPolicyOptions, AACExclusion

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
from trellix_epo import ESATPPolicies, ESATPPolicyOptions, ESATPPolicyDAC, DACExclusion

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
from trellix_epo import (ESWCPolicies, ESWCPolicyOptions, ESWCPolicyBlockAllowList, WCSite,
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
from trellix_epo import (SIRPolicies, SIRPolicyCollectData, SIRPolicySetRegistry,
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
from trellix_epo import (FWRule, FWGroup, FWNetwork, FWApplication, FWExecutable,
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
from trellix_epo import SCPolicies, SCAWLPolicyRules, SCException

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
from trellix_epo import SCRuleGroups, SCAWLPolicyRules

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
from trellix_epo import (EDRFPolicies, EDRFPolicyGeneral, EDRFPolicyStreaming,
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

`trellix_epo.validators` holds address checks shared by the policy
classes, written as the regular expressions of the ePO console extensions so
that a class refuses exactly what its console refuses: `is_ipv4()`,
`is_ipv6()` (every short form, link-local zone, IPv4 mapped), `is_hostname()`
(a DNS name with a domain) and `is_ip_or_hostname()`.

```python
from trellix_epo.validators import is_ip_or_hostname

is_ip_or_hostname('fd00::10')       # True
is_ip_or_hostname('localhost')      # False: the console wants a domain
```

## Examples

The [`examples/`](examples/) directory has short, runnable scripts covering
Trellix Agent (General/Repository), ENS Threat Prevention (On-Access Scan,
On-Demand Scan, process exclusions), ENS Firewall (Rules reporting and editing), and
Solidcore (Application Control, Integrity Monitor and Change Control policies,
Rule Groups - some of them working directly against an ePO server), Trellix
EDR with Forensics (best practices and example exclusions applied to copies of
the policies) and client tasks (ENS deployment from the repository, product
update, Solidcore activation and a Solidcore maintenance window) and the
System Tree (groups and systems from a CSV list, Markdown report), the
policy assignments (Markdown report) and the server tasks (run and wait).

## Documentation

There is no separate documentation site yet; every class and method has a
docstring describing which ePO UI setting it maps to.

## Requirements

Python 3.8 or later.

## History

### 2.1.0 - 2026-10-18

**Added**
- `get_info()` on every policy: name, product and category (console
  labels), typeid, featureid, ePO server and the counts of the policy type
  (Firewall groups and rules, Exploit Prevention signatures, application
  rules and exclusions, Access Protection and DAC rules and exclusions,
  On-Access Scan processes, On-Demand Scan locations, ENS Common
  exclusions, Web Control sites, Solidcore rules and Rule Groups, Trellix
  Agent repositories, SIR registry queries, files, folders and values), and
  on the policy exports (`Policies`): server, number of policies by type.
- One representation for every policy and every export, built from
  `get_info()`: `<ESFWPolicyRules 'Demo': 10 groups, 56 rules>`,
  `<ESTPPolicies: 12 policies>` (it replaces the three former styles).

**Removed (breaking)**
- The display code written before the Markdown export, which the Markdown
  export now covers entirely: ENS Firewall Rules `print_info()`,
  `print_sequences()`, `get_sequences()`, `get_toc()` and `get_content()`
  (use `to_markdown()` / `save_markdown()`), ENS Exploit Prevention
  `print_info()` (use the representation or `get_info()`), and the
  text-table `__str__()` of `ExclusionList`, `OASProcessList`,
  `OASURLList`, `ODSLocationList` and `RepositoryList` (`print()` shows
  their representation; the lists are in the policy Markdown).

**Changed**
- Trellix Agent classes: the constructor parameter is
  `policy_from_tapolicies` and is optional, as in the other classes (create
  the object empty, then `load_from_file()`); the type error says "Trellix
  Agent".
- Examples `firewall_rules.py` and `agent_general_repository.py` use the
  representation and the Markdown export.

### 2.0.0 - 2026-10-17

**Moved** from `mcafee-epo-policies` (created 2020-10-26, last release 1.2.0)
to `trellix-epo`: PyPI project `trellix-epo`, import name `trellix_epo`,
GitHub repository `bmarandel/trellix-epo` (the old URLs redirect).
`mcafee-epo-policies` gets no new feature.

**Changed (breaking)**
- Package `mcafee_epo_policies` renamed `trellix_epo`.
- Trellix Agent: module `ma` renamed `ta` and its classes `McAfeeAgent*`
  renamed `TA*` (`TAPolicies`, `TAPolicyGeneral`, `TAPolicyRepository`,
  `TAPolicyTroubleshooting`, `TAPolicyCustomProps`, `TAPolicyTelemetry`),
  without aliases.
- ENS Common module `es/common` renamed `es/cm`.
- The `examples` extra (`mcafee-epo` package) is removed: the library has
  its own Web API client.

**Added**
- Trellix EDR with Forensics policies (`edrf`: General, Streaming,
  Detection, Investigation, Remediation; extension 50.3) with the Markdown
  export and `examples/edrf_best_practices.py`.
- Console field limits in every module: the length, number range and
  allowed characters of each console field are checked (the library refuses
  what the console refuses), with shared checks in `validators`.
- `EPOClient`, a client of the ePO Web API written with the standard
  library only (`call()`, `query()`, policy export and import, Solidcore
  Rule Groups), and on top of it one object per domain:
  - `epo.tags` and `epo.tags.groups`: tags with criteria written as in the
    console builder (`Tag`, `TagCriteria`);
  - `epo.client_tasks`: typed client tasks (Trellix Agent Product
    Deployment and Product Update, SIR, the 11 Solidcore tasks) with the
    console rules, run now, applied tasks;
  - `epo.repository`: packages of the Main Repository (check in, branch
    change, delete, pull, replicate) and repositories;
  - `epo.systems` and `epo.groups`: the System Tree (`System` with the
    properties of `system.find` and their console labels, `Group`; add,
    move, sort, delete, custom fields, group creation);
  - `epo.policies`: Policy Catalog, assignments to groups and systems,
    inheritance reset, applied policies (`PolicyRef`, `Assignment`,
    `AppliedPolicy`);
  - `epo.server_tasks`: server tasks (run and wait, enable, disable,
    cancel) and the Server Task Log, latest first;
  - `epo.queries`: SQUID queries built with `squid.Query`, saved queries
    of Queries & Reports, console labels of the columns;
  - `epo.users` and `epo.permission_sets`: users (password, Windows,
    certificate), permission sets exported and imported with their roles.
- Policy Assignment Rules (`assignmentrules`): the file of the console
  import and export (no Web API command), with `check_server()`.
- Trellix Agent 5.8.7: the agent-to-server TLS cipher lists (read only).
- Markdown tables for the new objects (systems, groups, assignments, tasks,
  task log, queries, users, permission sets).
- New examples: Web API connection, tags, assignment rule, client tasks
  (ENS deployment, product update, Solidcore enable and maintenance
  window), System Tree import, policy assignments report, server task run.
- Every server behaviour the library handles (silent "true" answers,
  hidden traps of the commands) was checked on an ePO 5.10 Update 7 lab and
  is written in the module docstrings.

**Fixed**
- Policies written with non-ASCII characters: written as XML character
  references (the Web API import reads UTF-8 as ISO-8859-1).
- Solidcore: the General_<n> sections (trusted directories saved by the
  8.4 console) are read as rules. SIR: odd-length REG_BINARY values are
  padded as the console does.

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

For bugs, questions and discussions please use the [GitHub Issues](https://github.com/bmarandel/trellix-epo/issues).

## License

Copyright 2020 Benjamin Marandel

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License. 
