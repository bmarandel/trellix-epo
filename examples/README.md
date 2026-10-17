# Examples

Short, runnable scripts showing how to use `trellix_epo` against a
real policy exported from the ePO Policy Catalog. Each script expects its
own single-policy XML export (the same shape you get from extracting one
policy out of a `Policies` collection, or from `Policy.load_from_file`).

- **`agent_general_repository.py`** - McAfee Agent General and Repository
  policies: read/adjust communication intervals, reorder and enable/disable
  repositories.
- **`on_access_scan.py`** - ENS Threat Prevention On-Access Scan: read
  settings, raise GTI sensitivity, add a folder exclusion.
- **`on_demand_scan.py`** - ENS Threat Prevention On-Demand Scan: add a Full
  Scan location and a file type exclusion.
- **`firewall_rules.py`** - ENS Firewall: export the rule tree as a Markdown
  report.
- **`firewall_rule_editing.py`** - ENS Firewall Rules: print the rule tree,
  add a group with a location holding a rule (networks, application,
  schedule), move a rule into it, disable a rule and remove another one.
- **`firewall_recon_detection.py`** - ENS Firewall Rules: add network
  reconnaissance detection rules ("honey ports") at the end of a policy - one
  group per server profile (Windows Server roles and Microsoft products,
  third-party applications on Windows, Linux), one Block + "Treat match as
  intrusion" + Log rule per service not already allowed by the policy, the
  MITRE ATT&CK technique (T1046 by default, `--technique T1595.001` for
  internet facing servers) in the rule name shown by the ePO intrusion
  events. Run it again to replace the groups.
- **`access_protection.py`** - ENS Threat Prevention Access Protection: list
  the rules, create a user-defined rule (executables, user names, subrules),
  block a Trellix-defined rule and add an exclusion.
- **`policy_documentation.py`** - ENS, Trellix Agent, System Information Reporter, Solidcore and Trellix EDR with Forensics: from a
  full product export, write one Markdown document per policy (all ENS
  policy types) (console
  sections, settings tables, document control section for the review and
  approval). Takes the export file, then optionally the output folder and
  the author name.
- **`set-proc-exclusions.py`** - ENS Threat Prevention On-Access Scan: bulk
  utility that reads a plain text list of process names or full paths (one
  per line), adds each `.exe` as "Low Risk" in the policy's Process
  Settings, and makes sure the Low Risk profile is set to skip scanning
  entirely. Takes two arguments - see `python3 examples/set-proc-exclusions.py -h`.

- **`solidcore_application_control.py`** - Solidcore Application Control
  Rules (Windows): from a full Solidcore export, list the policies, then copy
  one (keeping its shared Rule Groups) with an updater, a trusted directory
  and an execution control rule added. Takes two arguments - the export file
  and the name of the policy to copy.

- **`solidcore_rule_groups.py`** - Solidcore Rule Groups: create a user
  defined Application Control Rule Group and make a policy use it; writes
  `rule_group.xml` (for `scor.rulegroup.import`) and `policy.xml` (for
  `policy.importPolicy`, after the Rule Group). Takes three arguments - the
  Solidcore export, the policy name and the new Rule Group name.

- **`edrf_best_practices.py`** - Trellix EDR with Forensics: from a full
  export (`policy.export productId=XCLIENT_META`), copies a policy of each
  type (General, Streaming, Detection, Investigation, Remediation - "My
  Default" unless another name is given) as "<policy> - Best Practices" and
  applies best practices (Self Protection, health reports, Low hash strategy,
  Host Remediation, containment page - title, message, optional logo, the
  HTML page shown on the device rebuilt as the console does with the
  extension 50.3 -, VPN and ePO server reachable when contained, Event
  streamer with events stored on disk, Sysmon events, a filter for a noisy
  process and two TLS syslog servers with failover, from the Event Streamer
  module user guide) and example exclusions (trusted backup/scanner tools, database
  folders, a registry key, disk image extensions). The example values are
  constants at the top of the script, to be replaced with those of your
  environment. Writes one file with the five policies, ready to import.
  Takes the export file, then optionally the policy name and the output file.

### Working directly against ePO (Solidcore, tags, client tasks)

These scripts export and import policies, Rule Groups and tags with the ePO Web
API client of the library (`EPOClient`, no other package needed) and the
shared helper `epo_connection.py` (command line options and connection).
Set the connection with `--url`/`--user` or the
`EPO_URL`/`EPO_USER`/`EPO_PASSWORD` environment variables (the password is
asked if not set); `--insecure` skips the server certificate check (lab
servers), `--dry-run` only writes the XML files. They can be run again: they
update what the previous run created.

- **`solidcore_app_control_sample.py`** - retrieves the Application Control
  Rules (Windows) policy "App CTRL Windows Sample" (created with the Trellix
  and Windows Update Rule Groups if missing), adds one example item in each
  tab (updaters, certificate with `--certificate`, installer, directory, user,
  executable files, exclusion, filters, execution control), creates a
  "Sample - Microsoft SQL Server" Rule Group and adds it to the policy.
- **`solidcore_fim_windows_critical_files.py`** - creates the Integrity
  Monitoring Rules (Windows) policy "FIM Windows Server 2019 Sample" from a
  blank policy, with the Trellix "Windows 2019 Server (64 bit) Base Filters"
  Rule Group and a new "Windows Critical Config Files" Rule Group: Windows
  configuration and data files worth monitoring (no executables), with the
  reasons documented in the script.
- **`solidcore_change_control_critical_files.py`** - creates the Change
  Control Rules (Windows) policy "CC Windows Critical Files Sample" from some
  files of "Windows Critical Config Files" (run the FIM script first):
  write-protects the name resolution files and the Run/RunOnce registry
  keys. Read-Protect is deliberately not used: it is disabled by default
  because of its impact on the system performance.
- **`tags_off_low_space.py`** - creates the "Policy Management" tag group
  and two tags in it: "OFF", a manual tag set by hand on the systems that
  must get the OFF policies, and "Low-Space", a criteria tag for the
  systems with less than 2 GB free on the C drive ("Free C Drive Space" of
  the Computer Properties, on systems that have a C drive: the others
  report 0 MB free), evaluated on each agent-server communication.
  `--run-criteria` evaluates it on all the systems at once; `--dry-run`
  writes the tag import file only. An existing "OFF" tag keeps its notes
  and systems.
- **`assignment_rule_suspicious.py`** - writes a Policy Assignment Rule file
  to import in the console (the Web API has no command for these rules):
  every system with the "Suspicious" tag (set by the helpdesk) gets an ENS
  Threat Prevention On-Access Scan policy (`--oas`) and Exploit Prevention
  policies (`--ep`, repeatable). `--check` checks the tag, group and policy
  names on the server first (an unknown tag would be dropped by the import,
  and the rule would apply to every system).
- **`client_tasks_ens_deployment.py`** - Trellix Agent "Product Deployment"
  task that installs Endpoint Security on Windows (Platform, Threat
  Prevention, Adaptive Threat Protection, Firewall, Web Control by default;
  `--modules` to choose), built from the packages of a repository branch
  with the modules they depend on. Run it again after a new ENS version is
  checked in: the task is replaced in place and keeps its assignments.
- **`client_tasks_product_update.py`** - Trellix Agent "Product Update" task:
  "Update All" by default, or `--packages` for selected packages (e.g. the
  content of the day), with the "Update in Progress" dialog box and postpone
  options; `--list-packages` shows what a task can select.
- **`client_tasks_solidcore_enable.py`** - Solidcore "SC: Enable" task for
  one kind of client (`--platform windows|windows-nt|linux|aix-hpux`):
  Change Control and/or Application Control, restart or limited activation,
  Inventory / Observe Mode, checked as in the console.
- **`client_tasks_solidcore_maintenance.py`** - Client tasks of a Solidcore
  maintenance window: "SC: Begin Update Mode <change>" (the change number as
  Workflow ID), "SC: End Update Mode" and "SC: Pull Inventory", checked
  against the server and imported into the Client Task Catalog; `--begin` /
  `--end` run them now on systems. `--markdown` writes the client tasks of
  the server as a Markdown document instead.

Run any script with `-h`-style usage by calling it without arguments, e.g.:

```
python3 examples/on_access_scan.py my_oas_policy.xml
```

Each script writes its result next to where you run it (e.g.
`oas_updated.xml`) - it never overwrites the input file.
