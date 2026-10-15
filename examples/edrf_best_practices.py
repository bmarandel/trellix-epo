#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
edrf_best_practices.py

Example for the trellix_epo package: from a Trellix EDR with
Forensics export (all the EDRF policies, as returned by the ePO API command
"policy.export productId=XCLIENT_META"), copy a policy of each type
(General, Streaming, Detection, Investigation, Remediation - "My Default"
unless another name is given) and apply some configuration best practices
and example exclusions. The copies, named "<policy> - Best Practices", are
saved in one file ready to be imported into ePO (Policy Catalog > Import,
or the API command policy.importPolicy). The source policies are not
changed.

Recommendations from the Trellix EDR with Forensics Product Guide (release
50.0.1):
- Always enable Self Protection (malware attacks target the security
  software first).
- File Hashing: the Low hash strategy is the recommended setting (fewest
  device resources).
- Disabled trace rules: change them only with Trellix Technical Support
  (the script leaves them untouched).
- Exclusions: full paths, FOLDERID_* paths or system environment variables;
  avoid user path variables (%appdata%, %userprofile%...).
- Containment: add the VPN address to the allowed addresses, so that
  contained hosts on a VPN keep reaching the Forensics (HX) servers.

Recommendations from the Endpoint Security Event Streamer Module User
Guide (release 2.0.35, the module behind the Event streamer of the
extension 50.3):
- Store the events on disk: memory only reduces the disk I/O but loses the
  events at an unexpected reboot, power failure or crash; it is meant for
  servers producing many events per second.
- Syslog servers: TLS, and a priority per server (P1 tried first, the next
  priority when it cannot be reached).
- Event logs: Sysmon (Microsoft-Windows-Sysmon/Operational) is the guide
  example of a custom event log.
- Event filters: drop the process creation events (4688) of a known
  executable (EventID + NewProcessName conditions, the guide example).
  "Allow" by default with "Exclude" conditions drops the events matching
  all of them (console help).
- Keep the module settings at their defaults unless the system produces a
  large number of events per second.

Containment page (extension 50.3): the title, the message (line breaks
kept) and an optional company logo are shown on the contained device; a
URL page must use an IP address (no DNS resolution on contained hosts).

The other values (product names, paths, addresses, numbers) are examples:
replace them with those of your environment (see the EXAMPLE_* constants)
and test the policies on a few endpoints before a wide deployment.

Usage:
    python3 edrf_best_practices.py <edrf_export.xml> [policy name] [output.xml]
"""

import sys

from trellix_epo import (EDRFPolicies, EDRFPolicyGeneral, EDRFPolicyStreaming,
                                 EDRFEventLog, EDRFEventFilter, EDRFFilterCondition,
                                 EDRFSyslogServer, EDRFPolicyDetection, EDRFRegistryExclusion,
                                 EDRFPolicyInvestigation, EDRFPolicyRemediation, EDRFAllowedIP)
from trellix_epo.policies import Policy

# ----------------------------------------------------------------------------
# Example values - replace them with those of your environment.
# ----------------------------------------------------------------------------
# A backup agent and a vulnerability scanner: trusted, very active tools whose
# activity floods the traces and the indicator detection without adding value.
EXAMPLE_WINDOWS_TOOLS = ['FOLDERID_ProgramFiles\\ExampleBackup\\backup-agent.exe',
                         'FOLDERID_ProgramFiles\\ExampleScanner\\scan-engine.exe']
EXAMPLE_LINUX_TOOLS = ['/opt/examplebackup/bin/backup-agent']
EXAMPLE_MAC_TOOLS = ['/Applications/ExampleBackup.app/Contents/MacOS/backup-agent']
# A database whose data files change all the time.
EXAMPLE_DATA_FOLDERS = ['C:\\ExampleDB\\Data', '/var/lib/exampledb']
EXAMPLE_REGISTRY_KEY = EDRFRegistryExclusion('LocalMachine', 'SOFTWARE\\ExampleBackup\\State',
                                             ['LastRun', 'Progress'])
# Large disk images: hashing them costs much for little investigation value.
EXAMPLE_HASHING_EXTENSIONS = ['.iso', '.vhd', '.vhdx', '.vmdk']
EXAMPLE_HASHING_PATHS_WINDOWS = ['FOLDERID_ProgramData\\ExampleBackup\\Cache']
EXAMPLE_HASHING_PATHS_LINUX = ['/var/opt/examplebackup/cache']
# Addresses a contained host must still reach: the ePO server (policies,
# agent wake-up) and the VPN gateway (product guide: contained hosts on VPNs).
EXAMPLE_ALLOWED_ADDRESSES = [EDRFAllowedIP('10.0.0.20', 'ePO server (example)'),
                             EDRFAllowedIP('vpn.example.com', 'VPN gateway (example)')]
EXAMPLE_VPN_CLIENTS = {'windows': ['C:\\Program Files\\ExampleVPN\\vpnclient.exe'],
                       'mac': ['/Applications/ExampleVPN.app/Contents/MacOS/vpnclient'],
                       'linux': ['/usr/sbin/openvpn']}
EXAMPLE_HELPDESK = 'the IT help desk (example: +33 1 23 45 67 89)'
# Containment page: the company name in the title and, optionally, its logo
# (a JPG, PNG or GIF file of 1000 KB at most; None for no logo).
EXAMPLE_COMPANY = 'Example Corp'
EXAMPLE_LOGO_FILE = None
# Event streamer: two syslog servers of the SOC (the second one if the first
# one cannot be reached), the Sysmon event IDs to stream (process creation,
# network connection, file creation, registry events) and the backup agent
# whose process creation events are not worth streaming.
EXAMPLE_SYSLOG_SERVERS = [EDRFSyslogServer('SIEM (primary)', 'siem1.example.com', 6514, 'P1',
                                           tls=True),
                          EDRFSyslogServer('SIEM (backup)', 'siem2.example.com', 6514, 'P2',
                                           tls=True)]
EXAMPLE_SYSMON_EVENT_IDS = '1, 3, 11, 12, 13, 14'
EXAMPLE_NOISY_PROCESS = 'C:\\Program Files\\ExampleBackup\\backup-agent.exe'


def general(policy):
    """
    Self Protection, content updates, health reports and a bounded CPU usage.
    """
    policy.set_option('self_protection', '1')           # product guide: always
    policy.set_option('content_updates', '1')
    policy.set_option('content_update_interval', 240)
    policy.set_option('health_report', '1')              # "Show Advanced" settings
    policy.set_option('health_interval', 15)
    policy.set_option('cpu_limit', 50)                    # example: limit the acquisitions
    policy.set_option('logging', '1')
    policy.set_option('log_level', 'INFO')


def streaming(policy):
    """
    Traces sent to the DXL Broker, trusted tools excluded from the traces,
    Windows events streamed to the SOC syslog servers (Event streamer).
    """
    policy.set_option('trace', '1')
    policy.set_option('send_to_cloud', '1')
    policy.set_option('ioc_alerts', '1')
    policy.add_to_list('windows_process_exclusions', EXAMPLE_WINDOWS_TOOLS)
    policy.add_to_list('linux_process_exclusions', EXAMPLE_LINUX_TOOLS)
    policy.add_to_list('mac_process_exclusions', EXAMPLE_MAC_TOOLS)
    if 'event_streamer' not in policy.OPTIONS:                # library older than 50.3
        return
    policy.set_option('event_streamer', '1')
    policy.set_option('events_in_memory', '0')                # guide: no loss at a reboot
    # Event logs: the extension defaults plus Sysmon (guide example).
    if 'Sysmon' not in [log.key() for log in policy.get_table('event_logs')]:
        policy.add_to_table('event_logs', EDRFEventLog(
            'Sysmon', 'Microsoft-Windows-Sysmon/Operational', EXAMPLE_SYSMON_EVENT_IDS))
    # Filter (guide example): process creations of the backup agent dropped.
    noisy = EDRFEventFilter('Backup agent process creation', 'ms_windows_event', [
        EDRFFilterCondition('EventID', '4688', 'exclude', 'match'),
        EDRFFilterCondition('NewProcessName', EXAMPLE_NOISY_PROCESS, 'exclude', 'match')],
        os='windows', default_action='allow')
    if noisy.key() not in [item.key() for item in policy.get_table('event_filters')]:
        policy.add_to_table('event_filters', noisy)
    # OS events need Real-Time Indicator Detection (see detection()): process
    # events only, the other types produce many more events.
    policy.set_option('os_process_events', '1')
    policy.set_option('events_to_syslog', '1')
    known = [server.key() for server in policy.get_table('syslog_servers')]
    for server in EXAMPLE_SYSLOG_SERVERS:
        if server.key() not in known:
            policy.add_to_table('syslog_servers', server)


def detection(policy):
    """
    Real-Time Indicator Detection on all event types, example exclusions.
    """
    for name in ['detection', 'network_events', 'dns_events', 'url_events']:
        policy.set_option(name, '1')
    policy.add_to_list('process_exclusions', EXAMPLE_WINDOWS_TOOLS[:1] + EXAMPLE_LINUX_TOOLS)
    policy.add_to_list('path_exclusions', EXAMPLE_DATA_FOLDERS)
    if EXAMPLE_REGISTRY_KEY not in policy.get_registry_exclusions():
        policy.add_registry_exclusion(EXAMPLE_REGISTRY_KEY)


def investigation(policy):
    """
    Low hash strategy, paused on battery, large images and caches not hashed.
    """
    policy.set_option('file_hashing', '1')
    policy.set_option('hash_strategy', 'low')             # product guide: recommended
    policy.set_option('hashing_power_saved', '1')
    for platform in ('windows', 'linux', 'mac'):
        policy.add_to_list(platform + '_hashing_extensions', EXAMPLE_HASHING_EXTENSIONS)
    policy.add_to_list('windows_hashing_paths', EXAMPLE_HASHING_PATHS_WINDOWS)
    policy.add_to_list('linux_hashing_paths', EXAMPLE_HASHING_PATHS_LINUX)


def remediation(policy):
    """
    Host Remediation, a containment page (title, message, logo), management
    and VPN reachable.
    """
    policy.set_option('host_remediation', '1')
    policy.set_option('display_message', '1')
    if 'message_source' in policy.OPTIONS:                    # extension 50.3
        policy.set_option('message_source', 'byhand')
        policy.set_option('containment_title', '{} - Security alert'.format(EXAMPLE_COMPANY))
        if EXAMPLE_LOGO_FILE:
            with open(EXAMPLE_LOGO_FILE, 'rb') as logo:
                policy.set_containment_image(EXAMPLE_LOGO_FILE.replace('\\', '/').split('/')[-1],
                                             logo.read())
    policy.set_option('containment_message',
                      'WARNING: Endpoint Contained by the security team.\n\n'
                      'Your device has been disconnected from the network: only the security '
                      'tools can still reach it.\nDo not turn it off.\n'
                      'Please contact {}.'.format(EXAMPLE_HELPDESK))
    policy.set_option('release_message', 'Your device has been reconnected to the network.')
    for platform, paths in EXAMPLE_VPN_CLIENTS.items():
        policy.add_to_list(platform + '_allowed_paths', paths)
    known = [address.address for address in policy.get_allowed_ips()]
    for address in EXAMPLE_ALLOWED_ADDRESSES:
        if address.address not in known:
            policy.add_allowed_ip(address)


STEPS = [(EDRFPolicyGeneral, general), (EDRFPolicyStreaming, streaming),
         (EDRFPolicyDetection, detection), (EDRFPolicyInvestigation, investigation),
         (EDRFPolicyRemediation, remediation)]


def main():
    if len(sys.argv) not in (2, 3, 4):
        print('Usage: python3 edrf_best_practices.py <edrf_export.xml> [policy name] '
              '[output.xml]', file=sys.stderr)
        return 1
    name = sys.argv[2] if len(sys.argv) >= 3 else 'My Default'
    output = sys.argv[3] if len(sys.argv) == 4 else 'edrf_best_practices.xml'

    with open(sys.argv[1], 'rb') as export_file:
        policies = EDRFPolicies(export_file.read())

    result = None
    for policy_class, apply in STEPS:
        template = name if policies.contain(policy_class.TYPE, name) else 'My Default'
        if template != name:
            print('{}: no policy "{}", "My Default" used.'.format(policy_class.TYPE, name))
        new_name = '{} - Best Practices'.format(template)
        new_policy = policies.new_policy(policy_class.TYPE, new_name, template=template)
        if new_policy is None:
            print('{}: no policy "{}" in the export, skipped.'.format(policy_class.TYPE, template),
                  file=sys.stderr)
            continue
        policy = policy_class(new_policy)
        apply(policy)
        print('{:13} "{}" -> "{}"'.format(policy_class.TYPE, template, new_name))
        # One file for all the policies: EPOPolicySettings first, then EPOPolicyObject.
        if result is None:
            result = policy.root
        else:
            objects = result.findall('EPOPolicyObject')
            for element in policy.root.findall('EPOPolicySettings'):
                result.insert(list(result).index(objects[0]), element)
            for element in policy.root.findall('EPOPolicyObject'):
                result.append(element)

    if result is None:
        return 1
    # Saved by the library: characters out of ASCII as XML references (see Policy.get_xml_content).
    Policy(result).save_to_file(output)
    print('Saved to {} (import it in the ePO Policy Catalog).'.format(output))
    return 0


if __name__ == '__main__':
    sys.exit(main())
