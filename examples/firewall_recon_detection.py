#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
firewall_recon_detection.py

Example for the trellix_epo package: add network reconnaissance
detection rules ("honey ports") to an existing ENS Firewall Rules policy.

ENS Firewall blocks the traffic that no rule allows. A rule that blocks an
inbound connection to a well-known service port, with "Treat match as
intrusion" and "Log matching traffic" checked, doesn't change what is
blocked when it is the last rule of the policy: it only turns the
connection attempts to the services the server doesn't offer into
intrusion events in ePO - the typical footprint of a port scan:

- MITRE ATT&CK T1595.001 Active Scanning: Scanning IP Blocks (tactic
  TA0043 Reconnaissance), when the scan comes from outside;
- MITRE ATT&CK T1046 Network Service Discovery (tactic TA0007 Discovery),
  when it comes from a host already compromised on the internal network.

The technique ID (--technique, T1046 by default) is written in the rule
name, which is what the ePO Firewall intrusion event shows.

The script adds one group per server profile at the end of the policy:

- windows-microsoft: Windows Server roles and Microsoft server products
  (AD DS, DNS, DHCP, IIS, SQL Server, Exchange, RDS, WSUS, SCCM...);
- windows-thirdparty: third-party applications often found on Windows
  servers (Citrix, Oracle, SAP, VMware Horizon, backup, remote control,
  middleware...);
- linux: Linux server services (SSH, NFS, Samba, databases, containers,
  monitoring, configuration management...).

The ports already allowed inbound by an enabled rule of the policy are left
out (the rule would never match), as are the ports already covered by a
previous detection rule; the groups added by a previous run are replaced.
Check the result in a test policy first: an allowed service listening on a
port of these lists but allowed by no rule (the firewall blocks it anyway)
will raise an event for each connection.

Usage:
    python3 firewall_recon_detection.py <policy.xml> [--profile windows-microsoft]
        [--profile linux] [--technique T1595.001] [--output recon_policy.xml]
"""

import argparse
import sys

from trellix_epo import ESFWPolicyRules, FWRule, FWGroup

TCP, UDP = FWRule.TCP, FWRule.UDP

# (service, transport, ports) - ports as in the console: '22', '6000-6063'.
PROFILES = {
    'windows-microsoft': ('Windows Server (Microsoft)', [
        ('FTP / FTPS (IIS)', TCP, ['20', '21', '990']),
        ('SSH (OpenSSH Server)', TCP, ['22']),
        ('Telnet Server', TCP, ['23']),
        ('SMTP (IIS SMTP / Exchange)', TCP, ['25', '465', '587', '2525']),
        ('WINS', TCP, ['42']),
        ('WINS', UDP, ['42']),
        ('DNS Server', TCP, ['53']),
        ('DNS Server', UDP, ['53']),
        ('DHCP Server', UDP, ['67', '647']),
        ('TFTP / PXE (WDS)', UDP, ['69', '4011']),
        ('HTTP / HTTPS (IIS)', TCP, ['80', '443']),
        ('Kerberos', TCP, ['88', '464']),
        ('Kerberos', UDP, ['88', '464']),
        ('POP3 / IMAP (Exchange)', TCP, ['110', '143', '993', '995']),
        ('NTP (Windows Time server)', UDP, ['123']),
        ('RPC Endpoint Mapper', TCP, ['135']),
        ('NetBIOS', UDP, ['137', '138']),
        ('NetBIOS session', TCP, ['139']),
        ('SNMP', UDP, ['161', '162']),
        ('LDAP / Global Catalog', TCP, ['389', '636', '3268', '3269']),
        ('LDAP (CLDAP)', UDP, ['389']),
        ('SMB', TCP, ['445']),
        ('IKE / IPsec NAT-T (RRAS)', UDP, ['500', '4500']),
        ('L2TP (RRAS)', UDP, ['1701']),
        ('PPTP (RRAS)', TCP, ['1723']),
        ('RADIUS (NPS)', UDP, ['1645', '1646', '1812', '1813']),
        ('SQL Server', TCP, ['1433', '1434', '2382', '2383', '4022', '5022']),
        ('SQL Server Browser', UDP, ['1434']),
        ('KMS (Volume Activation)', TCP, ['1688']),
        ('MSMQ', TCP, ['1801', '2101', '2103', '2105']),
        ('MSMQ', UDP, ['1801', '3527']),
        ('NFS Server (Server for NFS)', TCP, ['111', '2049']),
        ('NFS Server (Server for NFS)', UDP, ['111', '2049']),
        ('iSCSI Target Server', TCP, ['3260']),
        ('Failover Clustering', TCP, ['3343']),
        ('Failover Clustering', UDP, ['3343']),
        ('Remote Desktop (RDP)', TCP, ['3389']),
        ('Remote Desktop (RDP)', UDP, ['3389']),
        ('RD Gateway (UDP transport)', UDP, ['3391']),
        ('SCCM Remote Control', TCP, ['2701']),
        ('SCOM agent / console', TCP, ['5723', '5724']),
        ('WinRM (PowerShell Remoting)', TCP, ['5985', '5986']),
        ('Windows Admin Center', TCP, ['6516']),
        ('Hyper-V Live Migration', TCP, ['6600']),
        ('Web Deploy (IIS management)', TCP, ['8172']),
        ('WSUS', TCP, ['8530', '8531']),
        ('AD Web Services', TCP, ['9389']),
        ('SCCM client notification', TCP, ['10123']),
        ('SharePoint service applications', TCP, ['808', '32843', '32844', '32845']),
        ('AD FS device authentication', TCP, ['49443']),
        ('Skype for Business / Lync SIP', TCP, ['5060', '5061']),
    ]),
    'windows-thirdparty': ('Windows Server (third-party applications)', [
        ('Citrix ICA / Session Reliability', TCP, ['1494', '2598']),
        ('Citrix HDX EDT', UDP, ['1494', '2598']),
        ('Citrix License Server', TCP, ['7279', '8082', '8083', '27000']),
        ('Citrix Provisioning Services', UDP, ['6890-6909', '6910-6930']),
        ('Citrix Provisioning Services SOAP', TCP, ['54321-54323']),
        ('Oracle Database (TNS listener)', TCP, ['1521', '1522', '2483', '2484']),
        ('Oracle Enterprise Manager', TCP, ['1158', '3938', '5500', '7803']),
        ('Oracle WebLogic', TCP, ['7001', '7002']),
        ('IBM Db2', TCP, ['50000']),
        ('IBM WebSphere', TCP, ['9043', '9060', '9080', '9443']),
        ('HCL Domino (Notes RPC)', TCP, ['1352']),
        ('SAP NetWeaver', TCP, ['3200-3299', '3300-3399', '3600-3699']),
        ('SAP start service', TCP, ['50013', '50014']),
        ('MySQL / MariaDB', TCP, ['3306', '33060']),
        ('PostgreSQL', TCP, ['5432']),
        ('MongoDB', TCP, ['27017-27019']),
        ('Redis', TCP, ['6379']),
        ('Elasticsearch', TCP, ['9200', '9300']),
        ('Memcached', TCP, ['11211']),
        ('Apache Tomcat (HTTP/AJP)', TCP, ['8009', '8080', '8443']),
        ('Java RMI registry', TCP, ['1099']),
        ('JBoss / WildFly management', TCP, ['9990']),
        ('RabbitMQ', TCP, ['5671', '5672', '15672']),
        ('Apache Kafka / ZooKeeper', TCP, ['2181', '9092']),
        ('VMware Horizon (PCoIP/Blast)', TCP, ['4172', '22443', '32111']),
        ('VMware Horizon (PCoIP/Blast)', UDP, ['4172', '22443']),
        ('VNC', TCP, ['5800', '5900-5903']),
        ('TeamViewer', TCP, ['5938']),
        ('TeamViewer', UDP, ['5938']),
        ('AnyDesk', TCP, ['7070']),
        ('Radmin', TCP, ['4899']),
        ('Veeam Backup & Replication', TCP, ['6160', '6162', '9392', '9401']),
        ('Veritas NetBackup / Backup Exec', TCP, ['1556', '6101', '6106', '10000', '13724',
                                                  '13782']),
        ('Zabbix agent / server', TCP, ['10050', '10051']),
        ('Nagios NRPE', TCP, ['5666']),
        ('Docker API', TCP, ['2375', '2376']),
    ]),
    'linux': ('Linux server', [
        ('FTP / FTPS', TCP, ['20', '21', '990']),
        ('SSH', TCP, ['22']),
        ('Telnet', TCP, ['23']),
        ('SMTP', TCP, ['25', '465', '587']),
        ('DNS (BIND)', TCP, ['53']),
        ('DNS (BIND)', UDP, ['53']),
        ('DHCP server', UDP, ['67']),
        ('TFTP', UDP, ['69']),
        ('HTTP / HTTPS', TCP, ['80', '443', '8080', '8443']),
        ('Kerberos', TCP, ['88', '464', '749']),
        ('Kerberos', UDP, ['88', '464']),
        ('POP3 / IMAP', TCP, ['110', '143', '993', '995']),
        ('rpcbind / NFS / mountd', TCP, ['111', '2049', '20048']),
        ('rpcbind / NFS / mountd', UDP, ['111', '2049', '20048']),
        ('NTP', UDP, ['123']),
        ('Samba (NetBIOS/SMB)', TCP, ['139', '445']),
        ('Samba (NetBIOS)', UDP, ['137', '138']),
        ('SNMP', UDP, ['161', '162']),
        ('XDMCP', UDP, ['177']),
        ('LDAP (OpenLDAP / 389 DS)', TCP, ['389', '636']),
        ('r-services (rexec/rlogin/rsh)', TCP, ['512-514']),
        ('Syslog', UDP, ['514']),
        ('Syslog over TCP/TLS', TCP, ['601', '6514']),
        ('CUPS / IPP', TCP, ['631']),
        ('rsync', TCP, ['873']),
        ('Squid proxy', TCP, ['3128']),
        ('iSCSI target', TCP, ['3260']),
        ('MySQL / MariaDB', TCP, ['3306', '33060']),
        ('Subversion / Git daemon', TCP, ['3690', '9418']),
        ('Salt master', TCP, ['4505', '4506']),
        ('PostgreSQL', TCP, ['5432']),
        ('Nagios NRPE', TCP, ['5666']),
        ('VNC', TCP, ['5900-5903']),
        ('X11', TCP, ['6000-6063']),
        ('Redis', TCP, ['6379']),
        ('Kubernetes API / kubelet / etcd', TCP, ['2379', '2380', '6443', '10250']),
        ('Ceph monitor', TCP, ['3300', '6789']),
        ('Oracle Database (TNS listener)', TCP, ['1521']),
        ('Puppet server', TCP, ['8140']),
        ('Cockpit', TCP, ['9090']),
        ('Prometheus node exporter', TCP, ['9100']),
        ('Elasticsearch', TCP, ['9200', '9300']),
        ('Webmin', TCP, ['10000']),
        ('Zabbix agent / server', TCP, ['10050', '10051']),
        ('Memcached', TCP, ['11211']),
        ('Docker API', TCP, ['2375', '2376']),
        ('GlusterFS', TCP, ['24007', '24008']),
        ('MongoDB', TCP, ['27017-27019']),
    ]),
}

GROUP_PREFIX = 'Recon detection - '
# Maximum length of a rule name in the console (a longer name is imported
# but the console then fails to open the policy).
NAME_MAX = 100


def port_set(ports):
    """
    Returns the port numbers of a console port list ('80', '1000-2000').
    """
    numbers = set()
    for port in ports:
        if '-' in port:
            first, last = port.split('-')
            numbers.update(range(int(first), int(last) + 1))
        elif port.strip().isdigit():
            numbers.add(int(port))
    return numbers


def port_list(numbers):
    """
    Returns a console port list ('80', '6000-6063') from port numbers.
    """
    ports, numbers = [], sorted(numbers)
    while numbers:
        first = last = numbers.pop(0)
        while numbers and numbers[0] == last + 1:
            last = numbers.pop(0)
        ports.append(str(first) if first == last else '{}-{}'.format(first, last))
    return ports


def allowed_ports(policy):
    """
    Returns the TCP and UDP ports allowed inbound by the enabled rules of the
    policy (outside the recon groups) - even when the rule is limited to some
    applications or networks - and the rules allowing all the inbound IP
    traffic of a transport protocol (any port, application and network).
    """
    allowed = {TCP: set(), UDP: set()}
    broad = []

    def walk(rules):
        for rule in rules:
            if not rule.enabled or rule.name.startswith(GROUP_PREFIX):
                continue
            if rule.is_group:
                walk(rule.rules)
            elif rule.action == FWRule.ALLOW and rule.direction in [FWRule.IN, FWRule.EITHER]:
                protocols = [rule.transport_protocol] if rule.transport_protocol else [TCP, UDP]
                for protocol in protocols:
                    if protocol not in allowed:
                        continue
                    if rule.local_ports:
                        allowed[protocol] |= port_set(rule.local_ports)
                    elif not (rule.applications or rule.local_networks or
                              rule.remote_networks) and \
                            (not rule.network_protocols or
                             set(rule.network_protocols) & {FWRule.IPV4, FWRule.IPV6}):
                        broad.append(rule.name.strip())
    walk(policy.get_rules())
    return allowed, sorted(set(broad))


def recon_group(key, technique, allowed, covered):
    """
    Returns the detection group of a profile; covered holds the ports
    already used by a previous detection rule.
    """
    title, services = PROFILES[key]
    group = FWGroup(GROUP_PREFIX + title, FWRule.IN,
                    notes='Added by firewall_recon_detection.py: inbound connection attempts '
                          'to services not offered by the server (MITRE ATT&CK T1595.001 '
                          'Active Scanning - TA0043 Reconnaissance; T1046 Network Service '
                          'Discovery - TA0007 Discovery). Keep this group at the end of the '
                          'policy.',
                    network_protocols=[FWRule.IPV4, FWRule.IPV6])
    skipped = []
    for service, protocol, ports in services:
        wanted = port_set(ports)
        numbers = wanted - allowed[protocol] - covered[protocol]
        label = 'TCP' if protocol == TCP else 'UDP'
        if wanted & allowed[protocol]:
            skipped.append('{} ({} {})'.format(service, label, ', '.join(
                port_list(wanted & allowed[protocol]))))
        if not numbers:
            continue
        covered[protocol] |= numbers
        ports = port_list(numbers)
        name = 'Recon {} - {} ({} {})'.format(technique, service, label, ', '.join(ports))
        if len(name) > NAME_MAX:
            # The ports stay in the rule and in its notes.
            name = 'Recon {} - {} ({})'.format(technique, service, label)
        group.rules.append(FWRule(
            name,
            FWRule.BLOCK, FWRule.IN, intrusion=True, log=True,
            notes='Connection attempt to {} ({} {}) not offered by this server: possible '
                  'network service scanning. MITRE ATT&CK {}.'.format(
                      service, label, ', '.join(ports), technique),
            network_protocols=[FWRule.IPV4, FWRule.IPV6], transport_protocol=protocol,
            local_ports=ports))
    return group, skipped


def main():
    parser = argparse.ArgumentParser(description='Add network reconnaissance detection rules '
                                                 'to an ENS Firewall Rules policy.')
    parser.add_argument('policy', help='ENS Firewall Rules policy (XML export)')
    parser.add_argument('--profile', action='append', choices=sorted(PROFILES),
                        help='server profile (can be repeated, all by default)')
    parser.add_argument('--technique', default='T1046',
                        help='MITRE ATT&CK technique ID written in the rule names '
                             '(default: T1046, e.g. T1595.001 for internet facing servers)')
    parser.add_argument('--output', default='fw_recon_detection.xml', help='output file')
    args = parser.parse_args()

    policy = ESFWPolicyRules()
    policy.load_from_file(args.policy)
    policy.load_policy()

    # Replace the groups of a previous run.
    for rule in policy.get_rules():
        if rule.is_group and rule.name.startswith(GROUP_PREFIX):
            policy.remove_rule(rule)

    allowed, broad = allowed_ports(policy)
    covered = {TCP: set(), UDP: set()}
    for key in args.profile or ['windows-microsoft', 'windows-thirdparty', 'linux']:
        group, skipped = recon_group(key, args.technique, allowed, covered)
        if group.rules:
            # At the end: only the traffic allowed by no other rule reaches it.
            policy.add_rule(group)
        print('{}: {} detection rule(s)'.format(group.name, len(group.rules)))
        for item in skipped:
            print('  already allowed by the policy, left out: {}'.format(item))
    if broad:
        print('Rules allowing a whole protocol inbound (the detection rules may never see '
              'this traffic): {}'.format(', '.join(broad)))

    policy.save_to_file(args.output)
    print('Updated policy written to {}'.format(args.output))
    return 0


if __name__ == '__main__':
    sys.exit(main())
