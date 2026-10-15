# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2021 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class InternetProtocols,
                              MessageTypes,
                              MessageTypesv6
                              and NetworkProtocols.
"""

class InternetProtocols():
    """
    This class define the list of known Internet Protocols.
    Reference: IANA
    https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    """

    def __init__(self):
        self.ips = {
            '0': 'HOPOPT',
            '1': 'ICMP',
            '2': 'IGMP',
            '3': 'GGP',
            '4': 'IP',
            '5': 'ST',
            '6': 'TCP',
            '7': 'CBT',
            '8': 'EGP',
            '9': 'IGP',
            '10': 'BBN-RCC-MON',
            '11': 'NVP-II',
            '12': 'PUP',
            '13': 'ARGUS',
            '14': 'EMCON',
            '15': 'XNET',
            '16': 'CHAOS',
            '17': 'UDP',
            '18': 'MUX',
            '19': 'DCN-MEAS',
            '20': 'HMP',
            '21': 'PRM',
            '22': 'XNS-IDP',
            '23': 'TRUNK-1',
            '24': 'TRUNK-2',
            '25': 'LEAF-1',
            '26': 'LEAF-2',
            '27': 'RDP',
            '28': 'IRTP',
            '29': 'ISO-TP4',
            '30': 'NETBLT',
            '31': 'MFE-NSP',
            '32': 'MERIT-INP',
            '33': 'SEP',
            '34': '3PC',
            '35': 'IDPR',
            '36': 'XTP',
            '37': 'DDP',
            '38': 'IDPR-CMTP',
            '39': 'TP++',
            '40': 'IL',
            '41': 'IPv6-Over-IPv4',
            '42': 'SDRP',
            '43': 'IPv6-Route',
            '44': 'IPv6-Frag',
            '45': 'IDRP',
            '46': 'RSVP',
            '47': 'GRE',
            '48': 'MHRP',
            '49': 'BNA',
            '50': 'ESP',
            '51': 'AH',
            '52': 'I-NLSP',
            '53': 'SWIPE',
            '54': 'NARP',
            '55': 'MOBILE',
            '56': 'TLSP',
            '57': 'SKIP',
            '58': 'ICMPv6',
            '59': 'IPv6-NoNxt',
            '60': 'IPv6-Opts',
            '61': 'Any host internal protocol',
            '62': 'CFTP',
            '63': 'Any local network',
            '64': 'SAT-EXPAK',
            '65': 'KRYPTOLAN',
            '66': 'RVD',
            '67': 'IPPC',
            '68': 'Any distributed file system',
            '69': 'SAT-MON',
            '70': 'VISA',
            '71': 'IPCV',
            '72': 'CPNX',
            '73': 'CPHB',
            '74': 'WSN',
            '75': 'PVP',
            '76': 'BR-SAT-MON',
            '77': 'SUN-ND',
            '78': 'WB-MON',
            '79': 'WB-EXPAK',
            '80': 'ISO-IP',
            '81': 'VMTP',
            '82': 'SECURE-VMTP',
            '83': 'VINES',
            '84': 'TTP',
            '85': 'NSFNET-IGP',
            '86': 'DGP',
            '87': 'TCF',
            '88': 'EIGRP',
            '89': 'OSPFIGP',
            '90': 'Sprite-RPC',
            '91': 'LARP',
            '92': 'MTP',
            '93': 'AX.25',
            '94': 'IPIP',
            '95': 'MICP',
            '96': 'SCC-SP',
            '97': 'ETHERIP',
            '98': 'ENCAP',
            '99': 'Any private encryption scheme',
            '100': 'GMTP',
            '101': 'IFMP',
            '102': 'PNNI',
            '103': 'PIM',
            '104': 'ARIS',
            '105': 'SCPS',
            '106': 'QNX',
            '107': 'A/N',
            '108': 'IPComp',
            '109': 'SNP',
            '110': 'Compaq-Peer',
            '111': 'IPX-in-IP',
            '112': 'VRRP',
            '113': 'PGM',
            '114': 'Any 0-hop protocol',
            '115': 'L2TP',
            '116': 'DDX',
            '117': 'IATP',
            '118': 'STP',
            '119': 'SRP',
            '120': 'UTI',
            '121': 'SMP',
            '122': 'SM',
            '123': 'PTP',
            '124': 'ISIS',
            '125': 'FIRE',
            '126': 'CRTP',
            '127': 'CRUDP',
            '128': 'SSCOPMCE',
            '129': 'IPLT',
            '130': 'SPS',
            '131': 'PIPE',
            '132': 'SCTP',
            '133': 'FC',
            '134': 'RSVP-E2E-IGNORE',
            '135': 'Mobility Header',
            '136': 'UDPLite',
            '137': 'MPLS-in-IP',
            '138': 'MANET',
            '139': 'HIP',
            '140': 'Shim6',
            '141': 'WESP',
            '142': 'ROHC'
        }

    def get_name(self, ref):
        """
        Return the name of the protocol based on the reference id.
        """
        return self.ips.get(ref, 'None')

    def get_ref(self, name):
        """
        Return the referenced id of a protocol based on its name.
        """
        search = [key for key, value in self.ips.items() if value == name]
        return search[0] if len(search) > 0 else 'None'

class MessageTypes():
    """
    This class define the list of known ICMP Message Types.
    Reference: IANA
    https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
    """

    def __init__(self):
        self.mts = {
            '0': 'Echo Reply',
            '3': 'Destination Unreachable',
            '4': 'Source Quench',
            '5': 'Redirect',
            '6': 'Alternate Host Address',
            '8': 'Echo Request',
            '9': 'Router Advertisement',
            '10': 'Router Solicitation',
            '11': 'Time Exceeded',
            '12': 'Parameter Problem',
            '13': 'Timestamp',
            '14': 'Timestamp Reply',
            '15': 'Information Request',
            '16': 'Information Reply',
            '17': 'Address Mask Request',
            '18': 'Address Mask Reply',
            '30': 'Traceroute',
            '31': 'Datagram Conversion Error',
            '32': 'Mobile Host Redirect',
            '33': 'IPv6 Where-Are-You',
            '34': 'IPv6 I-Am-Here',
            '35': 'Mobile Registration Request',
            '36': 'Mobile Registration Reply',
            '37': 'Domain Name Request',
            '38': 'Domain Name Reply',
            '39': 'SKIP',
            '40': 'Photuris'
        }

    def get_name(self, ref):
        """
        Return the message type name based on the type id.
        """
        return self.mts.get(ref, 'None')

    def get_ref(self, name):
        """
        Return a type id based on the Message name.
        """
        search = [key for key, value in self.mts.items() if value == name]
        return search[0] if len(search) > 0 else 'None'

class MessageTypesv6():
    """
    This class define the list of known ICMPv6 Message Types.
    Reference: IANA
    https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
    """

    def __init__(self):
        self.mts = {
            '1': 'Destination Unreachable',
            '2': 'Packet Too Big',
            '3': 'Time Exceeded',
            '4': 'Parameter Problem',
            '128': 'Echo Request',
            '129': 'Echo Reply',
            '130': 'Multicast Listener Query',
            '131': 'Multicast Listener Report',
            '132': 'Multicast Listener Done',
            '133': 'Router Solicitation',
            '134': 'Router Advertisement',
            '135': 'Neighbor Solicitation',
            '136': 'Neighbor Advertisement',
            '137': 'Redirect Message',
            '138': 'Router Renumbering',
            '139': 'ICMP Node Information Query',
            '140': 'ICMP Node Information Response',
            '141': 'Inverse Neighbor Discovery Solicitation Message',
            '142': 'Inverse Neighbor Discovery Advertisement Message',
            '143': 'Version 2 Multicast Listener Report',
            '144': 'Home Agent Address Discovery Request Message',
            '145': 'Home Agent Address Discovery Reply Message',
            '146': 'Mobile Prefix Solicitation',
            '147': 'Mobile Prefix Advertisement',
            '148': 'Certification Path Solicitation Message',
            '149': 'Certification Path Advertisement Message',
            '151': 'Multicast Router Advertisement',
            '152': 'Multicast Router Solicitation',
            '153': 'Multicast Router Termination',
            '154': 'FMIPv6 Messages',
            '155': 'RPL Control Message',
            '156': 'ILNPv6 Locator Update Message',
            '157': 'Duplicate Address Request',
            '158': 'Duplicate Address Confirmation',
            '159': 'MPL Control Message',
            '160': 'Extended Echo Request',
            '161': 'Extended Echo Reply'
        }

    def get_name(self, ref):
        """
        Return the message type name based on the type id.
        """
        return self.mts.get(ref, 'None')

    def get_ref(self, name):
        """
        Return a type id based on the Message name.
        """
        search = [key for key, value in self.mts.items() if value == name]
        return search[0] if len(search) > 0 else 'None'

class NetworkProtocols():
    """
    This class define the list of known Network Protocols.
    Reference: IANA
    https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
    """

    def __init__(self):
        self.nps = {
            '2048': 'IPv4',
            '2054': '(806) Address Resolution Protocol (ARP)',
            '8192': '(2000) Cisco Discovery Protocol',
            '32821': '(8035) Reverse Address Resolution Protocol (RARP)',
            '32823': '(8037) IPX',
            '32824': '(8038) IPX (alternate)',
            '32832': '(8040) NetBIOS Frames (Microsoft NetBEUI)',
            '32923': '(809b) AppleTalk',
            '33011': '(80f3) AppleTalk Address Resolution Protocol (AARP)',
            '33024': '(8100) VLAN-tagged frame (IEEE 802.1Q)',
            '33079': '(8137) Novell IPX',
            '33080': '(8138) Novel IPX (alternate)',
            '34525': 'IPv6',
            '34887': '(8847) MPLS unicast',
            '34888': '(8848) MPLS with upstream-assigned label',
            '34915': '(8863) PPPOE Discovery Protocol',
            '34916': '(8864) PPPOE Session Protocol',
            '34958': '(888e) EAPOL'
        }

    def get_name(self, ref):
        """
        Return the name of the protocol based on the reference id.
        """
        return self.nps.get(ref, 'None')

    def get_ref(self, name):
        """
        Return the referenced id of a protocol based on its name.
        """
        search = [key for key, value in self.nps.items() if value == name]
        return search[0] if len(search) > 0 else 'None'
