# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

r"""
This module defines the checks shared by the policy classes, written as the
console code (not the Python ipaddress module) so that a class refuses
exactly what its console refuses:

- MAX_SETTING_LENGTH: the ePO server keeps 3072 characters per setting
  (longer values are truncated, even by an import - checked on the lab with
  Trellix EDR with Forensics and ENS Common policies).
- is_ipv4 / is_ipv6 / is_hostname / is_ip_or_hostname: the rules of the
  Trellix EDR with Forensics extension 50.3 (Validation.js).
- check_setting_length / check_int / check_length: stored setting length,
  number ranges and text lengths of the console fields.
- is_orion_ipv4 / is_orion_ipv6 / is_orion_hostname / has_valid_macros:
  the rules of the ePO console core (OrionValidate) and of the path macro
  check shared by the Trellix Agent and ENS pages (IsValidMacro).
- is_ens_*: the rules of the ENS Threat Prevention pages (On-Access and
  On-Demand Scan, Access Protection), is_x500_name: the signer check of
  the ePO server.
- is_ep_* / is_linux_path: the rules of the Exploit Prevention dialogs.
- is_sc_*: the rules of the Solidcore dialogs (paths, updaters, trusted
  directories, Change Control, registry keys) and of the Application Control
  Options (Helpdesk information checked by the ePO server).
- is_sp_*: the rules of the ENS Storage Protection pages (addresses, filers,
  file types, NetApp exclusions).
- is_wc_*: the rules of the ENS Web Control pages (Options IP lists, landmark
  DNS name, Web Reporter URL, Block and Allow List site patterns).
- fw_* / is_fw_* / is_orion_ip_group: the rules of the ENS Firewall pages
  (rule editor IpAddress, ports, executable paths, locations, Options
  Defined Networks and DNS Blocking).

Each function documents what it checks with an example of a valid and of an
invalid value (doctest format, run by tests/test_validators.py).
"""

import re

MAX_SETTING_LENGTH = 3072       # characters kept by the ePO server for a setting

# Dotted IPv4 address; leading zeros are accepted (010.0.0.1).
IPV4 = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                  r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')

# DNS host name with two labels at least (localhost is refused), the last
# one starting with a letter (so 1.2.3.256 is neither an address nor a name).
HOSTNAME = re.compile(r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+'
                      r'([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$')

_IPV4_SEG = r'(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
_IPV4_END = r'({0}\.){{3,3}}{0}'.format(_IPV4_SEG)
_HEX = r'[0-9a-fA-F]{1,4}'
# IPv6 address in every short form (fd00::10, ::1...), with a zone index
# for the link-local addresses (fe80::1%eth0) and IPv4 mapped or embedded
# addresses (::ffff:10.0.0.1).
IPV6 = re.compile(
    r'^((' + _HEX + r':){7,7}' + _HEX +
    r'|(' + _HEX + r':){1,7}:'
    r'|(' + _HEX + r':){1,6}:' + _HEX +
    r'|(' + _HEX + r':){1,5}(:' + _HEX + r'){1,2}'
    r'|(' + _HEX + r':){1,4}(:' + _HEX + r'){1,3}'
    r'|(' + _HEX + r':){1,3}(:' + _HEX + r'){1,4}'
    r'|(' + _HEX + r':){1,2}(:' + _HEX + r'){1,5}'
    r'|' + _HEX + r':((:' + _HEX + r'){1,6})'
    r'|:((:' + _HEX + r'){1,7}|:)'
    r'|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}'
    r'|::(ffff(:0{1,4}){0,1}:){0,1}' + _IPV4_END +
    r'|(' + _HEX + r':){1,4}:' + _IPV4_END + r')$')


def is_ipv4(value):
    """
    Checks a dotted IPv4 address as the Trellix EDR with Forensics pages do
    (see IPV4): four numbers from 0 to 255, leading zeros accepted, no
    surrounding spaces.

    Valid / invalid (an octet over 255):

    >>> is_ipv4('10.0.0.1')
    True
    >>> is_ipv4('10.0.0.256')
    False
    """
    return bool(IPV4.search(str(value)))


def is_ipv6(value):
    """
    Checks an IPv6 address as the Trellix EDR with Forensics pages do (see
    IPV6): every short form, a zone index on link-local addresses, IPv4
    mapped or embedded addresses.

    Valid / invalid (three colons in a row):

    >>> is_ipv6('fe80::1%eth0')
    True
    >>> is_ipv6('fd00:::1')
    False
    """
    return bool(IPV6.search(str(value)))


def is_hostname(value):
    """
    Checks a DNS host name with a domain as the Trellix EDR with Forensics
    pages do (see HOSTNAME): two labels at least, the last one starting with
    a letter.

    Valid / invalid (no domain):

    >>> is_hostname('epo.example.com')
    True
    >>> is_hostname('localhost')
    False
    """
    return bool(HOSTNAME.search(str(value)))


def is_ip_or_hostname(value):
    """
    Checks the "IP Address or DNS Hostname" fields of the Trellix EDR with
    Forensics pages: an IPv4 address, an IPv6 address or a DNS host name.

    Valid / invalid (a space in a name):

    >>> is_ip_or_hostname('fd00::10')
    True
    >>> is_ip_or_hostname('my server.example.com')
    False
    """
    return is_ipv4(value) or is_ipv6(value) or is_hostname(value)


# ------------------------------ Field values ------------------------------
def check_setting_length(setting, value):
    """
    Checks that a value fits in a policy setting: the ePO server keeps
    MAX_SETTING_LENGTH (3072) characters per setting and silently drops the
    rest, even on import. Raises ValueError for a longer value (None is
    accepted: the setting is not written).

    Valid (nothing returned) / invalid (one character too many):

    >>> check_setting_length('Notes', 'a' * 3072)
    >>> check_setting_length('Notes', 'a' * 3073)
    Traceback (most recent call last):
    ...
    ValueError: Notes: 3072 characters max once stored (the ePO server truncates the rest; 3073 given).
    """
    if value is not None and len(str(value)) > MAX_SETTING_LENGTH:
        raise ValueError('{}: {} characters max once stored (the ePO server truncates the rest; '
                         '{} given).'.format(setting, MAX_SETTING_LENGTH, len(str(value))))


def check_int(label, value, minimum, maximum):
    """
    Checks the value of a console number field: a whole number (an int or a
    string of digits, with a leading minus) between minimum and maximum, both
    included. Returns it as an int, else raises ValueError (label names the
    field in the message).

    Valid (a string is converted) / invalid (out of range):

    >>> check_int('Port', '8081', 1, 65535)
    8081
    >>> check_int('Port', 0, 1, 65535)
    Traceback (most recent call last):
    ...
    ValueError: Port: enter a number between 1 and 65535: 0
    """
    if isinstance(value, bool) or not (isinstance(value, int) or
                                       (isinstance(value, str) and
                                        re.fullmatch(r'-?\d+', value.strip()))):
        raise ValueError('{}: a whole number is expected: {!r}'.format(label, value))
    number = int(value)
    if not minimum <= number <= maximum:
        raise ValueError('{}: enter a number between {} and {}: {}'.format(
            label, minimum, maximum, number))
    return number


def check_length(label, value, max_length, required=False):
    """
    Checks the value of a console text field: a string of max_length
    characters at most (the maxlength of the field), not blank when
    required. Returns it, else raises ValueError (label names the field in
    the message).

    Valid / invalid (a required field left blank):

    >>> check_length('Notes', 'Approved by the SOC', 256)
    'Approved by the SOC'
    >>> check_length('Name', '  ', 256, required=True)
    Traceback (most recent call last):
    ...
    ValueError: Name is required.
    """
    if not isinstance(value, str):
        raise ValueError('{}: a text is expected: {!r}'.format(label, value))
    if required and not value.strip():
        raise ValueError('{} is required.'.format(label))
    if len(value) > max_length:
        raise ValueError('{}: {} characters max ({} given).'.format(
            label, max_length, len(value)))
    return value


# ------------------------------ ePO console core (OrionValidate) ------------------------------
_OH = '[0-9A-Fa-f]{1,4}'
_OD = r'(\b((25[0-5])|(1\d{2})|(2[0-4]\d)|(\d{1,2}))\b)'
_OV4 = r'({0}\.){{3}}{0}'.format(_OD)
# OrionValidate.isValidIPv6String (no zone index, IPv4 mapped or embedded).
ORION_IPV6 = re.compile(
    '^((({h}:){{7}}{h})|(({h}:){{6}}:{h})|(({h}:){{5}}:({h}:)?{h})|(({h}:){{4}}:({h}:){{0,2}}{h})|'
    '(({h}:){{3}}:({h}:){{0,3}}{h})|(({h}:){{2}}:({h}:){{0,4}}{h})|(({h}:){{6}}{v4})|'
    '(({h}:){{0,5}}:{v4})|(::({h}:){{0,5}}{v4})|({h}::({h}:){{0,5}}{h})|(::({h}:){{0,6}}{h})|'
    '(({h}:){{1,7}}:))$'.format(h=_OH, v4=_OV4))
ORION_HOSTNAME_FORBIDDEN = ' ,~:!@#$%^&\'(){}'


def is_orion_ipv4(value):
    """
    Checks an IPv4 address as the ePO console core does
    (OrionValidate.isValidIPv4String, e.g. Trellix Agent relay servers):
    four dotted numbers up to 255, leading zeros and surrounding spaces
    accepted.

    Valid / invalid (three numbers only):

    >>> is_orion_ipv4(' 010.0.0.1 ')
    True
    >>> is_orion_ipv4('10.0.0')
    False
    """
    value = str(value).strip()
    return re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', value) is not None and \
        all(int(quad) <= 255 for quad in value.split('.'))


def is_orion_ipv6(value):
    """
    Checks an IPv6 address as the ePO console core does
    (OrionValidate.isValidIPv6String, see ORION_IPV6): short forms and IPv4
    mapped addresses, surrounding spaces accepted, but no zone index.

    Valid / invalid (a zone index):

    >>> is_orion_ipv6('::ffff:10.0.0.1')
    True
    >>> is_orion_ipv6('fe80::1%eth0')
    False
    """
    return ORION_IPV6.search(str(value).strip()) is not None


def is_orion_hostname(value):
    """
    Checks a host name as the ePO console core does
    (OrionValidate.isValidHostName, also isValidDomainName of the ENS pages):
    255 characters max once trimmed, none of space , ~ : ! @ # $ % ^ & ' ( )
    { }, not ending with . or -. A name without domain is accepted.

    Valid / invalid (a space inside):

    >>> is_orion_hostname('relay01.example.com')
    True
    >>> is_orion_hostname('relay 01')
    False
    """
    value = str(value).strip()
    return 0 < len(value) <= 255 and not any(char in value for char in ORION_HOSTNAME_FORBIDDEN) \
        and value[-1] not in '.-'


def has_valid_macros(path, macros):
    r"""
    Checks the <MACRO> parts of a path as the Trellix Agent and ENS pages do
    (IsValidMacro): the < and > are balanced, not nested, and each macro is
    in macros (the list of the product page).

    Valid / invalid (a macro unknown to the page):

    >>> has_valid_macros(r'<SYSTEM_DRIVE>\Repo', ['SYSTEM_DRIVE'])
    True
    >>> has_valid_macros(r'<FOO>\Repo', ['SYSTEM_DRIVE'])
    False
    """
    if path.count('<') != path.count('>'):
        return False
    end = 0
    while True:
        start = path.find('<', end)
        if start == -1:
            return path.find('>', end) == -1
        start += 1
        end = path.find('>', start)
        if end == -1:
            return False
        name = path[start:end]
        if not name or '<' in name or name not in macros:
            return False
        end += 1


# ------------------------------ ENS Threat Prevention pages ------------------------------
# Process names of On-Access Scan (g_processNameRegEx): an optional drive (or ?:),
# then names without \ / : " < > | separated by single backslashes.
ENS_PROCESS_NAME = re.compile(r'^(?:(?:[a-zA-Z?]:)(?=\\))?(?:\\?(?=([^\\/:"<>|]))\1+)+$')


def is_ens_process_name(name):
    r"""
    Checks a process of the On-Access Scan process lists (validateProcessItem):
    a Linux or Mac full path (starting with /), or a Windows process name or
    path (see ENS_PROCESS_NAME); surrounding spaces ignored.

    Valid / invalid (a | in the name):

    >>> is_ens_process_name(r'C:\Windows\notepad.exe')
    True
    >>> is_ens_process_name('note|pad.exe')
    False
    """
    name = str(name).strip()
    return bool(name) and (name.startswith('/') or ENS_PROCESS_NAME.match(name) is not None)


def is_ens_path(path, allow_percentage=True):
    r"""
    Checks a path of the ENS Threat Prevention pages (isValidPath of
    validation.js): scan exclusions and targets, Exploit Prevention caller
    modules and, with allow_percentage=False, Application Protection
    executables. Full paths (C:\..., ?:\..., \folder), UNC paths, an
    environment variable start (%VAR%\...), **\ or *\ anywhere paths and
    file names without folder are accepted; < > | " / and a colon other than
    the drive one are refused, as are partial paths (folder\file), double
    backslashes after the start, \\?\ and \\.\ and paths made of wildcards
    only.

    Valid / invalid (a partial path) / invalid without environment variables:

    >>> is_ens_path(r'%TEMP%\setup.exe')
    True
    >>> is_ens_path(r'folder\setup.exe')
    False
    >>> is_ens_path(r'%TEMP%\setup.exe', allow_percentage=False)
    False
    """
    text = str(path).strip()
    non_special = asterisks = backslashes = percents = 0
    is_unc = is_full = is_anywhere = False
    for index, char in enumerate(text):
        if char in '<>|"/':
            return False
        if char == '?':
            backslashes = 0
            if index == 1 and text[0] == '*':
                is_full = True
        elif char == '\\':
            if index == 0 and len(text) > 1 and text[1] != '\\':
                is_full = True
            if index == 1 and text[0] == '*':
                is_full = True
            backslashes += 1
            if backslashes > 1 and index > 1:
                return False
            if backslashes == 2:
                is_unc = True
            asterisks = 0
        elif char == '*':
            asterisks += 1
            if asterisks > 1 and index == 1:
                is_anywhere = True
            backslashes = 0
        elif char == ':':
            if index != 1 or text[2:3] != '\\':
                return False
            is_full = True
        else:
            if char == '%':
                if not allow_percentage:
                    return False
                percents += 1
            backslashes = asterisks = 0
            non_special += 1
    has_env_var = percents > 1 and text[:1] == '%'
    if not (is_anywhere or is_unc or is_full or has_env_var) and '\\' in text:
        return False
    if text.startswith('\\\\?\\') or text.startswith('\\\\.\\'):
        return False
    return non_special > 0


def is_ens_file_types(text):
    r"""
    Checks the typed list of file types of the On-Access and On-Demand Scan
    pages (validateFileTypes, "Specified file types"), without the ::: of
    "All files with no extension": none of / " | < > \ * and no : except a
    ::: item, not made of ? only. An empty list is accepted.

    Valid / invalid (a wildcard):

    >>> is_ens_file_types('doc,docx,xls?')
    True
    >>> is_ens_file_types('do*')
    False
    """
    text = str(text)
    if text == '':
        return True
    if any(char in text for char in '/"|<>\\*'):
        return False
    if text.count('?') == len(text):
        return False
    return all(token == ':::' or ':' not in token for token in text.split(' '))


def is_ens_exclusion_file_type(file_type):
    r"""
    Checks the file type of a scan exclusion (IsValidExclusionFileType):
    ::: (files with no extension), or an extension without dot and without
    / " | < > : \ *, not made of ? only.

    Valid / invalid (with the dot):

    >>> is_ens_exclusion_file_type('tmp')
    True
    >>> is_ens_exclusion_file_type('.tmp')
    False
    """
    file_type = str(file_type)
    if file_type == ':::':
        return True
    if file_type == '' or any(char in file_type for char in '/"|<>:.\\*'):
        return False
    return file_type.count('?') != len(file_type)


# Signer distinguished names: keywords accepted by the ePO server checks
# (/ENDP_AM_1000/ and /ENDP_FW_META/ExecutableValidateSignerName.do, the same
# rules, probed on the lab), plus OIDs.
X500_KEYWORDS = {'CN', 'C', 'L', 'S', 'ST', 'O', 'OU', 'T', 'IP', 'STREET', 'DC', 'DNQ',
                 'DNQUALIFIER', 'SURNAME', 'GIVENNAME', 'INITIALS', 'GENERATION', 'EMAIL',
                 'EMAILADDRESS', 'E', 'UID', 'SERIALNUMBER', 'POSTALCODE', 'POBOX',
                 'DESCRIPTION'}


def _split_unquoted(text, separators):
    r"""
    Helper of is_x500_name: splits text on the separators found outside
    double quotes and not escaped by a backslash; None if a quote is not
    closed.

    Valid (the quoted comma is kept) / invalid (a quote not closed):

    >>> _split_unquoted('CN="Contoso, Ltd", C=US', ',')
    ['CN="Contoso, Ltd"', ' C=US']
    >>> _split_unquoted('CN="Contoso', ',') is None
    True
    """
    parts, current, quoted, escaped = [], '', False, False
    for char in text:
        if escaped:
            current += char
            escaped = False
        elif char == '\\':
            current += char
            escaped = True
        elif char == '"':
            current += char
            quoted = not quoted
        elif char in separators and not quoted:
            parts.append(current)
            current = ''
        else:
            current += char
    return None if quoted else parts + [current]


def is_x500_name(name):
    """
    Checks the distinguished name of a signer (Access Protection and Exploit
    Prevention executables, "Signed by") as the ePO server does: relative
    names separated by , or ; (none empty), each KEYWORD=value (a keyword of
    X500_KEYWORDS, any case, or an OID such as 2.5.4.3 or OID.2.5.4.3),
    several of them joined by +; the values may be empty, quoted or contain
    escaped characters.

    Valid / invalid (a name without KEYWORD=):

    >>> is_x500_name('CN=Microsoft Corporation, O=Microsoft Corporation, C=US')
    True
    >>> is_x500_name('Microsoft Corporation')
    False
    """
    rdns = _split_unquoted(str(name), ',;')
    if rdns is None:
        return False
    for rdn in rdns:
        avas = _split_unquoted(rdn, '+')
        if avas is None:
            return False
        for ava in avas:
            key, equal, _ = ava.strip().partition('=')
            key = key.strip()
            if not equal or not (key.upper() in X500_KEYWORDS or
                                 re.fullmatch(r'(OID\.)?\d+(\.\d+)*', key, re.IGNORECASE)):
                return False
    return True


def is_ens_executable_path(path):
    r"""
    Checks the "File name or path" of an Access Protection executable
    (Windows) and of a Dynamic Application Containment exclusion (ENS ATP,
    VSECommon.js, same rule): a path starting with C:\, ?:\, *:\, **\ or \\server, without
    double backslash after it and without / " < > | (IsValidDriveLetterPath),
    or a file name without \ / " < > | (IsValidFilename) of
    VSECommon_CustomForAP.js.

    Valid / invalid (a double backslash inside the path):

    >>> is_ens_executable_path(r'**\setup.exe')
    True
    >>> is_ens_executable_path(r'C:\Tools\\setup.exe')
    False
    """
    path = str(path)
    if re.fullmatch(r'[^\\/"<>|]+', path):
        return True
    match = re.match(r'([a-zA-Z*?]:\\|\*\*\\|\\\\)', path)
    if not match:
        return False
    rest = path[match.end():]
    return not rest.startswith('\\') and '\\\\' not in rest and \
        not any(char in rest for char in '/"<>|')


def is_ens_parameter_path(path):
    r"""
    Checks a Files target of an Access Protection subrule (validateFilePath
    of the parameter dialog, Windows): no / * ? " | < > (IsValidPath), or a
    file name or path without / " < > | not starting with *\.

    Valid / invalid (starting with *\):

    >>> is_ens_parameter_path(r'C:\Data\*')
    True
    >>> is_ens_parameter_path(r'*\Data\a.txt')
    False
    """
    path = str(path)
    if not any(char in path for char in '/*?"|<>'):
        return True
    return re.fullmatch(r'[^/"<>|]+', path) is not None and not path.startswith('*\\')


# validateUserName of the Access Protection user name dialog (Windows):
# domain (63 characters) \ user without " / \ [ ] : ; | = , + ? < > @.
# Valid: CORP\jdoe; invalid: jdoe (the domain is required).
ENS_USER_NAME = re.compile('^[a-zA-Z0-9.][a-zA-Z0-9-.\u00C4\u00D6\u00DC\u00E4\u00F6\u00FC\\s]{0,61}'
                           '[a-zA-Z0-9\u00C4\u00D6\u00DC\u00E4\u00F6\u00FC]*\\\\'
                           '[^"/\\\\\\[\\]:;|=,+?<>@]+$')


# ------------------------------ ENS Exploit Prevention ------------------------------
# Fields of the Exploit Prevention exclusion dialog (EditXPExclusion.jsp).
# User or group SID. Valid: S-1-5-32-544; invalid: S-1-5 (no sub-authority).
EP_SID = re.compile(r'^S-[0-9]-([0-9]+-){1,14}[0-9]+$')
# validateUserName: the domain is optional.
# Valid: jdoe, CORP.LOCAL\j doe; invalid: j;doe.
EP_USER_NAME = re.compile('^([a-zA-Z0-9.][a-zA-Z0-9-.\u00C4\u00D6\u00DC\u00E4\u00F6\u00FC\\s]{0,61}'
                          '[a-zA-Z0-9\u00C4\u00D6\u00DC\u00E4\u00F6\u00FC]*\\\\)?'
                          '[^"/\\\\\\[\\]:;|=,+?<>@]+$')
# Group name without domain. Valid: Domain Users; invalid: CORP\Domain Users.
EP_GROUP_NAME = re.compile(r'^[^"/\\\[\]:;|=,+?<>@]+$')
# Hostname with * and ? wildcards. Valid: web-*.corp?; invalid: web_01.
EP_HOSTNAME = re.compile(r'^[a-zA-Z0-9*?.-]+$')
# Registry key or value under a known root.
# Valid: HKLM\Software\Contoso*; invalid: HKEY_LOCAL\Software.
EP_REGISTRY = re.compile(r'^(HKEY_LOCAL_MACHINE\\|HKLM\\|HKEY_CLASSES_ROOT\\|HKCR\\|'
                         r'HKEY_CURRENT_USER\\|HKCU\\|HKEY_USERS\\|HKU\\|HKEY_CURRENT_CONFIG\\|'
                         r'HKCC\\)([a-zA-Z0-9\s_@\-^!#.:/$%&+={}\[\]\\*])+$')
_EP_FILE_NAME = re.compile(r'^(((([a-zA-Z*?]:(\\(?!\\)))|%[^%]|(\*\*\\))'
                           r'(([^\\/"<>|]+(\\(?!\\)))|([^\\/"<>|]))*)|([^\\/"<>|]+))$')
# checkValidName of the Expert Rule dialog.
# Valid: Règle (test): a_b-c.d/e; invalid: Rule;1.
EP_EXPERT_RULE_NAME = re.compile("^[A-Za-z0-9\\-_:.'()/\u00C0-\u00FF\\s]+$")
EP_MAX_IP_LIST_LENGTH = 3072


def is_ep_file_paths(text):
    r"""
    Checks the "File name or path" of an Exploit Prevention exclusion
    process and the Target file (validateFilePath / isValidProcess): a
    comma-separated list where each item has none of / * ? " | < >
    (IsValidPath of VSECommon.js), or is a path (C:\..., ?:\..., %VAR...,
    **\...) or a file name without / " < > | and not starting with *\.

    Valid / invalid (starting with *\):

    >>> is_ep_file_paths(r'C:\Data\report.txt,%TEMP%\x.dll,**\setup.exe')
    True
    >>> is_ep_file_paths(r'*\setup.exe')
    False
    """
    for item in str(text).split(','):
        if not any(char in item for char in '/*?"|<>'):
            continue
        if item.startswith('*\\') or not _EP_FILE_NAME.fullmatch(item):
            return False
    return True


def is_linux_path(path):
    r"""
    Checks a Linux path of the ENS pages (isValidLinuxPath of validation.js,
    Exploit Prevention "Linux File - Process" exclusions): no backslash, not
    starting with //.

    Valid / invalid (a backslash):

    >>> is_linux_path('/opt/app/bin/*')
    True
    >>> is_linux_path(r'/opt\app')
    False
    """
    return '\\' not in path and not path.startswith('//')


def _js_trim(text):
    """
    Helper of the IP list check: removes the surrounding white spaces as the
    trim() of the console page.

    >>> _js_trim(' 10.0.0.1 ')
    '10.0.0.1'
    """
    return re.sub(r'^\s+|\s+$', '', text)


def _js_number(text):
    """
    Helper of the IP range check: Number(text) of JavaScript, used by the
    console to compare the bounds of an IPv6 range group (decimal, hex 0x..,
    empty = 0); None when JavaScript gives NaN.

    Valid / invalid (hexadecimal digits without 0x):

    >>> _js_number('0x10')
    16
    >>> _js_number('db8') is None
    True
    """
    text = _js_trim(text)
    if text == '':
        return 0
    if re.fullmatch(r'0[xX][0-9a-fA-F]+', text):
        return int(text, 16)
    if re.fullmatch(r'0[oO][0-7]+', text):
        return int(text, 8)
    if re.fullmatch(r'0[bB][01]+', text):
        return int(text, 2)
    if re.fullmatch(r'[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?', text):
        return float(text)
    return None


def _js_less(first, second):
    """
    Helper of the IP range check: Number(first) < Number(second) of
    JavaScript (False when one of them is NaN).

    Valid / invalid (hexadecimal groups are NaN for the console):

    >>> _js_less('1', '2')
    True
    >>> _js_less('a', 'f')
    False
    """
    first, second = _js_number(first), _js_number(second)
    return first is not None and second is not None and first < second


_EP_OCTET = r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'


def _ep_ipv4(text):
    """
    Helper of the IP list check: isValidIPv4String of the exclusion dialog,
    four numbers up to 255 (three digits at most), surrounding spaces
    accepted.

    Valid / invalid (four digits):

    >>> _ep_ipv4('010.0.0.1')
    True
    >>> _ep_ipv4('0010.0.0.1')
    False
    """
    return re.fullmatch(r'(?:{0}\.){{3}}{0}'.format(_EP_OCTET), _js_trim(text)) is not None


def _ep_ipv6(text):
    """
    Helper of the IP list check: isValidIPv6String of the exclusion dialog
    (the same rule as is_orion_ipv6).

    Valid / invalid (brackets):

    >>> _ep_ipv6('fd00::1')
    True
    >>> _ep_ipv6('[fd00::1]')
    False
    """
    return ORION_IPV6.search(_js_trim(text)) is not None


def _ep_cidr(text):
    """
    Helper of the IP list check: isValidCIDR of the exclusion dialog, an
    IPv4 address with a prefix of 1-32 or an IPv6 address with a prefix of
    1-128 (OrionValidate.isValidIpv4CidrSubnet / isValidIpv6CidrSubnet).

    Valid / invalid (prefix over 32):

    >>> _ep_cidr('10.0.0.0/8')
    True
    >>> _ep_cidr('10.0.0.0/33')
    False
    """
    parts = _js_trim(text).split('/')
    if len(parts) != 2:         # the console ignores a third part
        return False
    prefix = _js_trim(parts[1])
    if not re.fullmatch(r'-?[0-9]+', prefix):
        return False
    if is_orion_ipv4(parts[0]):
        return 1 <= int(prefix) <= 32
    return is_orion_ipv6(parts[0]) and 1 <= int(prefix) <= 128


def _ep_ip_range(text):
    """
    Helper of the IP list check: isValidIPRange of the exclusion dialog, an
    address or a range. IPv4 ranges are written a.b.c.d-e.f.g.h and the two
    ends compared as strings (so the console refuses 10.0.0.9-10.0.0.10);
    IPv6 ranges are written per group (2001-2003:db8::1428-1434:57ab) with
    decimal bounds.

    Valid / invalid (refused by the console string comparison):

    >>> _ep_ip_range('192.168.1.1-192.168.1.16')
    True
    >>> _ep_ip_range('10.0.0.9-10.0.0.10')
    False
    """
    if _ep_ipv4(text) or _ep_ipv6(text):
        return True
    colons = text.split(':')
    if '::' not in text and len(colons) == 1:
        dots = text.split('.')
        if len(dots) != 7:
            return False

        def part(item, upper):
            pieces = item.split('-')
            if len(pieces) == 2:
                return pieces[1] if upper else pieces[0]
            return item if len(pieces) == 1 else 'zzz'
        lower = '.'.join(part(item, False) for item in dots[:4])
        upper, start = '', ''
        for index in range(3, 7):
            pieces = dots[index].split('-')
            if len(pieces) == 2:
                start = pieces[1]
            else:
                upper += ('.' if index != 3 else '') + (dots[index] if len(pieces) == 1 else 'zzz')
        upper = start + upper
        if lower > upper:
            return False
        return _ep_ipv4(lower) and _ep_ipv4(upper)

    def group(item, upper):
        pieces = item.split('-')
        if len(pieces) == 2:
            return pieces[1 if upper else 0] if _js_less(pieces[0], pieces[1]) else 'zzz'
        return item if len(pieces) == 1 else 'zzzz'
    return all(_ep_ipv6(':'.join(group(item, upper) for item in colons)) for upper in (False, True))


def is_ep_ip_list(text):
    """
    Checks the "IP addresses" of an Exploit Prevention Network IPS exclusion
    (validateArgumentIPList): 3072 characters max, a comma-separated list of
    IPv4 or IPv6 addresses, CIDR subnets (see _ep_cidr) or ranges (see
    _ep_ip_range). The console stops checking at the first CIDR item; this
    check goes on with the next items.

    Valid / invalid (a host name is not accepted):

    >>> is_ep_ip_list('10.0.0.0/8, 192.168.1.1-192.168.1.16, fd00::1')
    True
    >>> is_ep_ip_list('10.0.0.1, server01')
    False
    """
    text = _js_trim(str(text))
    if len(text) > EP_MAX_IP_LIST_LENGTH:
        return False
    for item in text.split(','):
        item = _js_trim(item)
        if item and not (_ep_cidr(item) or _ep_ip_range(item)):
            return False
    return True



# ------------------------------ ENS Web Control ------------------------------
WC_MAX_IP_LIST_LENGTH = 16000   # characters of an Options IP list (refused from 16000)
WC_SITE_FORBIDDEN = '* <>\\,'   # site pattern characters refused (comma: list separator)
# Internal landmark DNS name (validateDomainName of the Options page).
WC_DOMAIN_NAME = re.compile(r'^((([A-Z]|[a-z]){1}((([A-Z]|[a-z]|[0-9]|\-)+)?([A-Z]|[a-z]|[0-9]){1})?)'
                            r'{1}|((([A-Z]|[a-z]){1}((([A-Z]|[a-z]|[0-9]|\-)+)?([A-Z]|[a-z]|[0-9])'
                            r'{1})?){1}((\.){1}([A-Z]|[a-z]){1}((([A-Z]|[a-z]|[0-9]|\-)+)?([A-Z]|'
                            r'[a-z]|[0-9]){1})?)+){1})$', re.IGNORECASE)
# parseUri 1.2.2 (Steven Levithan), used by the Web Reporter URL check.
_PARSE_URI = re.compile(r'^(?:(?![^:@]+:[^:@/]*@)([^:/?#.]+):)?(?://)?((?:(([^:@]*)(?::([^:@]*))?)?@)?'
                        r'([^:/?#]*)(?::(\d*))?)(((/(?:[^?#](?![^?#/]*\.[^?#/.]+(?:[?#]|$)))*/?)?'
                        r'([^?#/]*))(?:\?([^#]*))?(?:#(.*))?)')


def _wc_ip_range(text):
    """
    Helper of the Web Control IP lists: isValidIPRange of the Options page,
    an IPv4 or IPv6 address or a range written per octet or group
    (192.168.56-68.1-5, 2001-2003:db8::1), each range with a first value
    lower than the second (Number() of JavaScript).

    Valid / invalid (a range with equal bounds):

    >>> _wc_ip_range('192.168.56-68.1-5')
    True
    >>> _wc_ip_range('10.0.0.5-5')
    False
    """
    if _ep_ipv4(text) or _ep_ipv6(text):
        return True
    colons = text.split(':')

    def part(item, upper, invalid):
        pieces = item.split('-')
        if len(pieces) == 2:
            return pieces[1 if upper else 0] if _js_less(pieces[0], pieces[1]) else 'zzz'
        return item if len(pieces) == 1 else invalid
    if '::' not in text and len(colons) == 1:
        dots = text.split('.')
        if len(dots) != 4:
            return False
        return all(_ep_ipv4('.'.join(part(item, upper, 'zzz') for item in dots))
                   for upper in (False, True))
    return all(_ep_ipv6(':'.join(part(item, upper, 'zzzz') for item in colons))
               for upper in (False, True))


def is_wc_ip_list(text):
    """
    Checks the IP addresses to exclude from Web Control rating or blocking
    (validateAgumentIPList of the Options page): less than 16000 characters,
    a comma-separated list of IPv4 or IPv6 addresses, CIDR subnets (see
    _ep_cidr) or ranges (see _wc_ip_range). The console stops checking at
    the first CIDR item; this check goes on with the next items.

    Valid / invalid (a range written a.b.c.d-e.f.g.h):

    >>> is_wc_ip_list('172.16.0.0/16, 192.168.56-68.1-5, fd00::1')
    True
    >>> is_wc_ip_list('10.0.0.1-10.0.0.9')
    False
    """
    text = _js_trim(str(text))
    if len(text) >= WC_MAX_IP_LIST_LENGTH:
        return False
    for item in text.split(','):
        item = _js_trim(item)
        if item and not (_ep_cidr(item) or _wc_ip_range(item)):
            return False
    return True


def is_wc_gateway_ip_list(text):
    """
    Checks the default gateway and internal landmark IP addresses of the Web
    Control Interlock (validateGatewayIPList of the Options page): less than
    16000 characters, a comma-separated list of IPv4 or IPv6 addresses
    (OrionValidate.isValidIPString), no range nor subnet.

    Valid / invalid (a subnet):

    >>> is_wc_gateway_ip_list('10.0.0.254, fd00::1')
    True
    >>> is_wc_gateway_ip_list('10.0.0.0/8')
    False
    """
    text = _js_trim(str(text))
    if len(text) >= WC_MAX_IP_LIST_LENGTH:
        return False
    return all(not _js_trim(item) or is_orion_ipv4(item) or is_orion_ipv6(item)
               for item in text.split(','))


def is_wc_domain_name(name):
    """
    Checks the DNS name for internal landmark (validateDomainName of the Web
    Control Options page): labels of letters, digits and -, each starting
    with a letter and not ending with -.

    Valid / invalid (a label starting with a digit):

    >>> is_wc_domain_name('intranet.example.com')
    True
    >>> is_wc_domain_name('www.1example.com')
    False
    """
    return WC_DOMAIN_NAME.search(str(name)) is not None


def is_wc_reporter_url(url):
    """
    Checks the Web Reporter URL (isValidWebReporterURLConfig of the Web
    Control Options page, parseUri): no protocol or http, https, ftp, ftps
    followed by ://, a host name or IP address (OrionValidate), a port of
    1-65535 if any, and a path without : \\ " ` ! @ # $ % ^ & * = ; , < > ? |.

    Valid / invalid (a ; in the path):

    >>> is_wc_reporter_url('http://reporter.example.com:9121/')
    True
    >>> is_wc_reporter_url('http://reporter.example.com/a;b/')
    False
    """
    url = str(url)
    match = _PARSE_URI.match(url)
    protocol, authority, host, port, path = (match.group(index) or ''
                                             for index in (1, 2, 6, 7, 9))
    if protocol and not (protocol.lower() in ('http', 'ftp', 'https', 'ftps') and '://' in url):
        return False
    if not host or not (is_orion_hostname(host) or is_orion_ipv4(host) or is_orion_ipv6(host)):
        return False
    if ':' in authority and not (re.fullmatch(r'-?[0-9]+', port.strip()) and
                                 1 <= int(port) <= 65535):
        return False
    return not any(char in path for char in ':\\"`!@#$%^&*=;,<>?|')


def is_wc_site_pattern(pattern):
    """
    Checks a site pattern of the Web Control Block and Allow List
    (validatePattern of the dialogs and the server, which splits the Add
    entry on commas and line breaks and trims it): 3 characters at least,
    none of * < > \\ , or white space. The console accepts a tab inside a
    pattern, but the policy export writes it raw in an XML attribute, read
    back as a space (an invalid pattern) by the next import: refused here. No length limit but the 3072
    characters of a setting: the Add dialog has none, the Edit dialog
    (maxlength 245) keeps a longer pattern (checked on the lab with 400).

    Valid / invalid (a wildcard):

    >>> is_wc_site_pattern('www.example.com/path')
    True
    >>> is_wc_site_pattern('*.example.com')
    False
    """
    pattern = str(pattern)
    return len(pattern) >= 3 and not re.search(r'\s', pattern) and \
        not any(char in pattern for char in WC_SITE_FORBIDDEN)


# Solidcore console path checks (scor.validation of commonUtils.jsp, identical
# results on the Solidcore 8.4 lab for 62 cases). os is 'WIN' or 'UNIX'.
_SC_WIN_START = re.compile(r'(^[^/\\:*?"<>|]:\\)|(^\\\\)|(^\*$)|(^%[a-zA-Z0-9_ ]+(\([xX]{1}86\))?%(\\|$))')
_SC_CC_START = re.compile(r'(^[^/\\:*"<>|]:\\)|(^\\\\)|(^%[a-zA-Z0-9_ ]+(\([xX]{1}86\))?%(\\|$))')
_SC_UPDATER_BAD = re.compile(r'(^[/\\:*"<>|]:\\)|(^(\*){1})')
_SC_DIRECTORY = re.compile(r'^(\\\\[^\s\\]+|[A-Za-z]:\\|%([^=\s]|[^=]+[^=\s]+)%|(\\\\[^\s\\]+|[A-Za-z]:|'
                           r'%([^=\s]|[^=]+[^=\s]+)%)(\\[^/:"<>|\\]*[^/:"<>|\\. ])+)\\?\Z')
_SC_REGISTRY_ROOT = re.compile(r'(HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG|HKEY_CURRENT_USER|'
                               r'HKEY_LOCAL_MACHINE|HKEY_USERS|\\REGISTRY)', re.IGNORECASE)


def _sc_common(path):
    """
    Helper of the Solidcore Windows path checks (scor.common.validation):
    1024 characters at most, no \\.\\ , no \\\\ after the first character,
    not ending with \\. .

    >>> _sc_common('C:\\\\Tools\\\\.')
    False
    """
    return len(path) <= 1024 and '\\.\\' not in path and '\\\\' not in path[1:] and \
        not path.endswith('\\.')


def is_sc_path(path, os='WIN'):
    r"""
    Checks a path of the Solidcore dialogs (scor.validation.validatePath).
    Windows: 1024 characters at most, starting with a drive (C:\, ?:\), a
    network share (\\), an environment variable (%WINDIR%, %ProgramFiles(x86)%)
    or * alone; * only as a whole folder name (C:\*\a.exe) and never last;
    no / : ? " < > | after the drive, no \.\ nor \\ inside, not ending
    with \. . Unix: starting with /, without : ? < > |, * only as a whole
    folder name and never last (or * alone).

    Valid / invalid (a wildcard inside a name):

    >>> is_sc_path('C:\\Program Files\\*\\setup.exe')
    True
    >>> is_sc_path('C:\\Tools\\a*.exe')
    False
    """
    path = str(path)
    if path == '':
        return False
    if os == 'WIN':
        return len(path) <= 1024 and bool(_SC_WIN_START.search(path)) and \
            not re.search(r'((.\*)$)|((.\*\\)$)', path) and \
            not re.search(r'[/:?"<>|]', path[3:]) and \
            not re.search(r'([^\\]\*)|(\*[^\\])', path) and _sc_common(path)
    if path == '*':
        return True
    return path[0] == '/' and not any(char in path.strip() for char in ':?<>|') and \
        not re.search(r'((.\*)$)|((.\*/)$)', path) and not re.search(r'([^/]\*)|(\*[^/])', path)


def is_sc_updater_name(name, os='WIN'):
    r"""
    Checks an Updater By Name file name, parent or library of the Solidcore
    dialog (UpdaterWildCardValidation, Windows; any value on Unix): not
    starting with *, not only ? characters, see _sc_common.

    Valid / invalid (a leading wildcard):

    >>> is_sc_updater_name('setup?.exe')
    True
    >>> is_sc_updater_name('*setup.exe')
    False
    """
    name = str(name)
    if os != 'WIN':
        return True
    return not _SC_UPDATER_BAD.search(name) and not re.fullmatch(r'[?]+', name) and \
        _sc_common(name)


def is_sc_directory(path, os='WIN'):
    r"""
    Checks a Solidcore trusted directory (IsValidDomainUserPath, Windows;
    any value on Unix): a drive (C:\), a share (\\server) or an environment
    variable (%LOCALAPPDATA%), followed by folders not ending with a dot or a
    space, an optional final \, see _sc_common.

    Valid / invalid (no drive):

    >>> is_sc_directory('\\\\fileserver\\installers\\')
    True
    >>> is_sc_directory('Program Files\\App')
    False
    """
    path = str(path)
    if os != 'WIN':
        return True
    return bool(_SC_DIRECTORY.search(path)) and _sc_common(path)


def is_sc_cc_path(path, os='WIN'):
    r"""
    Checks a Change Control read/write protection file path (wildCardCCPolicy,
    Windows; any value on Unix): a drive (C:\, ?:\), a share (\\) or an
    environment variable, see _sc_common; wildcards are accepted.

    Valid / invalid (a relative path):

    >>> is_sc_cc_path('C:\\Data\\*.cfg')
    True
    >>> is_sc_cc_path('Data\\*.cfg')
    False
    """
    path = str(path)
    if os != 'WIN':
        return True
    return bool(_SC_CC_START.search(path)) and _sc_common(path)


def is_sc_registry_key(key):
    r"""
    Checks a Solidcore registry key (isRegistryValid of the Change Control
    and filter dialogs): a key of HKEY_CLASSES_ROOT, HKEY_CURRENT_CONFIG,
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_USERS or \REGISTRY (any case),
    * only as a whole key name and never last.

    Valid / invalid (no root key):

    >>> is_sc_registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\\*\\Run')
    True
    >>> is_sc_registry_key('SOFTWARE\\Vendor')
    False
    """
    key = str(key)
    return not re.search(r'((.\*)$)|((.\*\\)$)', key) and \
        not re.search(r'([^\\]\*)|(\*[^\\])', key) and _SC_REGISTRY_ROOT.match(key) is not None


def is_sc_file_name(name):
    """
    Checks a Solidcore process or parent process name
    (windowsFileNameCharactersValidater): without : ? < > | * " \\ / once
    trimmed.

    Valid / invalid (a path):

    >>> is_sc_file_name('powershell.exe')
    True
    >>> is_sc_file_name('C:\\\\Windows\\\\powershell.exe')
    False
    """
    return not any(char in str(name).strip() for char in ':?<>|*"\\/')


def is_sc_execution_path(path):
    r"""
    Checks the Path attribute of a Solidcore Execution Control rule
    (pathValidator): a Windows path (is_sc_path) without any *, and for a
    network path a valid file name character in third position.

    Valid / invalid (a wildcard):

    >>> is_sc_execution_path('C:\\Windows\\System32\\cmd.exe')
    True
    >>> is_sc_execution_path('C:\\*\\cmd.exe')
    False
    """
    path = str(path)
    return is_sc_path(path, 'WIN') and '*' not in path and \
        not (path.startswith('\\\\') and not is_sc_file_name(path[2:3]))



_SC_RELATIVE = re.compile(r'^([a-zA-Z]\:([^\\]+\\)*[^/:"\'<>|]+([^/:\'"<>|]+)\Z)|'
                          r'(([^\\]+\\)*[^/:"\'<>|]+([^/:\'"<>|]+)\Z)')


def is_sc_exclusion_value(value, field, os='WIN'):
    r"""
    Checks a value of the Solidcore exclusion dialog (validatePathForSkipList
    of Solidcore 8.4, compared on the lab). field is the input of the dialog:
    the exclusion type (its Process/File/Path/Volume/Registry box, e.g.
    'skipSolidification'), 'parent_' + the exclusion type for its Parent
    Process Name box, or 'library' for the Library Name box. Windows - all:
    required, 1024 characters, no \\ after the first character, * only
    after a \ (but for skipSolidification); skipFileOperation(_f) /
    skipDenyWrite / skipChangeTracking: ending with two characters out of
    / : " ' < > |; process_ctx_bypass and its parent: a file name (no
    \ / : * ? " < > |); skipSolidification: a drive or ?: path (folders not
    ending with a dot or a space); skipRegistry: is_sc_registry_key (the 8.4
    page itself fails on a registry value: isRegistryValid is missing).
    skipVolume has no rule of its own in 8.4 (8.3.2 required C: or C:\).
    Unix: required; skipSolidification without : * ? < > |.

    Valid / invalid (a relative path):

    >>> is_sc_exclusion_value('C:\\Program Files\\App\\', 'skipSolidification')
    True
    >>> is_sc_exclusion_value('Program Files\\App', 'skipSolidification')
    False
    """
    value = str(value)
    if value == '':
        return False
    if os != 'WIN':
        return field != 'skipSolidification' or \
            (bool(value.strip()) and not any(char in value.strip() for char in ':*?<>|'))
    if len(value) > 1024 or '\\\\' in value[1:]:
        return False
    if field != 'skipSolidification' and re.search(r'([^\\]\*)', value):
        return False
    if field in ('skipFileOperation', 'skipFileOperation_f', 'skipDenyWrite',
                 'skipChangeTracking') and not _SC_RELATIVE.search(value):
        return False
    if field in ('process_ctx_bypass', 'parent_process_ctx_bypass') and \
            not re.fullmatch(r'[^\\/:*?"<>|]+', value):
        return False
    if field == 'skipSolidification' and \
            not re.fullmatch(r'([A-Za-z]:\\|([A-Za-z?]:)(\\[^/:"<>|\\]*[^/:"<>|\\. ])+)\\?', value):
        return False
    if field == 'skipRegistry':
        return is_sc_registry_key(value)
    return True



_SC_TOP_LEVEL = re.compile(r'^.:[\\]$|^.:\\users\\?$|^.:\\Documents and Settings\\?$|'
                           r'^.:\\windows\\?$|^.:\\Program Files( \(x86\))?\\?$|^.:\\Program Data\\?$|'
                           r'^.:\\winnt\\?$|^%HOMEDRIVE%\\?$|^%WINDIR%\\?$|^%SystemRoot%\\?$|'
                           r'^%SystemDrive%\\?$|^%PROGRAMDATA%\\?$|^%PROGRAMFILES%(\(X86\))?\\?$|'
                           r'^%PROGRAMW6432%\\?$', re.IGNORECASE)


def is_sc_top_level_path(path):
    r"""
    Returns True for a top-level Windows path where the Solidcore Integrity
    Monitor refuses Content Change Tracking (validateTopLevelPaths): a drive
    root, \Users, \Documents and Settings, \Windows, \Program Files (x86),
    \Program Data, \WINNT, or %HOMEDRIVE%, %WINDIR%, %SystemRoot%,
    %SystemDrive%, %PROGRAMDATA%, %PROGRAMFILES%, %PROGRAMW6432%.

    >>> is_sc_top_level_path('C:\\Windows\\')
    True
    >>> is_sc_top_level_path('C:\\Windows\\System32')
    False
    """
    return bool(_SC_TOP_LEVEL.search(str(path).strip()))


def is_sc_fim_pattern(pattern):
    """
    Checks an Include or Exclude Pattern of a Solidcore directory change
    tracking (validatePatterns of the Integrity Monitor dialog): a file name
    with * only at its start or at its end (once), without \\ / ? : " < > |.

    Valid / invalid (a wildcard inside):

    >>> is_sc_fim_pattern('*.cfg')
    True
    >>> is_sc_fim_pattern('app*.cfg')
    False
    """
    pattern = str(pattern)
    return '\n' not in pattern and not re.search(r'.\*.|.\*{2}', pattern) and \
        not re.search(r'^\*{2}|\*{2}$|^\*.+\*$', pattern) and '\\' not in pattern and \
        not any(char in pattern for char in '/?:"<>|')


def is_sc_fim_user(user, os='WIN'):
    """
    Checks a user of the Solidcore Integrity Monitor User tab (isUserValid):
    without / nor *, one \\ at most (DOMAIN\\user); on Unix no \\ at all.

    Valid / invalid (two backslashes):

    >>> is_sc_fim_user('NT AUTHORITY\\\\SYSTEM')
    True
    >>> is_sc_fim_user('a\\\\b\\\\c')
    False
    """
    user = str(user)
    if os == 'UNIX' and '\\' in user:
        return False
    return '/' not in user and '*' not in user and user.count('\\') <= 1


# ------------------------------ ENS Storage Protection ------------------------------
def is_sp_ipv4(address):
    """
    Checks an ICAP bind address or connection list address
    (IsValidBindAddressFormat / IsValidIPAddressFormat2 of the ICAP page,
    which only lets digits and dots be typed): four numbers, the first one
    up to 223, the others up to 255.

    Valid / invalid (a multicast address):

    >>> is_sp_ipv4('0.0.0.0')
    True
    >>> is_sp_ipv4('224.0.0.1')
    False
    """
    parts = str(address).split('.')
    return len(parts) == 4 and all(re.fullmatch(r'[0-9]+', part) for part in parts) and \
        int(parts[0]) <= 223 and all(int(part) <= 255 for part in parts[1:])


def is_sp_filer(filer):
    """
    Checks a NetApp filer of the Filers list (ipAddress_or_filerName lets
    letters, digits and dots be typed; FinalValidateFiler flags a dotted
    value that is not an address - a three-part name even breaks the page
    script): a name of letters and digits, or an IPv4 address whose first
    number is 1-223 (IsValidIPAddressFormat2 of the NetApp page, stricter
    than the ICAP one: 0.0.0.0 is flagged).

    Valid / invalid (a name with a domain):

    >>> is_sp_filer('filer01')
    True
    >>> is_sp_filer('filer01.example.com')
    False
    """
    filer = str(filer)
    return bool(re.fullmatch(r'[A-Za-z0-9]+', filer)) or \
        (is_sp_ipv4(filer) and int(filer.split('.')[0]) >= 1)


def is_sp_file_type(file_type):
    """
    Checks a file type of the ENSSP "File types to scan" lists
    (validateFileTypes of Common.js, space-separated): 3 characters at most,
    without / " | < > \\ : or space; ':::' stands for the files with no
    extension.

    Valid / invalid (four characters):

    >>> is_sp_file_type('do?')
    True
    >>> is_sp_file_type('docx')
    False
    """
    file_type = str(file_type)
    return file_type == ':::' or (0 < len(file_type) <= 3 and
                                  not any(char in file_type for char in '/"|<>\\: '))


def is_sp_exclusion_pattern(pattern):
    r"""
    Checks a NetApp exclusion pattern (IsValidExclusionPattern and
    IsValidAmcoreExclusionPattern of Common.js): not empty, without / | < >,
    not \ \\ \? \?\ \\? alone and not starting with \\\ \\?\ or \?\\.

    Valid / invalid (a forward slash):

    >>> is_sp_exclusion_pattern('C:\\Data\\')
    True
    >>> is_sp_exclusion_pattern('/vol/data')
    False
    """
    pattern = str(pattern)
    if not pattern or any(char in pattern for char in '/|<>'):
        return False
    if pattern in ('\\', '\\\\', '\\?', '\\?\\', '\\\\?'):
        return False
    return not (pattern.startswith('\\\\\\') or pattern[:4] in ('\\\\?\\', '\\?\\\\'))


def is_sp_exclusion_file_type(file_type):
    """
    Checks a NetApp exclusion file type (IsValidExclusionFileType of
    Common.js, textbox of 10 characters): ':::' (files with no extension,
    what the console stores for an empty type) or a type without
    / " | < > : \\.

    Valid / invalid (a colon):

    >>> is_sp_exclusion_file_type('tmp')
    True
    >>> is_sp_exclusion_file_type('a:b')
    False
    """
    file_type = str(file_type)
    return file_type == ':::' or (0 < len(file_type) <= 10 and
                                  not any(char in file_type for char in '/"|<>:\\'))


# ------------------------------ Solidcore ------------------------------
_SC_EMAIL = r'[\w-]+(?:\.[A-Za-z0-9]+)*@[\w-]+(?:\.[A-Za-z0-9]+)*\.[A-Za-z]{2,}'
_SC_LABEL = r'[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?'


def is_sc_email_list(text):
    """
    Checks the Helpdesk "Mail to" of a Solidcore Application Control Options
    policy as the ePO server of Solidcore 8.4 does (rule found on the lab:
    the console page also checks OrionValidate.areEmailAddresses): one or
    more addresses separated by ; (one space at most on each side), each
    word[.word...]@label[.label...].tld: the first word and the first label
    of ASCII letters, digits, _ and -, the next ones of letters and digits
    only, a top-level domain of letters.

    Valid / invalid (a comma separator):

    >>> is_sc_email_list('helpdesk@example.com; soc@example.com')
    True
    >>> is_sc_email_list('helpdesk@example.com, soc@example.com')
    False
    """
    return re.fullmatch(r'{0}(?: ?; ?{0})*'.format(_SC_EMAIL), str(text), re.ASCII) is not None


def is_sc_website(url):
    """
    Checks the Helpdesk "Link to Website" of a Solidcore Application Control
    Options policy as the ePO server of Solidcore 8.4 does (rule found on
    the lab): an optional https:// or ftp:// (any case; http:// is refused),
    labels of letters, digits and - (starting and ending with a letter or a
    digit, no _), a top-level domain of letters, an optional port, no path.

    Valid / invalid (http://):

    >>> is_sc_website('https://helpdesk.example.com:8443')
    True
    >>> is_sc_website('http://helpdesk.example.com')
    False
    """
    return re.fullmatch(r'(?:(?:https|ftp)://)?(?:{0}\.)+[A-Za-z]{{2,}}(?::[0-9]+)?'.format(
        _SC_LABEL), str(url), re.IGNORECASE) is not None


# ------------------------------ ENS Firewall ------------------------------
# DNS Blocking domain names (validDomain of the Options page, EditFWOpts.jsp; the
# Add dialog also accepts * alone): labels of letters, digits, - and the * ?
# wildcards, two labels at least, ending with a letter or a wildcard.
# Valid: *.example.com; invalid: example (no domain).
FW_BLOCKED_DOMAIN = re.compile(r'^(?:[a-zA-Z0-9?*](?:[-a-zA-Z0-9?*]*[a-zA-Z0-9?*])?\.)+'
                               r'(?:[-a-zA-Z0-9?*]*[a-zA-Z0-9?*])?[a-zA-Z?*]$')
# IpAddress of the rule editor (fw/rules/ip.js).
_FW_V4 = re.compile(r'^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.'
                    r'(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$')
_FW_V6 = re.compile(r'^(^(([0-9A-Fa-f]{1,4}(((:[0-9A-Fa-f]{1,4}){5}::[0-9A-Fa-f]{1,4})|((:[0-9A-Fa-f]{1,4}){4}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,1})|((:[0-9A-Fa-f]{1,4}){3}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,2})|((:[0-9A-Fa-f]{1,4}){2}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,3})|(:[0-9A-Fa-f]{1,4}::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,4})|(::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,5})|(:[0-9A-Fa-f]{1,4}){7}))$|^(::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,6})$)|^::$)|^(^(([0-9A-Fa-f]{1,4}((((:[0-9A-Fa-f]{1,4}){4}:)|(:[0-9A-Fa-f]{1,4}){3}:(:[0-9A-Fa-f]{1,4}){0,1})|((:[0-9A-Fa-f]{1,4}){2}:(:[0-9A-Fa-f]{1,4}){0,2})|((:[0-9A-Fa-f]{1,4}):(:[0-9A-Fa-f]{1,4}){0,3})|(:(:[0-9A-Fa-f]{1,4}){0,4})|(:[0-9A-Fa-f]{1,4}){5}))|^(::[0-9A-Fa-f]{1,4}(:[0-9A-Fa-f]{1,4}){0,4}))|^:):((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[0-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{0,2})$')
_FW_FQDN = re.compile(r'^(?:[a-zA-Z0-9*?](?:[-a-zA-Z0-9*?]*[a-zA-Z0-9*?])?\.)+'
                      r'[a-zA-Z0-9*?](?:[-a-zA-Z0-9*?]*[a-zA-Z0-9*?])?[a-zA-Z*?]$')
_FW_INVALID = re.compile(r'[^0-9a-fA-F./:-]')
_FW_FQDN_INVALID = re.compile(r'[^a-zA-Z0-9*?.-]')
FW_ANY = '0000:0000:0000:0000:0000:0000:0000:0000'
FW_LOCAL_SUBNET = '0000:0000:0000:0000:0000:ffff:0000:0000'
FW_ANY_IPV4 = FW_LOCAL_SUBNET + '-0000:0000:0000:0000:0000:ffff:ffff:ffff'
FW_ANY_IPV6 = FW_ANY + '-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
# Address types of fw_address_type (IpAddress.getAddrType).
FW_SINGLE, FW_NETWORK, FW_RANGE, FW_FQDN = 'Single', 'Network', 'Range', 'FQDN'


def _fw_normalize_ip6(address):
    """
    IpAddress.normalizeIp6: the 8 groups of 4 hexadecimal digits of an IPv6
    address (a dotted IPv4 end is converted).

    >>> _fw_normalize_ip6('fd00::1')
    'fd00:0000:0000:0000:0000:0000:0000:0001'
    """
    parts = address.split(':')
    if '.' in parts[-1]:
        quads = [int(quad) for quad in parts[-1].split('.')]
        parts[-1] = format((quads[0] << 8) + quads[1], 'x')
        parts.append(format((quads[2] << 8) + quads[3], 'x'))
    if parts[0] == '':
        parts[0] = '0000'
    index = 0
    while index < len(parts):
        if parts[index] != '':
            parts[index] = parts[index].rjust(4, '0')
        else:
            del parts[index]
            missing = 8 - len(parts)
            for offset in range(missing):
                parts.insert(index + offset, '0000')
            index += missing - 1
        index += 1
    return ':'.join(parts)


def fw_ip_entry(entry):
    """
    Returns the stored form of an address typed in a Firewall rule network
    or location (IpAddress of the rule editor, fw/rules/ip.js): an IPv4 or
    IPv6 address, a CIDR network, a range (first-last, IPv4 or IPv6, not
    backward) or a domain name (letters, digits, - and the * ? wildcards).
    IPv4 is stored as IPv4-mapped IPv6 (a /n network as /96+n). Raises
    ValueError for anything else.

    Valid / invalid (a backward range):

    >>> fw_ip_entry('10.0.0.1')
    '0000:0000:0000:0000:0000:ffff:0a00:0001'
    >>> fw_ip_entry('10.0.0.9-10.0.0.1')
    Traceback (most recent call last):
    ...
    ValueError: IP range is backward: '10.0.0.9-10.0.0.1'
    """
    entry = str(entry).lower()
    if not _FW_FQDN_INVALID.search(entry) and _FW_FQDN.search(entry) and \
            not _FW_V4.search(entry):
        return entry
    if _FW_INVALID.search(entry):
        raise ValueError('Entry contains invalid characters: {!r}'.format(entry))
    if '-' in entry:
        start, end = entry.split('-', 1)
        if _FW_V4.search(start):
            if not _FW_V4.search(end):
                raise ValueError('IPv4 range ends with invalid IPv4 address: {!r}'.format(entry))
            start = _fw_normalize_ip6('0000:0000:0000:0000:0000:ffff:' + start)
            end = _fw_normalize_ip6('0000:0000:0000:0000:0000:ffff:' + end)
        elif _FW_V6.search(start):
            if not _FW_V6.search(end):
                raise ValueError('IPv6 range ends with invalid IPv6 address: {!r}'.format(entry))
            start, end = _fw_normalize_ip6(start), _fw_normalize_ip6(end)
        else:
            raise ValueError('Invalid IP range specified: {!r}'.format(entry))
        if start > end:
            raise ValueError('IP range is backward: {!r}'.format(entry))
        return start + '-' + end
    if '/' in entry:
        address, prefix = entry.split('/', 1)
        valid_prefix = re.fullmatch(r'-?[0-9]+', prefix.strip()) is not None
        if is_orion_ipv4(address) and valid_prefix and 1 <= int(prefix) <= 32:
            return '{}/{}'.format(
                _fw_normalize_ip6('0000:0000:0000:0000:0000:ffff:' + address), 96 + int(prefix))
        if is_orion_ipv6(address) and valid_prefix and 1 <= int(prefix) <= 128:
            return '{}/{}'.format(_fw_normalize_ip6(address), prefix)
        raise ValueError('Invalid network specification: {!r}'.format(entry))
    if _FW_V4.search(entry):
        return _fw_normalize_ip6('0000:0000:0000:0000:0000:ffff:' + entry)
    if _FW_V6.search(entry):
        return _fw_normalize_ip6(entry)
    raise ValueError('Invalid entry: {!r}'.format(entry))


def fw_address_type(stored):
    """
    IpAddress.getAddrType of the rule editor: the type of a stored address
    (FW_SINGLE, FW_NETWORK, FW_RANGE, FW_FQDN, or 'Any', 'Local subnet',
    'Any IPv4', 'Any IPv6' for the special values).

    Valid single address / the any address is not a single one:

    >>> fw_address_type(fw_ip_entry('10.0.0.1'))
    'Single'
    >>> fw_address_type(fw_ip_entry('::'))
    'Any'
    """
    if len(stored) < 39 or stored[4] != ':':
        return FW_FQDN
    if len(stored) == 39:
        return {FW_ANY: 'Any', FW_LOCAL_SUBNET: 'Local subnet'}.get(stored, FW_SINGLE)
    if stored[39] == '/':
        return FW_NETWORK
    return {FW_ANY_IPV4: 'Any IPv4', FW_ANY_IPV6: 'Any IPv6'}.get(stored, FW_RANGE)


def is_fw_fqdn(value):
    """
    FQDNValidator of the Firewall pages (network domain names, location
    "Domain reachable"): 255 characters max, labels of letters, digits and -,
    two labels at least, the last one ending with a letter, an optional
    final dot; no wildcard.

    Valid / invalid (a wildcard):

    >>> is_fw_fqdn('server.example.com')
    True
    >>> is_fw_fqdn('*.example.com')
    False
    """
    return len(value) <= 255 and re.fullmatch(
        r'(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?\.){1,255}'
        r'(?:[a-zA-Z0-9][-a-zA-Z0-9]{0,61}[a-zA-Z])\.?', value) is not None


def is_fw_dns_suffix(value):
    """
    dnsSuffixValidator of the location criteria "Connection-specific DNS
    suffix": 1-255 characters, labels with the * ? wildcards, two labels at
    least, an optional final dot.

    Valid / invalid (one label only):

    >>> is_fw_dns_suffix('*.corp.example.com')
    True
    >>> is_fw_dns_suffix('corp')
    False
    """
    return 0 < len(value) <= 255 and re.fullmatch(
        r'(?:[a-zA-Z0-9*?](?:[-a-zA-Z0-9*?]{0,61}[a-zA-Z0-9*?])?\.){1,255}'
        r'(?:[a-zA-Z0-9*?][-a-zA-Z0-9*?]{0,61}[a-zA-Z*?]|\*)\.?', value) is not None


def is_fw_host(value):
    """
    validHost of the Firewall network dialog for one address of a network,
    in the console form: an IPv4 or IPv6 address (not the any or local
    subnet addresses), a CIDR network, a range first-last or a domain name
    (see is_fw_fqdn), 255 characters max.

    Valid / invalid (a domain name with a wildcard):

    >>> is_fw_host('10.20.0.1-10.20.0.50')
    True
    >>> is_fw_host('*.example.com')
    False
    """
    value = str(value)
    if len(value) > 255:
        return False
    try:
        stored = fw_ip_entry(value)
    except ValueError:
        return False
    kind = fw_address_type(stored)
    if kind == FW_FQDN:
        return is_fw_fqdn(value)
    return kind in [FW_SINGLE, FW_NETWORK, FW_RANGE]


def is_fw_single_ip(value):
    """
    singleIpValidator of the location criteria (default gateway, DHCP, DNS
    and WINS servers): one IPv4 or IPv6 address.

    Valid / invalid (a network):

    >>> is_fw_single_ip('fd00::53')
    True
    >>> is_fw_single_ip('10.0.0.0/8')
    False
    """
    try:
        return fw_address_type(fw_ip_entry(value)) == FW_SINGLE
    except ValueError:
        return False


def is_fw_port(value):
    """
    validatePort of the rule Transport tab (TCP and UDP local and remote
    ports): a port 1-65535 or a range first-last with first < last.

    Valid / invalid (a backward range):

    >>> is_fw_port('1000-2000')
    True
    >>> is_fw_port('2000-1000')
    False
    """
    value = str(value)
    if value.strip() == '' or (re.fullmatch(r'-?[0-9]+', value.strip()) and
                               1 <= int(value) <= 65535):
        return True
    match = re.match(r'^(\s*\d+\s*)-(\s*\d+\s*)(.*)', value)
    if not match or match.group(3):
        return False
    first, last = int(match.group(1)), int(match.group(2))
    return 1 <= first <= 65535 and 1 <= last <= 65535 and first < last


def is_orion_ip_group(value, version):
    """
    OrionValidate.isValidIPv4AddrGroup (version 4) / isValidIPv6AddrGroup
    (version 6, which also accepts IPv4): a list (separated by commas or
    spaces) of addresses, first-last ranges (ends not compared) or CIDR
    networks.

    Valid / invalid (a host name):

    >>> is_orion_ip_group('10.0.0.1-10.0.0.9, 192.168.0.0/16', 4)
    True
    >>> is_orion_ip_group('server01', 4)
    False
    """
    value = str(value)
    chars = r'[\d\-.,\s/]+' if version == 4 else r'[0-9A-Fa-f\-.,:\s/]+'
    if not value.strip() or not re.fullmatch(chars, value):
        return False
    singles = [is_orion_ipv4] if version == 4 else [is_orion_ipv6, is_orion_ipv4]
    for item in re.split(r'[,\s]+', value):
        if not item.strip():
            continue
        if '-' in item:
            start, end = item.split('-', 1)
            if not any(single(start) and single(end) for single in singles):
                return False
        elif '/' in item:
            start, mask = item.split('/', 1)
            valid_mask = re.fullmatch(r'-?[0-9]+', mask.strip()) is not None
            if not (valid_mask and ((is_orion_ipv4(start) and 1 <= int(mask) <= 32) or
                                    (version == 6 and is_orion_ipv6(start) and
                                     1 <= int(mask) <= 128))):
                return False
        elif not any(single(item) for single in singles):
            return False
    return True


def is_fw_defined_network(address_type, value):
    """
    definedNetworksValidator of the Firewall Options "Defined Networks"
    (address of 100 characters): SingleIP an IPv4 or IPv6 address, Subnet a
    CIDR network without spaces, Range a range first-last (not backward;
    the console also lets an address or a network through), FQDN a domain name (labels of 63 characters, 255 max, ending
    with a top-level domain of 2-63 letters, ASCII only).

    Valid / invalid (a network typed as a single address):

    >>> is_fw_defined_network('Subnet', '10.10.0.0/16')
    True
    >>> is_fw_defined_network('SingleIP', '10.10.0.0/16')
    False
    """
    value = str(value)
    if not value.strip() or len(value) > 100:
        return False
    if address_type == 'SingleIP':
        return is_orion_ipv4(value) or is_orion_ipv6(value)
    if address_type == 'Subnet':
        value = value.strip()
        if re.search(r'\s', value):
            return False
        parts = value.split('/')
        if len(parts) < 2 or not re.fullmatch(r'-?[0-9]+', parts[1].strip()):
            return False
        return (is_orion_ipv4(parts[0]) and 1 <= int(parts[1]) <= 32) or \
            (is_orion_ipv6(parts[0]) and 1 <= int(parts[1]) <= 128)
    if address_type == 'Range':
        # validateIp only checks that IpAddress reads the value: a single
        # address or a network passes too.
        try:
            fw_ip_entry(value)
        except ValueError:
            return False
        return is_orion_ip_group(value, 4) or is_orion_ip_group(value, 6)
    if address_type == 'FQDN':
        value = value.strip()
        return len(value) <= 255 and value.isascii() and re.fullmatch(
            r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}', value) is not None
    return False


def is_fw_file_path(path):
    r"""
    IsValidFileNameOrFilePath of the Firewall executable dialog ("File name
    or path", 257 characters): with a / or a \, a Linux or Mac path (no \,
    not starting with //), a drive path (C:\, ?:\, *:\ or **\ start, no
    double \), a UNC path or a **\ path, the * ? wildcards being allowed;
    otherwise a file name without \ / : " < > |.

    Valid / invalid (a double backslash):

    >>> is_fw_file_path(r'C:\Program Files\*\app.exe')
    True
    >>> is_fw_file_path(r'C:\Tools\\app.exe')
    False
    """
    path = str(path)
    if '/' not in path and '\\' not in path:
        return re.fullmatch(r'[^\\/:"<>|]+', path) is not None
    if '\\' not in path and not path.startswith('//'):
        return True
    return re.fullmatch(r'((([a-zA-Z*?]:(\\(?!\\)))|(\*\*\\)|(\\\\))'
                        r'(([^\\/"<>|]+(\\(?!\\)))|([^\\/"<>|]))*)', path) is not None or \
        re.fullmatch(r'(\\\\[^\\/:"<>|]+)\\(?!\\)([^\\/"<>|]*(\\(?!\\))*)*', path) is not None or \
        re.fullmatch(r'\*\*\\((?:[^\\/"<>|])+(?:\\(?!\\))*)+', path) is not None


FW_REGISTRY_ROOTS = ['HKEY_CLASSES_ROOT', 'HKEY_CURRENT_CONFIG', 'HKEY_CURRENT_USER',
                     'HKEY_LOCAL_MACHINE', 'HKEY_USERS']


def is_fw_registry_key(key):
    r"""
    validateRegistryKey of the location "Registry key" field (1499
    characters): a root of FW_REGISTRY_ROOTS (any case), a key path without
    = nor double \, then the value name without =.

    Valid / invalid (an abbreviated root):

    >>> is_fw_registry_key(r'HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\Office')
    True
    >>> is_fw_registry_key(r'HKLM\SOFTWARE\Contoso\Office')
    False
    """
    parts = str(key).split('\\')
    if parts[0].upper() not in FW_REGISTRY_ROOTS:
        return False
    path = '\\'.join(parts[1:-1])
    if path == '' or '=' in path or '\\\\' in path:
        return False
    return '=' not in parts[-1]
