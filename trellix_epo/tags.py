# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the ePO tags as objects, without a server: Tag (name,
notes, criteria, evaluation, group), TagCriteria and TagCondition (the
criteria of the console, written as the SQUID expression ePO stores), and
TagList (the XML of system.exportTag / system.importTag).

A criteria works as the console builder: the conditions on different
properties are all required (and); several conditions on the same property
are joined with "and" or "or" (set_grouping()). The values are given in the
units of the console and converted as the console does (checked on ePO 5.10
Update 7):

>>> criteria = TagCriteria()
>>> criteria.add('OS Platform', 'eq', 'Server').add('OS Platform', 'eq', 'Workstation')
<TagCriteria: OS Platform Equals Server and OS Platform Equals Workstation>
>>> criteria.set_grouping('OS Platform', 'or')
>>> criteria.add('Free Disk Space', 'gt', '10 GB')   # doctest: +NORMALIZE_WHITESPACE
<TagCriteria: (OS Platform Equals Server or OS Platform Equals Workstation)
and Free Disk Space Greater than 10240 MB>
>>> criteria.to_squid()       # doctest: +NORMALIZE_WHITESPACE
'( where ( and ( or ( eq EPOComputerProperties.OSPlatform "Server" )
  ( eq EPOComputerProperties.OSPlatform "Workstation" ) )
  ( gt EPOComputerProperties.FreeDiskSpace 10240 ) ) )'

The property catalog and the console limits are in tagcatalog.
"""

import datetime
import ipaddress
import re
import xml.etree.ElementTree as et

from . import tagcatalog as cat

# Root tag group of ePO ("My Tags") and the group of the deployment tags,
# which the tag import can't use.
ROOT_GROUP = 'My Tags'
DEPLOYMENT_GROUP = 'Deployment Tags'

# Console limit of a tag name (newTag.do, maxlength 50).
MAX_TAG_NAME = 50

# Duration units of the console and their length in milliseconds, as the ePO
# server converts them (a month is 30 days, a quarter 91 days, a year 365 days).
DURATION_UNITS = {'year': 365 * 86400000, 'quarter': 91 * 86400000, 'month': 30 * 86400000,
                  'week': 7 * 86400000, 'day': 86400000, 'hour': 3600000}

# Size units: number of MB (megabytes properties) or of bytes (bytes
# properties), and the maximum number of digits the console takes per unit.
_MB_UNITS = {'MB': (1, 9), 'GB': (1024, 6), 'TB': (1024 * 1024, 3)}
_BYTE_UNITS = {'KB': (1024, 12), 'MB': (1024 ** 2, 9), 'GB': (1024 ** 3, 6), 'TB': (1024 ** 4, 3)}

# Operators that take a duration, a date or no value.
_DURATION_OPS = ('newerThan', 'newerThanFull', 'olderThan')
_DATE_OPS = ('newerThanAbsolute', 'olderThanAbsolute')
_NO_VALUE_OPS = ('isBlank', 'not_isBlank', 'beforeNow')

# Console version check: up to 4 numeric parts of 1 to 10 digits.
_VERSION = re.compile(r'\d{1,10}(\.\d{1,10}){0,3}')


# ------------------------------ SQUID text ------------------------------
def squid_quote(text):
    """
    Returns a SQUID string: in double quotes, the double quotes and the
    backslashes escaped with a backslash.

    >>> print(squid_quote('a"b\\'c'))
    "a\\"b'c"
    """
    return '"{}"'.format(text.replace('\\', '\\\\').replace('"', '\\"'))


def squid_parse(text):
    """
    Returns a SQUID expression as nested lists: an item in parentheses
    becomes a list, a quoted string a str subclass (SquidString), a word a
    str.

    >>> squid_parse('( where ( eq EPOComputerProperties.Vdi 1 ) )')
    ['where', ['eq', 'EPOComputerProperties.Vdi', '1']]
    >>> squid_parse('( eq P "a\\\\"b" )')[2]
    SquidString('a"b')
    >>> squid_parse('( eq P "x" ')
    Traceback (most recent call last):
    ValueError: Unbalanced parentheses in the SQUID expression.
    """
    tokens = re.findall(r'\(|\)|"(?:\\.|[^"\\])*"|[^\s()"]+', text)
    stack = [[]]
    for token in tokens:
        if token == '(':
            stack.append([])
        elif token == ')':
            if len(stack) < 2:
                raise ValueError('Unbalanced parentheses in the SQUID expression.')
            item = stack.pop()
            stack[-1].append(item)
        elif token.startswith('"'):
            stack[-1].append(SquidString(re.sub(r'\\(.)', r'\1', token[1:-1])))
        else:
            stack[-1].append(token)
    if len(stack) != 1 or len(stack[0]) != 1:
        raise ValueError('Unbalanced parentheses in the SQUID expression.')
    return stack[0][0]


class SquidString(str):
    """
    A quoted string of a SQUID expression (to tell "1" from 1).

    >>> SquidString('Server')
    SquidString('Server')
    """

    def __repr__(self):
        """
        Shows the class, to tell a quoted string from a word.
        """
        return 'SquidString({})'.format(str.__repr__(self))


# ------------------------------ Properties ------------------------------
class TagProperty():
    """
    A system property of the criteria builder (an entry of
    tagcatalog.PROPERTIES).

    >>> TagProperty.get('Free Disk Space')
    <TagProperty EPOComputerProperties.FreeDiskSpace (Free Disk Space, megabytes)>
    >>> TagProperty.get('EPOProdPropsView_EPOAGENT.productversion').category
    'Agent Properties'
    """

    def __init__(self, key, label, category, kind):
        """
        :param: key: The SQUID name, e.g. 'EPOComputerProperties.OSPlatform'.
        :param: label: The console label, e.g. 'OS Platform'.
        :param: category: The console category, e.g. 'Computer Properties'.
        :param: kind: The kind of value (tagcatalog.TEXT, MEGABYTES...).
        """
        self.key = key
        self.label = label
        self.category = category
        self.kind = kind

    def __repr__(self):
        """
        Shows the key, the label and the kind.
        """
        return '<TagProperty {} ({}, {})>'.format(self.key, self.label, self.kind)

    @property
    def operators(self):
        """
        The operator keys of the property, in the order of the console list.
        """
        return cat.KINDS[self.kind]['operators']

    @classmethod
    def all(cls):
        """
        Returns all the properties of the catalog.
        """
        return [cls(*entry) for entry in cat.PROPERTIES]

    @classmethod
    def get(cls, name):
        """
        Returns a property from its SQUID key, from its console label when
        only one property has it (e.g. 'OS Platform'), or from
        "<category>: <label>" (e.g. 'Agent Properties: Product Version').

        :raise: ValueError: Unknown or ambiguous name.

        >>> TagProperty.get('Product Version')     # doctest: +ELLIPSIS
        Traceback (most recent call last):
        ValueError: "Product Version" is the label of 17 properties, use the key or ...
        """
        entries = [entry for entry in cat.PROPERTIES if entry[0] == name]
        if not entries and ': ' in name:
            category, label = name.split(': ', 1)
            entries = [entry for entry in cat.PROPERTIES
                       if (entry[2].lower(), entry[1].lower()) == (category.lower(), label.lower())]
        if not entries:
            entries = [entry for entry in cat.PROPERTIES if entry[1].lower() == name.lower()]
        if len(entries) > 1:
            raise ValueError('"{}" is the label of {} properties, use the key or "<category>: {}": '
                             '{}, ...'.format(name, len(entries), name, entries[0][0]))
        if not entries:
            raise ValueError('Unknown tag criteria property "{}".'.format(name))
        return cls(*entries[0])

    @classmethod
    def from_key(cls, key):
        """
        Returns the property of a SQUID key, or a TEXT property for a key the
        catalog doesn't have (a product of another server).
        """
        for entry in cat.PROPERTIES:
            if entry[0] == key:
                return cls(*entry)
        return cls(key, key, '', cat.TEXT)


# ------------------------------ Value conversions ------------------------------
def _ip(value, version):
    """
    Returns the SQUID form of an address: an IPv4 address as given (also in
    an IPv6 property), an IPv6 address in the server form (8 groups,
    upper case, no leading zero).

    >>> _ip('fd00::5', 6), _ip('10.0.0.5', 6)
    ('FD00:0:0:0:0:0:0:5', '10.0.0.5')
    >>> _ip('fd00::5', 4)
    Traceback (most recent call last):
    ValueError: Invalid IPv4 address "fd00::5".
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        address = None
    if address is None or (version == 4 and address.version != 4):
        raise ValueError('Invalid IPv{} address "{}".'.format(version, value))
    if address.version == 4:
        return str(address)
    return ':'.join('{:X}'.format(int(part, 16)) for part in address.exploded.split(':'))


def _ip_function(value, version):
    """
    Returns the SQUID address function of a value: "( ipv4 "x" )" or
    "( ipv6 "x" )".
    """
    return '( ipv{} {} )'.format(version, squid_quote(_ip(value, version)))


def _ip_subnet(value, version):
    """
    Returns the address and the prefix length of a subnet "address/length"
    (checked with the ipaddress module, host bits allowed as in the console).

    >>> _ip_subnet('10.0.0.0/8', 4)
    ('10.0.0.0', 8)
    """
    text = str(value).strip()
    address, _, length = text.partition('/')
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError('Invalid subnet "{}" (address/prefix length).'.format(value))
    _ip(address, version)
    return address, int(length)


def _ip_range(value):
    """
    Returns the two addresses of a range given as "a-b" or (a, b).

    >>> _ip_range('10.0.0.1-10.0.0.9')
    ('10.0.0.1', '10.0.0.9')
    """
    if isinstance(value, (tuple, list)) and len(value) == 2:
        return str(value[0]).strip(), str(value[1]).strip()
    start, separator, end = str(value).partition('-')
    if not separator:
        raise ValueError('Invalid address range "{}" (start-end).'.format(value))
    return start.strip(), end.strip()


def _ip_items(value):
    """
    Returns the items of an address list given as a list or as a text
    separated by commas.

    >>> _ip_items('10.0.0.1, 10.0.0.2-10.0.0.5')
    ['10.0.0.1', '10.0.0.2-10.0.0.5']
    """
    items = value if isinstance(value, (list, tuple)) else str(value).split(',')
    items = [str(item).strip() for item in items if str(item).strip()]
    if not items:
        raise ValueError('The address list is empty.')
    if len(','.join(items)) > 2048:
        raise ValueError('The address list is longer than 2048 characters (console limit).')
    return items


def _size(value, units, label):
    """
    Returns a size as a number of base units: an int is already in base
    units, a text "<n> <unit>" is converted (e.g. '10 GB' -> 10240 MB),
    with the console limit of digits per unit.

    >>> _size('10 GB', _MB_UNITS, 'MB'), _size(512, _MB_UNITS, 'MB')
    (10240, 512)
    >>> _size('1000000 GB', _MB_UNITS, 'MB')
    Traceback (most recent call last):
    ValueError: Size "1000000 GB": the console takes 6 digits at most in GB.
    """
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    match = re.fullmatch(r'\s*(\d+)\s*([A-Za-z]{2})\s*', str(value))
    if not match or match.group(2).upper() not in units:
        raise ValueError('Invalid size "{}": a number of {} or "<n> <unit>" with a unit in {}.'
                         .format(value, label, ', '.join(units)))
    count, unit = match.group(1), match.group(2).upper()
    factor, digits = units[unit]
    if len(count) > digits:
        raise ValueError('Size "{}": the console takes {} digits at most in {}.'
                         .format(value, digits, unit))
    return int(count) * factor


def _duration(value):
    """
    Returns a duration in milliseconds from "<n> <unit>" (unit hour, day,
    week, month, quarter, year, singular or plural, n from 1 to 9999 as in
    the console), from a datetime.timedelta or from a number of
    milliseconds.

    >>> _duration('2 weeks'), _duration(datetime.timedelta(hours=1))
    (1209600000, 3600000)
    >>> _duration('0 days')     # doctest: +ELLIPSIS
    Traceback (most recent call last):
    ValueError: Invalid duration "0 days": "<n> <unit>" with n from 1 to 9999 and a unit in ...
    """
    if isinstance(value, datetime.timedelta):
        return int(value.total_seconds() * 1000)
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    match = re.fullmatch(r'\s*(\d{1,4})\s*([a-z]+?)s?\s*', str(value).lower())
    if not match or match.group(2) not in DURATION_UNITS or int(match.group(1)) < 1:
        raise ValueError('Invalid duration "{}": "<n> <unit>" with n from 1 to 9999 and a unit in '
                         '{}.'.format(value, ', '.join(DURATION_UNITS)))
    return int(match.group(1)) * DURATION_UNITS[match.group(2)]


def _duration_text(milliseconds):
    """
    Returns a duration in milliseconds as "<n> <unit>" with the largest exact
    unit, or as a timedelta when no unit fits.

    >>> _duration_text(1209600000), _duration_text(7776000000)
    ('2 weeks', '3 months')
    """
    for unit, length in DURATION_UNITS.items():
        if milliseconds % length == 0 and 1 <= milliseconds // length <= 9999:
            count = milliseconds // length
            return '{} {}{}'.format(count, unit, 's' if count > 1 else '')
    return datetime.timedelta(milliseconds=milliseconds)


def _timestamp(value):
    """
    Returns a date as milliseconds since 1970 (UTC): a datetime (without a
    time zone it is a local time, as in the console), a date (midnight local
    time) or a number of milliseconds.

    >>> _timestamp(datetime.datetime(2026, 10, 13, 6, 30, tzinfo=datetime.timezone.utc))
    1791873000000
    """
    if isinstance(value, datetime.datetime):
        return int(value.timestamp() * 1000)
    if isinstance(value, datetime.date):
        return int(datetime.datetime(value.year, value.month, value.day).timestamp() * 1000)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    raise ValueError('Invalid date "{}": a datetime, a date or milliseconds since 1970.'
                     .format(value))


def _version_parts(value):
    """
    Returns the parts of a version checked as the console does: 1 to 4
    numbers of 1 to 10 digits, each at most 2147483647.

    >>> _version_parts('5.8.6.185')
    [5, 8, 6, 185]
    >>> _version_parts('5.x')
    Traceback (most recent call last):
    ValueError: Invalid version "5.x" (1 to 4 numbers separated by dots).
    """
    text = str(value).strip()
    if not _VERSION.fullmatch(text) or any(int(part) > 2147483647 for part in text.split('.')):
        raise ValueError('Invalid version "{}" (1 to 4 numbers separated by dots).'.format(value))
    return [int(part) for part in text.split('.')]


def version2_number(value):
    """
    Returns the number ePO stores for a "Product Version (Fast)" property:
    major, then minor on 3 digits, revision on 6 digits, build on 6 digits.

    >>> version2_number('10.7.20.14066'), version2_number('5.8')
    ('10007000020014066', '5008000000000000')
    """
    parts = (_version_parts(value) + [0, 0, 0])[:4]
    if parts[1] > 999 or parts[2] > 999999 or parts[3] > 999999:
        raise ValueError('Version "{}" too large for a "Product Version (Fast)" property '
                         '(minor 999, revision and build 999999).'.format(value))
    return str(parts[0] * 10 ** 15 + parts[1] * 10 ** 12 + parts[2] * 10 ** 6 + parts[3])


def version2_text(number):
    """
    Returns the version of a "Product Version (Fast)" number.

    >>> version2_text('10007000020014066')
    '10.7.20.14066'
    """
    number = int(number)
    return '{}.{}.{}.{}'.format(number // 10 ** 15, number // 10 ** 12 % 1000,
                                number // 10 ** 6 % 1000000, number % 1000000)


# ------------------------------ Conditions ------------------------------
class TagCondition():
    """
    One condition of a tag criteria: a property, an operator and a value,
    checked and converted as the console does.

    >>> TagCondition('Last System Boot Time', 'olderThan', '2 weeks').to_squid()
    '( olderThan EPOComputerProperties.SystemBootTime 1209600000 )'
    >>> TagCondition('Is Laptop', 'eq', 'No').to_squid()
    '( eq EPOComputerProperties.IsPortable 0 )'
    >>> TagCondition('IP address', 'in_ipv6_subnet', '192.168.100.0/24').to_squid()
    '( in_ipv6_subnet EPOComputerProperties.IPV6 ( ipv6 "192.168.100.0" ) 24 )'
    >>> TagCondition('Custom 1', 'eq', '')
    Traceback (most recent call last):
    ValueError: Custom 1: a value is required.
    """

    def __init__(self, prop, operator, value=None):
        """
        :param: prop: A TagProperty, or a name for TagProperty.get().
        :param: operator: An operator key (e.g. 'eq') or its console label
                          (e.g. 'Equals').
        :param: value: The value (see the module docstring for the units);
                       None for the operators without a value (isBlank,
                       not_isBlank, beforeNow).
        :raise: ValueError: Unknown property or operator, invalid value.
        """
        self.prop = prop if isinstance(prop, TagProperty) else TagProperty.get(prop)
        self.operator = self.__operator(operator)
        self.value = value
        self.args = self.__squid_args(value)

    def __repr__(self):
        """
        Shows the condition as the console does (see __str__()).
        """
        return '<TagCondition: {}>'.format(self)

    def __str__(self):
        """
        Returns the condition as "<label> <operator label> <value>", e.g.
        "Free Disk Space Greater than 10240 MB".
        """
        text = '{} {}'.format(self.prop.label, cat.OPERATORS.get(self.operator, self.operator))
        value = self.display_value()
        return text + (' ' + value if value else '')

    def __eq__(self, other):
        """
        Two conditions are equal when they give the same SQUID text.
        """
        return isinstance(other, TagCondition) and self.to_squid() == other.to_squid()

    def __operator(self, operator):
        """
        Returns the operator key of a key or a console label, checked against
        the operators of the property.
        """
        operators = self.prop.operators
        if operator in operators:
            return operator
        label = str(operator).lower()
        keys = [key for key in operators if cat.OPERATORS.get(key, '').lower() == label]
        if len(keys) != 1:
            raise ValueError('{}: operator "{}" not available, use one of {}.'.format(
                self.prop.label, operator, ', '.join(operators)))
        return keys[0]

    def __squid_args(self, value):
        """
        Returns the SQUID text of the value (after the property name), the
        value checked for the kind of the property and the operator.
        """
        kind, operator, label = self.prop.kind, self.operator, self.prop.label
        if operator in _NO_VALUE_OPS:
            if value not in (None, ''):
                raise ValueError('{}: operator "{}" takes no value.'.format(label, operator))
            return ''
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValueError('{}: a value is required.'.format(label))
        if kind in (cat.TEXT, cat.LOOKUP):
            text = str(value)
            if len(text) > cat.KINDS[kind]['max_length']:
                raise ValueError('{}: the value is longer than {} characters (console limit).'
                                 .format(label, cat.KINDS[kind]['max_length']))
            return squid_quote(text)
        if kind == cat.INTEGER:
            if not re.fullmatch(r'-?\d{1,10}', str(value).strip()) or isinstance(value, bool):
                raise ValueError('{}: "{}" is not a number of 10 digits at most.'
                                 .format(label, value))
            return str(int(str(value).strip()))
        if kind == cat.ENUM:
            return str(self.__enum_value(value))
        if kind == cat.STRING_ENUM:
            return squid_quote(self.__string_enum_value(value))
        if kind == cat.MEGABYTES:
            return str(_size(value, _MB_UNITS, 'MB'))
        if kind == cat.BYTES:
            return str(_size(value, _BYTE_UNITS, 'bytes'))
        if kind in (cat.IPV4, cat.IPV6):
            return self.__ip_args(value, 4 if kind == cat.IPV4 else 6)
        if kind == cat.TIMESTAMP:
            if operator in _DURATION_OPS:
                return str(_duration(value))
            if operator in _DATE_OPS:
                return str(_timestamp(value))
            start, end = value
            return '( timestamp {} ) ( timestamp {} )'.format(_timestamp(start), _timestamp(end))
        if kind == cat.VERSION:
            _version_parts(value)
            return squid_quote(str(value).strip())
        if kind == cat.VERSION2:
            return squid_quote(version2_number(value))
        raise ValueError('{}: unknown kind "{}".'.format(label, kind))

    def __enum_value(self, value):
        """
        Returns the number of an ENUM value given as a number or as its
        console label (e.g. 'No' for 0).
        """
        values = cat.ENUM_VALUES.get(self.prop.key, {})
        if isinstance(value, int) and not isinstance(value, bool):
            if values and value not in values:
                raise ValueError('{}: value {} not in {}.'.format(self.prop.label, value, values))
            return value
        for number, text in values.items():
            if text.lower() == str(value).strip().lower() or str(number) == str(value).strip():
                return number
        if not values and re.fullmatch(r'-?\d+', str(value).strip()):
            return int(value)
        raise ValueError('{}: value "{}" not in {}.'.format(self.prop.label, value, values or
                                                              'the numbers of the server'))

    def __string_enum_value(self, value):
        """
        Returns the code of a STRING_ENUM value given as a code or as its
        console label (a language name, a management type name).
        """
        values = (cat.MANAGEMENT_TYPES if self.prop.key.endswith('.ManagementType')
                  else cat.LANGUAGES)
        text = str(value).strip()
        for code, name in values.items():
            if text.lower() in (code.lower(), name.lower()):
                return code
        # The product language lists also take the values of the database
        # (e.g. "409" for 0409).
        if values is cat.LANGUAGES and re.fullmatch(r'[0-9A-Fa-f]{1,4}', text):
            return text
        raise ValueError('{}: unknown value "{}".'.format(self.prop.label, value))

    def __ip_args(self, value, version):
        """
        Returns the SQUID arguments of an address condition: one address,
        a range (between), a subnet (in_subnet) or a list (match_any).
        """
        operator = self.operator
        if operator in ('eq', 'ne'):
            return _ip_function(value, version)
        if operator in ('between', 'notBetween'):
            start, end = _ip_range(value)
            return '{} {}'.format(_ip_function(start, version), _ip_function(end, version))
        if operator.endswith('subnet'):
            address, length = _ip_subnet(value, version)
            return '{} {}'.format(_ip_function(address, version), length)
        args = []
        for item in _ip_items(value):
            if '/' in item:
                address, length = _ip_subnet(item, version)
                args.append('( ipsubnet {} {} )'.format(_ip_function(address, version), length))
            elif '-' in item:
                start, end = _ip_range(item)
                args.append('( iprange {} {} )'.format(_ip_function(start, version),
                                                       _ip_function(end, version)))
            else:
                args.append(_ip_function(item, version))
        return ' '.join(args)

    def display_value(self):
        """
        Returns the value as text, with its unit (e.g. '10240 MB', '2 weeks').
        """
        if self.operator in _NO_VALUE_OPS:
            return ''
        kind, value = self.prop.kind, self.value
        if kind == cat.MEGABYTES:
            return '{} MB'.format(_size(value, _MB_UNITS, 'MB'))
        if kind == cat.BYTES:
            return '{} bytes'.format(_size(value, _BYTE_UNITS, 'bytes'))
        if kind == cat.TIMESTAMP and self.operator in _DURATION_OPS:
            return str(_duration_text(_duration(value)))
        if kind == cat.TIMESTAMP and self.operator in _DATE_OPS:
            return _timestamp_text(_timestamp(value))
        if kind == cat.TIMESTAMP:
            return '{} - {}'.format(_timestamp_text(_timestamp(value[0])),
                                    _timestamp_text(_timestamp(value[1])))
        if kind == cat.ENUM:
            number = self.__enum_value(value)
            return cat.ENUM_VALUES.get(self.prop.key, {}).get(number, str(number))
        if kind == cat.STRING_ENUM:
            code = self.__string_enum_value(value)
            return {**cat.LANGUAGES, **cat.MANAGEMENT_TYPES}.get(code, code)
        if isinstance(value, (list, tuple)):
            return ', '.join(str(item) for item in value)
        return str(value)

    def to_squid(self):
        """
        Returns the condition as SQUID text, e.g.
        '( eq EPOComputerProperties.OSPlatform "Server" )'.
        """
        return '( {} {}{} )'.format(self.operator, self.prop.key,
                                    ' ' + self.args if self.args else '')

    @classmethod
    def from_parsed(cls, item):
        """
        Returns the condition of a parsed SQUID condition (squid_parse()),
        its value given back in the units of TagCondition().

        >>> TagCondition.from_parsed(squid_parse(
        ...     '( gt EPOComputerProperties.FreeDiskSpace 10240 )')).value
        10240
        """
        operator, key, args = item[0], item[1], item[2:]
        prop = TagProperty.from_key(key)
        return cls(prop, operator, _decode_value(prop, operator, args))


def _timestamp_text(milliseconds):
    """
    Returns milliseconds since 1970 as a UTC date "YYYY-MM-DD HH:MM UTC".

    >>> _timestamp_text(1791873000000)
    '2026-10-13 06:30 UTC'
    """
    date = datetime.datetime.fromtimestamp(milliseconds / 1000, datetime.timezone.utc)
    return date.strftime('%Y-%m-%d %H:%M UTC')


def _decode_ip(item):
    """
    Returns the text of a parsed SQUID address item: "( ipv4 "x" )" gives
    'x', iprange 'a-b', ipsubnet 'n/l'.
    """
    if item[0] in ('ipv4', 'ipv6'):
        return str(item[1])
    if item[0] == 'iprange':
        return '{}-{}'.format(_decode_ip(item[1]), _decode_ip(item[2]))
    if item[0] == 'ipsubnet':
        return '{}/{}'.format(_decode_ip(item[1]), item[2])
    raise ValueError('Unknown SQUID address item {}.'.format(item))


def _decode_value(prop, operator, args):
    """
    Returns the value of parsed SQUID arguments, in the units TagCondition()
    takes (sizes in MB or bytes, durations as text, dates as UTC datetimes,
    addresses as text).
    """
    if operator in _NO_VALUE_OPS:
        return None
    kind = prop.kind
    if kind in (cat.IPV4, cat.IPV6):
        if operator in ('eq', 'ne'):
            return _decode_ip(args[0])
        if operator in ('between', 'notBetween'):
            return '{}-{}'.format(_decode_ip(args[0]), _decode_ip(args[1]))
        if operator.endswith('subnet'):
            return '{}/{}'.format(_decode_ip(args[0]), args[1])
        return [_decode_ip(arg) for arg in args]
    if kind == cat.TIMESTAMP:
        def date(milliseconds):
            return datetime.datetime.fromtimestamp(int(milliseconds) / 1000, datetime.timezone.utc)
        if operator in _DURATION_OPS:
            return _duration_text(int(args[0]))
        if operator in _DATE_OPS:
            return date(args[0])
        return (date(args[0][1]), date(args[1][1]))
    value = args[0]
    if kind in (cat.MEGABYTES, cat.BYTES, cat.ENUM):
        return int(value)
    if kind == cat.VERSION2:
        return version2_text(value)
    return str(value)


# ------------------------------ Criteria ------------------------------
class TagCriteria():
    """
    The criteria of a tag: conditions on system properties, all required
    when they are on different properties; the conditions on the same
    property are joined with "and" (default) or "or" (set_grouping()).
    """

    def __init__(self, conditions=None):
        """
        :param: conditions: TagCondition objects or (property, operator,
                            value) tuples.
        """
        self.conditions = []
        self.groupings = {}
        for condition in conditions or []:
            if isinstance(condition, TagCondition):
                self.conditions.append(condition)
            else:
                self.add(*condition)

    def __repr__(self):
        """
        Shows the criteria as text (see __str__()).
        """
        return '<TagCriteria: {}>'.format(self)

    def __str__(self):
        """
        Returns the criteria as text, e.g. "(OS Platform Equals Server or OS
        Platform Equals Workstation) and Free Disk Space Greater than 10240 MB".
        """
        groups = self.__groups()
        texts = []
        for key, conditions in groups:
            text = ' {} '.format(self.groupings.get(key, 'and')).join(str(c) for c in conditions)
            texts.append('({})'.format(text) if len(conditions) > 1 and len(groups) > 1 else text)
        return ' and '.join(texts)

    def __len__(self):
        """
        Returns the number of conditions.
        """
        return len(self.conditions)

    def __iter__(self):
        """
        Iterates over the conditions.
        """
        return iter(self.conditions)

    def __eq__(self, other):
        """
        Two criteria are equal when they give the same SQUID text.
        """
        return isinstance(other, TagCriteria) and self.to_squid() == other.to_squid()

    def __groups(self):
        """
        Returns the conditions grouped by property, in the order of the first
        condition of each property: [(key, [conditions])].
        """
        groups = {}
        for condition in self.conditions:
            groups.setdefault(condition.prop.key, []).append(condition)
        return list(groups.items())

    def add(self, prop, operator, value=None):
        """
        Adds a condition and returns the criteria (calls can be chained).

        >>> TagCriteria().add('Is 64-bit OS', 'eq', 'Yes')
        <TagCriteria: Is 64-bit OS Equals Yes>
        """
        self.conditions.append(TagCondition(prop, operator, value))
        return self

    def remove(self, prop=None, operator=None):
        """
        Removes the conditions of a property (all, or the ones with this
        operator) and returns how many were removed.
        """
        key = TagProperty.get(prop).key if prop else None
        kept = [c for c in self.conditions
                if not ((key is None or c.prop.key == key) and
                        (operator is None or c.operator == operator))]
        removed = len(self.conditions) - len(kept)
        self.conditions = kept
        return removed

    def set_grouping(self, prop, grouping):
        """
        Joins the conditions of a property with "and" or "or" (the console
        list shown from the second condition of a property).

        >>> TagCriteria().set_grouping('OS Platform', 'xor')
        Traceback (most recent call last):
        ValueError: Grouping must be "and" or "or".
        """
        if grouping not in ('and', 'or'):
            raise ValueError('Grouping must be "and" or "or".')
        self.groupings[TagProperty.get(prop).key] = grouping

    def to_squid(self):
        """
        Returns the criteria as the SQUID expression ePO stores, or '' when
        there is no condition (a manual tag).
        """
        if not self.conditions:
            return ''
        parts = []
        for key, conditions in self.__groups():
            if len(conditions) == 1:
                parts.append(conditions[0].to_squid())
            else:
                parts.append('( {} {} )'.format(self.groupings.get(key, 'and'),
                                                ' '.join(c.to_squid() for c in conditions)))
        if len(parts) == 1:
            return '( where {} )'.format(parts[0])
        return '( where ( and {} ) )'.format(' '.join(parts))

    @classmethod
    def from_squid(cls, text):
        """
        Returns the criteria of a SQUID expression (the "criteria" of a tag
        export), or None for an empty one.

        :raise: ValueError: An expression the console builder can't show
                            (e.g. an "or" between different properties).

        >>> TagCriteria.from_squid('( where ( and ( or ( eq EPOComputerProperties.OSPlatform '
        ...                        '"Server" ) ( eq EPOComputerProperties.OSPlatform "Workstation"'
        ...                        ' ) ) ( eq EPOComputerProperties.IsPortable 0 ) ) )')
        ... # doctest: +NORMALIZE_WHITESPACE
        <TagCriteria: (OS Platform Equals Server or OS Platform Equals Workstation)
        and Is Laptop Equals No>
        """
        if not text or not text.strip():
            return None
        tree = squid_parse(text)
        if not (isinstance(tree, list) and len(tree) == 2 and tree[0] == 'where'):
            raise ValueError('A tag criteria must be "( where ... )": {}'.format(text))
        criteria = cls()
        node = tree[1]
        children = node[1:] if node and node[0] == 'and' else [node]
        for child in children:
            if child[0] in ('and', 'or'):
                keys = {grand_child[1] for grand_child in child[1:]}
                if len(keys) != 1 or any(g[0] in ('and', 'or') for g in child[1:]):
                    raise ValueError('Criteria not supported by the console builder: {}'
                                     .format(text))
                for grand_child in child[1:]:
                    criteria.conditions.append(TagCondition.from_parsed(grand_child))
                criteria.groupings[keys.pop()] = child[0]
            else:
                criteria.conditions.append(TagCondition.from_parsed(child))
        return criteria


# ------------------------------ Tags ------------------------------
class Tag():
    """
    An ePO tag: name, notes, criteria (None for a manual tag), evaluation
    and tag group. The other attributes come from the server (read only).

    >>> Tag('OFF', 'Used to apply OFF policies.').check()
    >>> Tag('X' * 51).check()
    Traceback (most recent call last):
    ValueError: Tag name longer than 50 characters (console limit).
    """

    def __init__(self, name, notes='', criteria=None, evaluate_on_asci=False, group=None):
        """
        :param: name: The tag name (50 characters, unique without case).
        :param: notes: The notes.
        :param: criteria: A TagCriteria, a list of (property, operator,
                          value) tuples, or None for a manual tag.
        :param: evaluate_on_asci: Also evaluate the criteria on each
                                  agent-server communication (else only
                                  with the "Run Tag Criteria" action).
        :param: group: The tag group path under "My Tags", e.g. 'Policy
                       Management' or 'Policy Management/OFF tags'; None or
                       '' for "My Tags".
        """
        self.name = name
        self.notes = notes or ''
        if criteria is not None and not isinstance(criteria, TagCriteria):
            criteria = TagCriteria(criteria)
        self.criteria = criteria if criteria else None
        self.evaluate_on_asci = bool(evaluate_on_asci)
        self.group = group or ''
        # Read from the server. tag_type is 'manual' (no criteria),
        # 'criteria' (criteria run on demand) or 'mixed' (criteria also
        # evaluated on each agent-server communication).
        self.id = None
        self.uniquekey = None
        self.family = 'EPO'
        self.tag_type = None
        self.assigned_systems = None
        self.usage_count = None
        self.created_by = None
        self.modified_on = None
        self.whereclause = ''

    def __repr__(self):
        """
        Shows the name, the group and the criteria.
        """
        return '<Tag {}{}{}>'.format(self.name, ' in ' + self.group if self.group else '',
                                     ': ' + str(self.criteria) if self.criteria else ' (manual)')

    def check(self):
        """
        Checks the tag as the console does before a save.

        :raise: ValueError: Empty name, name longer than 50 characters, group
                            "Deployment Tags" (not supported by the import).
        """
        if not self.name or not self.name.strip():
            raise ValueError('A tag name is required.')
        if len(self.name) > MAX_TAG_NAME:
            raise ValueError('Tag name longer than {} characters (console limit).'
                             .format(MAX_TAG_NAME))
        if self.group.split('/')[0].lower() == DEPLOYMENT_GROUP.lower():
            raise ValueError('The "{}" group is not supported (the tag import ignores it).'
                             .format(DEPLOYMENT_GROUP))

    def to_element(self):
        """
        Returns the EPOTag element of the tag import: the id is required but
        not used by the server (0), the whereclause is computed by the server
        from the criteria, the group is set after the import (see
        EPOTags.save()).
        """
        return et.Element('EPOTag', {
            'name': self.name, 'id': '0', 'notes': self.notes,
            'uniquekey': self.uniquekey or 'null', 'family': self.family or 'EPO',
            'criteria': self.criteria.to_squid() if self.criteria else '', 'whereclause': '',
            'executeonasci': 'true' if self.evaluate_on_asci else 'false'})

    @classmethod
    def from_element(cls, element):
        """
        Returns the tag of an EPOTag element of a tag export (the group is
        the "taggroup" attribute: the name of the group, not its path; see
        EPOTags.list() for the path).
        """
        criteria = element.get('criteria', '')
        try:
            parsed = TagCriteria.from_squid(criteria)
        except ValueError:
            parsed = RawCriteria(criteria)
        tag = cls(element.get('name'), element.get('notes', ''), parsed,
                  element.get('executeonasci') == 'true', element.get('taggroup', ''))
        tag.id = int(element.get('id')) if element.get('id', '').isdigit() else None
        uniquekey = element.get('uniquekey')
        tag.uniquekey = None if uniquekey in (None, 'null') else uniquekey
        tag.family = element.get('family', 'EPO')
        tag.whereclause = element.get('whereclause', '')
        return tag


class RawCriteria(TagCriteria):
    """
    A criteria the console builder can't show (made by another tool): kept
    as its SQUID text, written back unchanged, not editable.
    """

    def __init__(self, squid):
        """
        :param: squid: The SQUID text of the criteria.
        """
        super(RawCriteria, self).__init__()
        self.squid = squid

    def __str__(self):
        """
        Returns the SQUID text.
        """
        return self.squid

    def __len__(self):
        """
        Counts as one condition (the criteria is not empty).
        """
        return 1

    def add(self, prop, operator, value=None):
        """
        Refused: the criteria is not editable.
        """
        raise ValueError('This criteria is not editable: {}'.format(self.squid))

    def to_squid(self):
        """
        Returns the SQUID text unchanged.
        """
        return self.squid


class TagList():
    """
    The tags of a tag export (system.exportTag), or a new list to import
    (system.importTag).
    """

    NAMESPACE = 'mcafee-epo-policyassignmentrule'

    def __init__(self, xml=None):
        """
        :param: xml: The XML of system.exportTag (bytes or text), or None for
                     an empty list.
        """
        self.tags = []
        if xml is not None:
            root = et.fromstring(xml if isinstance(xml, bytes) else xml.encode('utf-8'))
            self.tags = [Tag.from_element(element) for element in root.findall('EPOTag')]

    def __repr__(self):
        """
        Shows the number of tags.
        """
        return '<TagList of {} tag(s)>'.format(len(self.tags))

    def __iter__(self):
        """
        Iterates over the tags.
        """
        return iter(self.tags)

    def get(self, name):
        """
        Returns the tag of this name (case ignored, as ePO does), or None.
        """
        for tag in self.tags:
            if tag.name.strip().lower() == name.strip().lower():
                return tag
        return None

    def get_xml_content(self):
        """
        Returns the XML to import (bytes; the characters out of ASCII as XML
        references, as for the policy import).
        """
        et.register_namespace('epo', self.NAMESPACE)
        root = et.Element('{%s}EPOTagSchema' % self.NAMESPACE)
        for tag in self.tags:
            root.append(tag.to_element())
        return et.tostring(root, encoding='us-ascii', xml_declaration=True)
