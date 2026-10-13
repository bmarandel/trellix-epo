# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the classes EDRFPolicyRemediation (Trellix EDR with
Forensics: Remediation - Host Remediation, Containment Settings) and
EDRFAllowedIP.

Storage learnt from test policies changed in the ePO 5.10 console
(extensions XCLIENT_META 2.1.2.270 and 50.3.0.900):

- The ePO server escapes the double quotes of the settings (\\"); the
  console doubles the backslashes of the text areas (containment
  messages, application paths), line breaks replaced by semicolons (the
  console shows the semicolons when the policy is opened again).
- Since the extension 50.3 the application paths and the containment page
  settings (messages, image, HTML page, favicon) are split in 3072
  character parts by the ePO server (see EDRFPolicy) and their double
  quotes are no longer escaped. The Remediation page reads its settings
  with JSON.parse('...'): such a " stops the console from opening the
  policy (checked on the lab, a " typed in the containment message), so the
  library refuses " in them.
- Containment page (extension 50.3): "Enter by hand" (byhand_enabled) or
  "From URL" (url_enabled), two radio buttons. By hand, the console saves
  the title (100 characters), the message, the logo (a JPG, PNG or GIF of
  1000 KB at most: containment_notify_image = its base64 content,
  containment_notify_image_name = its file name), the HTML page shown on
  the device (containment_notify_html = base64 of the page built from
  them, see HTML_PAGE) and the console favicon (favicon, base64), and
  clears the URL. From URL, it saves the URL (100 characters, an http(s)
  address with an IP address, optional port and .html page), resets the
  title and the message to their defaults and clears the logo and the
  page. The library does the same, except for the favicon (an image of
  the extension): it keeps the one of the policy.
- Allowed IP Addresses: a JSON list, Allowed_IP_Addresses =
  [{"IP_Address":"10.0.0.10","description":"SOC jump host"}, ...] (rows in
  the order they were added), its quotes escaped as above. The console
  accepts an IPv4 address, a DNS host name or an IPv6 address (any short
  form since the extension 50.3, the 2.1.2 refused "fd00::10"), 100
  characters at most, and refuses duplicates. A description with " or \\
  is stored with a backslash the console page cannot read back (the policy
  no longer opens, checked on the lab): the library refuses them.
- The uncontainment password is hashed with a random salt by the ePO
  server: the library never defines it.
"""

import base64
import json
import re

from ..validators import is_ip_or_hostname
from .policy import EDRFPolicy, CHECK, SELECT, TEXT, LIST

NF = 'UEDR/NetworkFlow/'
DEFAULT_TITLE = 'Trellix Security Alert'
DEFAULT_MESSAGE = ('WARNING: Endpoint Contained. Your device has been disconnected from the '
                   'network and can only connect to the Trellix management console.')
# HTML page built by the console (Remediation.js of the extension 50.3).
HTML_PAGE = ('<html><head><meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>'
             '<style>#content-area-wrapper { width: 600px; margin: auto; overflow: hidden; } '
             '#content-area { line-height: 20px; white-space: pre-wrap; white-space: '
             '-moz-pre-wrap; word-wrap: break-word; font-family: sans-serif; } img { max-width: '
             '100%; } body, html { width: 100%; }</style>{title}<link rel="shortcut icon" '
             'href="./favicon.ico" type="image/x-icon"></head><body><div '
             'id="content-area-wrapper">{image}{content}</div></body></html>')
_HD = '[0-9a-fA-F]{1,4}'
_D = '(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
_IPV4 = '(?:' + _D + r'\.){3}' + _D
_IPV6 = ('(?:(?:{h}:){{7}}{h}|(?:{h}:){{1,7}}:|(?:{h}:){{1,6}}:{h}|(?:{h}:){{1,5}}(?::{h}){{1,2}}|'
         '(?:{h}:){{1,4}}(?::{h}){{1,3}}|(?:{h}:){{1,3}}(?::{h}){{1,4}}|(?:{h}:){{1,2}}(?::{h}){{1,5}}|'
         '{h}:(?::{h}){{1,6}}|:(?::{h}){{1,7}}|::|(?:{h}:){{6}}{v4}|::(?:ffff(?::0{{1,4}})?:)?{v4}|'
         '(?:{h}:){{1,4}}:{v4})').format(h=_HD, v4=_IPV4)
# Containment URL check of the console (IsValidContainmentURL).
CONTAINMENT_URL = re.compile(r'^https?:\/\/(?![^\/]*\[)(' + _IPV4 + r'|(?![^\/:]*[g-zG-Z])' +
                             _IPV6 + r')(?::\d+)?(?:\/+.*\.html?)?\/?$', re.IGNORECASE)
IMAGE_TYPES = ('.jpg', '.jpeg', '.png', '.gif')
MAX_IMAGE_SIZE = 1024000           # bytes (1000 KB)


def _js_replace(text, pattern, replacement):
    """
    String.prototype.replace of JavaScript with a string pattern: the
    first occurrence only, $$, $&, $` and $' of the replacement interpreted.
    """
    index = text.find(pattern)
    if index < 0:
        return text
    special = {'$': '$', '&': pattern, '`': text[:index], "'": text[index + len(pattern):]}
    value = re.sub(r"\$([$&`'])", lambda match: special[match.group(1)], replacement)
    return text[:index] + value + text[index + len(pattern):]


class EDRFAllowedIP():
    """
    An address a contained host can still connect to (Allowed IP Addresses).

    :param: address: IP Address or DNS Hostname.
    :param: description: Description.
    """

    def __init__(self, address, description=''):
        self.address = address
        self.description = description or ''

    def __repr__(self):
        return 'EDRFAllowedIP({!r}, {!r})'.format(self.address, self.description)

    def __eq__(self, other):
        return isinstance(other, EDRFAllowedIP) and self.to_dict() == other.to_dict()

    @classmethod
    def from_dict(cls, item):
        return cls(item.get('IP_Address', ''), item.get('description', ''))

    def to_dict(self):
        return {'IP_Address': self.address, 'description': self.description}

    def check(self):
        """
        Raise ValueError if the console would refuse the address.
        """
        if not is_ip_or_hostname(self.address):
            raise ValueError('Please enter correct IP Address/DNS Hostname: {!r}'.format(
                self.address))
        if len(self.address) > 100 or len(self.description) > 100:
            raise ValueError('IP Address and Description: 100 characters max each.')
        if '"' in self.description or '\\' in self.description:
            raise ValueError('A description with \\ or " stops the console from opening the '
                             'policy: {!r}'.format(self.description))


class EDRFPolicyRemediation(EDRFPolicy):
    """
    The EDRFPolicyRemediation class can be used to edit the Trellix EDR with
    Forensics policy: Remediation.
    """
    MD_CATEGORY = 'Remediation'
    TYPE = 'Remediation'
    ALLOWED_IP_SETTING = 'Allowed_IP_Addresses'

    OPTIONS = {
        'host_remediation': ('mxa/container/HostRemediation/enabled', 'Enable Host Remediation',
                             CHECK),
        'display_message': (NF + 'display_quarantine',
                            'Enable the option to display the message on containment actions',
                            CHECK),
        'message_source': (NF + 'byhand_enabled', 'Message settings when it is contained', SELECT,
                           {'byhand': 'Enter by hand', 'url': 'From URL'}),
        'containment_title': (NF + 'containment_title', 'Title', TEXT, 100),
        'containment_message': (NF + 'quarantine_message',
                                'Message to display on a device when it is contained', TEXT,
                                200000),
        'containment_url': (NF + 'containment_url', 'From URL', TEXT, 100),
        'release_message': (NF + 'unquarantine_message', 'Message to display on a device when it '
                            'is removed from the containment', TEXT, 200000),
        'uncontain_password': (NF + 'unquarantine_password_enabled',
                               'Enable password to uncontain the endpoint (Windows only)', CHECK),
        'windows_allowed_paths': (NF + 'allow_paths_windows',
                                  'Exclude application paths from containment for Windows', LIST,
                                  True),
        'mac_allowed_paths': (NF + 'allow_paths_macos',
                              'Exclude application paths from containment for macOS', LIST, False),
        'linux_allowed_paths': (NF + 'allow_paths_linux',
                                'Exclude application paths from containment for linux', LIST,
                                False),
    }
    DEFAULTS = {'mxa/container/HostRemediation/enabled': 'false', NF + 'allow_paths_linux': '',
                ALLOWED_IP_SETTING: '', NF + 'byhand_enabled': 'true', NF + 'url_enabled': 'false',
                NF + 'containment_title': DEFAULT_TITLE, NF + 'containment_url': '',
                NF + 'containment_notify_image': '', NF + 'containment_notify_image_name': '',
                NF + 'containment_notify_html': '', NF + 'favicon': ''}
    ESCAPE_QUOTES = True
    DOUBLE_BACKSLASHES = (NF + 'quarantine_message', NF + 'unquarantine_message',
                          NF + 'allow_paths_windows', NF + 'allow_paths_macos',
                          NF + 'allow_paths_linux')
    CHUNKED = DOUBLE_BACKSLASHES + (NF + 'containment_notify_image', NF + 'containment_notify_html',
                                    NF + 'favicon')
    QUOTES_BREAK_CHUNKS = True
    # Options of the "Enter by hand" containment page.
    BYHAND_OPTIONS = ['containment_title', 'containment_message']
    SECRETS = {'uncontain_password': NF + 'unquarantine_salted_password'}

    def get_option(self, name):
        """
        Get an option (see EDRFPolicy.get_option); message_source is 'byhand'
        or 'url'.
        """
        if name == 'message_source':
            return 'url' if self._get(NF + 'url_enabled') == 'true' else 'byhand'
        return super(EDRFPolicyRemediation, self).get_option(name)

    def set_option(self, name, value):
        """
        Set an option, checked as in the console (see EDRFPolicy.set_option).
        The containment page settings are saved as the console saves them:
        "Enter by hand" rebuilds the HTML page and clears the URL, "From URL"
        resets the title and the message and clears the logo and the page.
        """
        label = self.OPTIONS[name][1]
        if name == 'message_source':
            if value not in self.OPTIONS[name][3]:
                raise ValueError('{} must be within {}.'.format(label, list(self.OPTIONS[name][3])))
            self._set(NF + 'byhand_enabled', 'true' if value == 'byhand' else 'false')
            self._set(NF + 'url_enabled', 'true' if value == 'url' else 'false')
            if value == 'byhand':
                self._set(NF + 'containment_url', '')
                self.update_containment_page()
            else:
                self._typed_message = None
                self._set(NF + 'containment_title', DEFAULT_TITLE)
                self._set(NF + 'quarantine_message', DEFAULT_MESSAGE)
                for setting in ['containment_notify_html', 'containment_notify_image',
                                'containment_notify_image_name']:
                    self._set(NF + setting, '')
            return True
        if name in ('containment_title', 'containment_message', 'release_message', 'containment_url'):
            value = str(value)
            if not value.strip():
                raise ValueError('{} is required.'.format(label))
        if name in self.BYHAND_OPTIONS and self.get_option('message_source') != 'byhand':
            raise ValueError('{}: select "Enter by hand" first (message_source).'.format(label))
        if name == 'containment_url':
            if self.get_option('message_source') != 'url':
                raise ValueError('{}: select "From URL" first (message_source).'.format(label))
            if not CONTAINMENT_URL.search(value.strip()):
                raise ValueError('Please enter a valid url (http(s), IP address, optional port '
                                 'and .html page): {!r}'.format(value))
        if name in ('containment_message', 'release_message'):
            if len(value) > self.OPTIONS[name][3]:
                raise ValueError('{}: {} characters max.'.format(label, self.OPTIONS[name][3]))
            message = value
            value = value.replace('\n', ';')         # as the console text area
        result = super(EDRFPolicyRemediation, self).set_option(name, value)
        if name == 'containment_message':
            self._typed_message = message
            self.update_containment_page()
        elif name == 'containment_title':
            self.update_containment_page()
        return result

    # ------------------------------ Containment page ------------------------------
    def get_containment_image(self):
        """
        Get the logo of the containment page: (file name, content as bytes),
        or None.
        """
        name = self._get(NF + 'containment_notify_image_name')
        data = self._get(NF + 'containment_notify_image')
        if not name or not data:
            return None
        return name, base64.b64decode(data)

    def set_containment_image(self, name, data):
        """
        Set the logo of the containment page ("Add Logo"): its file name
        (.jpg, .jpeg, .png or .gif) and its content (bytes, 1000 KB max).
        """
        if self.get_option('message_source') != 'byhand':
            raise ValueError('Logo: select "Enter by hand" first (message_source).')
        if not str(name).lower().endswith(IMAGE_TYPES) or '/' in name or '\\' in name:
            raise ValueError('Invalid file type. Please select a JPG, PNG, or GIF: {!r}'.format(
                name))
        if '"' in name:
            raise ValueError('Logo: " is not supported in the file name: {!r}'.format(name))
        if len(data) > MAX_IMAGE_SIZE:
            raise ValueError('File exceeds size limit of 1000 KBs.')
        self._set(NF + 'containment_notify_image', base64.b64encode(data).decode('ascii'))
        self._set(NF + 'containment_notify_image_name', name)
        self.update_containment_page()

    def clear_containment_image(self):
        """
        Remove the logo of the containment page.
        """
        self._set(NF + 'containment_notify_image', '')
        self._set(NF + 'containment_notify_image_name', '')
        self.update_containment_page()

    def get_containment_page(self):
        """
        Get the HTML page shown on a contained device ('' if none).
        """
        value = self._get(NF + 'containment_notify_html')
        return base64.b64decode(value).decode('utf-8') if value else ''

    def build_containment_page(self):
        """
        Returns the HTML page the console builds from the title, the
        message and the logo name. The message is the text of the console
        field: the one given to set_option() (with its line breaks), else
        the stored one (line breaks shown as semicolons once saved).
        """
        title = self._get(NF + 'containment_title') or DEFAULT_TITLE
        message = getattr(self, '_typed_message', None)
        if message is None:
            message = self._get(NF + 'quarantine_message') or ''
        page = _js_replace(HTML_PAGE, '{title}', '<title>' + title + '</title>')
        page = _js_replace(page, '{content}',
                           '<pre id="content-area">' + message + '</pre>' if message else '')
        return _js_replace(page, '{image}', '<img src="' +
                           (self._get(NF + 'containment_notify_image_name') or '') + '" />')

    def update_containment_page(self):
        """
        Store the HTML page of an "Enter by hand" containment page, as the
        console does when the policy is saved.
        """
        if self.get_option('message_source') == 'byhand':
            page = self.build_containment_page()
            self._set(NF + 'containment_notify_html',
                      base64.b64encode(page.encode('utf-8')).decode('ascii'))

    # ------------------------------ Allowed IP Addresses ------------------------------
    def get_allowed_ips(self):
        """
        Get the Allowed IP Addresses (list of EDRFAllowedIP).
        """
        value = self._get(self.ALLOWED_IP_SETTING)
        if not value:
            return []
        return [EDRFAllowedIP.from_dict(item) for item in json.loads(value)]

    def set_allowed_ips(self, addresses):
        """
        Set the Allowed IP Addresses (list of EDRFAllowedIP), checked as in
        the console (valid address, no duplicate).
        """
        seen = set()
        for address in addresses:
            address.check()
            if address.address in seen:
                raise ValueError('Duplicate IP: {!r}'.format(address.address))
            seen.add(address.address)
        return self._set(self.ALLOWED_IP_SETTING, json.dumps(
            [address.to_dict() for address in addresses], separators=(',', ':'),
            ensure_ascii=False))

    allowed_ips = property(get_allowed_ips, set_allowed_ips)

    def add_allowed_ip(self, address):
        """
        Add an allowed address (Add button of the console).
        """
        return self.set_allowed_ips(self.get_allowed_ips() + [address])

    def remove_allowed_ip(self, address):
        """
        Remove an allowed address (IP Address or DNS Hostname).
        """
        addresses = self.get_allowed_ips()
        kept = [item for item in addresses if item.address != address]
        if len(kept) == len(addresses):
            raise ValueError('No allowed address {!r}.'.format(address))
        return self.set_allowed_ips(kept)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        one per console group box (see Policy.to_markdown).
        """
        rows = self.md_rows(['display_message', 'message_source'])
        if self.get_option('message_source') == 'url':
            rows += self.md_rows(['containment_url'])
        else:
            rows += self.md_rows(['containment_title'])
            image = self.get_containment_image()
            rows.append(['Logo', '{} ({} bytes)'.format(image[0], len(image[1])) if image else
                         'None'])
            rows += self.md_rows(['containment_message'])
        rows += self.md_rows(['release_message', 'uncontain_password'])
        if self.get_option('uncontain_password') == '1':
            rows.append(['Password', 'Defined in the ePO console (not exported)'])
        text = self.md_settings(rows)
        text += '\n### Exclusions\n\n' + self.md_list('windows_allowed_paths')
        text += '\n' + self.md_list('mac_allowed_paths')
        text += '\n' + self.md_list('linux_allowed_paths')
        text += '\n### Allowed IP Addresses\n\n' + self.md_table(
            ['IP Address or DNS Hostname', 'Description'],
            [[item.address, item.description] for item in self.get_allowed_ips()], numbered=True)
        return [('Host Remediation', self.md_settings(self.md_rows(['host_remediation']))),
                ('Containment Settings', text)]
