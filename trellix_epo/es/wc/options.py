# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESWCPolicyOptions (Endpoint Security Web
Control: Options).

Storage learnt from a test policy changed in the ePO 5.10 console: sections
WebProtection, EventLogging, ActionEnforcement and SecureSearch; the IP
address lists are ActionEnforcement.szGatewayIP_<n> (uiGatewayIPCount),
szIntLandIP_<n> (uiIntLandIPCount) and szAgumentIP_<n> (uiAgumentIPCount),
one address or range per setting. The Web Reporter password (elPassword)
is required by the console to send events to Web Reporter: it is only kept
by the library, never set nor written in the Markdown export.
"""

from .common import ESWCPolicy
from ...validators import (check_length, is_wc_domain_name, is_wc_gateway_ip_list,
                           is_wc_ip_list, is_wc_reporter_url)


class ESWCPolicyOptions(ESWCPolicy):
    """
    The ESWCPolicyOptions class can be used to edit the Endpoint Security Web
    Control policy: Options (checked against the ePO 5.10 console).
    """
    TYPE = 'EWC_General'
    MD_CATEGORY = 'Options'

    # Apply this action to sites not yet verified by Trellix GTI.
    UNVERIFIED_ACTIONS = {'1': 'Allow', '2': 'Warn', '0': 'Block'}
    GTI_SENSITIVITY = {'0': 'Very Low', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Very High'}
    SEARCH_ENGINES = {'0': 'Yahoo', '1': 'Google', '2': 'Bing', '3': 'Ask'}

    # Checkbox settings: setting name -> (section, console label).
    __CHECKBOXES = {
        'bEnableWebProtection': ('WebProtection', 'Enable Web Control'),
        'bDisableUserBrowserPlugin': ('WebProtection', 'Enable WC Browser Plugin (Edge and '
                                                       'Chrome) (Windows only)'),
        'bAllowIEInExtOffMode': ('WebProtection', 'Allow user to run Internet Explorer in '
                                                  'extension-off mode (Windows only)'),
        'bHideToolbar': ('WebProtection', 'Hide the toolbar on the client browser (Windows '
                                          'only)'),
        'bStandDown': ('ActionEnforcement', 'Disable if a web gateway appliance is detected'),
        'bGatewayIPValidate': ('ActionEnforcement', "Use your organization's default gateway"),
        'bGatewayPresenceValidate': ('ActionEnforcement', 'Detect web gateway enforcement'),
        'bGatewayLandmarkValidate': ('ActionEnforcement', 'Specify internal landmark to use'),
        'bStandDownMCPValidate': ('WebProtection', 'Disable if Skyhigh Client Proxy is '
                                                   'detected'),
        'bGreenRatedSites': ('EventLogging', 'Log web categories for green rated sites'),
        'bAllowedConfiguredBlockAllowList': ('EventLogging', 'Log events for allowed sites '
                                                             'configured in the Block and '
                                                             'Allow List'),
        'bLogIFrameEvents': ('EventLogging', 'Log Web Control iFrame events (Windows only)'),
        'bInformWebReporter': ('EventLogging', 'Send browser page views and downloads to Web '
                                               'Reporter (increases network activity) '
                                               '(Windows only)'),
        'unverifiedOverride': ('ActionEnforcement', 'Allow Green-rated file downloads from not '
                                                    'yet verified URL'),
        'bEnableHTMLiFrames': ('ActionEnforcement', 'Enable HTML iFrames support (Windows '
                                                    'only)'),
        'bGtiFailClose': ('ActionEnforcement', 'Block sites by default if Trellix GTI ratings '
                                               'server is not reachable'),
        'bPhishingBlock': ('ActionEnforcement', 'Block phishing pages for all sites (Includes '
                                                'Allowed sites and overrides content rating '
                                                'actions)'),
        'bAllowWarnAtDomainLevel': ('ActionEnforcement', 'Allow warn action at domain level '
                                                         '(Web Control will not generate '
                                                         'warnings within the same domain) '
                                                         '(Windows only)'),
        'bSiteObserve': ('ActionEnforcement', 'Enable Observe mode (Events are generated but '
                                              'actions are not enforced) (Windows only)'),
        'bEnfFileDownloads': ('ActionEnforcement', 'Enable file scanning for file downloads '
                                                   '(Windows only)'),
        'bEnfIMEmailLinkChecking': ('ActionEnforcement', 'Enable annotations in browser-based '
                                                         'email'),
        'bEnfIMEmailLinkHookChecking': ('ActionEnforcement', 'Enable annotations in non '
                                                             'browser-based email'),
        'bAllowAllPrivateUrls': ('ActionEnforcement', 'Allow all IP addresses in the local '
                                                      'network'),
        'bEnableSecureSearch': ('SecureSearch', 'Enable Secure Search (Windows only)'),
        'uiSecureResults': ('SecureSearch', 'Block links to risky sites in search results'),
    }
    # IP address lists: name -> (count setting, item template).
    __LISTS = {'gateway_ips': ('uiGatewayIPCount', 'szGatewayIP_{}'),
               'landmark_ips': ('uiIntLandIPCount', 'szIntLandIP_{}'),
               'excluded_ips': ('uiAgumentIPCount', 'szAgumentIP_{}')}

    @classmethod
    def options(cls):
        """
        Returns the checkbox options as a dict {setting name: console label}.
        """
        return {setting: label for setting, (_, label) in cls.__CHECKBOXES.items()}

    def get_option(self, setting):
        """
        Get the value ('1' or '0') of a checkbox option, e.g.
        get_option('bPhishingBlock'). See ESWCPolicyOptions.options().
        """
        return self._get(self.__CHECKBOXES[setting][0], setting)

    def set_option(self, setting, mode):
        """
        Set a checkbox option ('1' or '0'), e.g. set_option('bSiteObserve', '1').
        """
        return self._set_checkbox(self.__CHECKBOXES[setting][0], setting, mode)

    # ------------------------------ Web Control ------------------------------
    def get_web_control(self):
        """
        Get state of Enable Web Control ('1' or '0').
        """
        return self.get_option('bEnableWebProtection')

    def set_web_control(self, mode):
        """
        Set state of Enable Web Control ('1' or '0').
        """
        return self.set_option('bEnableWebProtection', mode)

    web_control = property(get_web_control, set_web_control)

    # Web Control Interlock: IP address lists (one address or range per item).
    def __get_ips(self, name):
        count, template = self.__LISTS[name]
        return self._get_list('ActionEnforcement', count, template)

    def __set_ips(self, name, addresses):
        """
        The console textarea holds the items joined by commas (less than
        16000 characters); the server splits it on commas and trims each
        item. Gateway and landmark items are IPv4 or IPv6 addresses
        (is_wc_gateway_ip_list), excluded items are addresses, subnets or
        ranges (is_wc_ip_list).
        """
        count, template = self.__LISTS[name]
        items = [str(address).strip() for address in addresses]
        check = is_wc_ip_list if name == 'excluded_ips' else is_wc_gateway_ip_list
        for item in items:
            if not item or ',' in item or not check(item):
                raise ValueError('Invalid IP address{}: {!r}'.format(
                    ', subnet or range' if name == 'excluded_ips' else '', item))
        if not check(','.join(items)):
            raise ValueError('The IP addresses take {} characters at most once joined by '
                             'commas.'.format(15999))
        return self._set_list('ActionEnforcement', count, template, items)

    def get_gateway_ips(self):
        """
        Get the IP addresses of "Use your organization's default gateway".
        """
        return self.__get_ips('gateway_ips')

    def set_gateway_ips(self, addresses):
        """
        Set the IP addresses of "Use your organization's default gateway".
        """
        return self.__set_ips('gateway_ips', addresses)

    gateway_ips = property(get_gateway_ips, set_gateway_ips)

    def get_landmark_dns(self):
        """
        Get the DNS name for internal landmark.
        """
        return self._get('ActionEnforcement', 'szGatewayLandmark')

    def set_landmark_dns(self, name):
        """
        Set the DNS name for internal landmark (255 characters, labels of
        letters, digits and - starting with a letter, see is_wc_domain_name;
        '' or None = no name).
        """
        name = check_length('DNS name for internal landmark', name or '', 255)
        if name and not is_wc_domain_name(name):
            raise ValueError('Invalid DNS name for internal landmark: {!r}'.format(name))
        return self._set('ActionEnforcement', 'szGatewayLandmark', name)

    landmark_dns = property(get_landmark_dns, set_landmark_dns)

    def get_landmark_ips(self):
        """
        Get the IP addresses for internal landmark.
        """
        return self.__get_ips('landmark_ips')

    def set_landmark_ips(self, addresses):
        """
        Set the IP addresses for internal landmark.
        """
        return self.__set_ips('landmark_ips', addresses)

    landmark_ips = property(get_landmark_ips, set_landmark_ips)

    # ------------------------------ Event Logging ------------------------------
    def get_web_reporter(self):
        """
        Get the Web Reporter configuration: a dict with 'enabled' ('1'/'0'),
        'url', 'user' and 'password_set' (the password itself is never
        returned).
        """
        return {'enabled': self.get_option('bInformWebReporter'),
                'url': self._get('EventLogging', 'elURL'),
                'user': self._get('EventLogging', 'elUsername'),
                'password_set': bool(self._get('EventLogging', 'elPassword'))}

    def set_web_reporter(self, enabled, url=None, user=None):
        """
        Set the Web Reporter configuration (None = keep the current value).
        The console requires a URL (50 characters, see is_wc_reporter_url), a
        user name (50 characters) and a password: the password can only be defined in the ePO
        console, the library keeps it as is.
        """
        if url is not None:
            check_length('Web Reporter URL', url, 50)
            if url and not is_wc_reporter_url(url):
                raise ValueError('Invalid Web Reporter URL: {!r}'.format(url))
        if user is not None:
            check_length('Web Reporter user name', user, 50)
        if url is not None:
            self._set('EventLogging', 'elURL', url)
        if user is not None:
            self._set('EventLogging', 'elUsername', user)
        if str(enabled) == '1':
            reporter = self.get_web_reporter()
            if not (reporter['url'] and reporter['user']):
                raise ValueError('Web Reporter needs a URL and a user name.')
            if not reporter['password_set']:
                raise ValueError('No Web Reporter password in this policy: define it in the '
                                 'ePO console first.')
        return self.set_option('bInformWebReporter', enabled)

    # ------------------------------ Action Enforcement ------------------------------
    def get_unverified_action(self):
        """
        Get the action applied to sites not yet verified by Trellix GTI: '1'
        Allow, '2' Warn, '0' Block.
        """
        return self._get('ActionEnforcement', 'applyActionNonGTI')

    def set_unverified_action(self, action):
        """
        Set the action applied to sites not yet verified by Trellix GTI: '1'
        Allow, '2' Warn, '0' Block.
        """
        if str(action) not in self.UNVERIFIED_ACTIONS:
            raise ValueError('The action must be "1" (Allow), "2" (Warn) or "0" (Block).')
        return self._set('ActionEnforcement', 'applyActionNonGTI', action)

    unverified_action = property(get_unverified_action, set_unverified_action)

    def get_gti_sensitivity(self):
        """
        Get the Trellix GTI sensitivity level of the file scanning for file
        downloads: '0' Very Low to '4' Very High.
        """
        return self._get('ActionEnforcement', 'gtiRiskLevelToBlock')

    def set_gti_sensitivity(self, level):
        """
        Set the Trellix GTI sensitivity level of the file scanning for file
        downloads: '0' Very Low to '4' Very High.
        """
        if str(level) not in self.GTI_SENSITIVITY:
            raise ValueError('The sensitivity level must be within {}.'.format(
                list(self.GTI_SENSITIVITY)))
        return self._set('ActionEnforcement', 'gtiRiskLevelToBlock', level)

    gti_sensitivity = property(get_gti_sensitivity, set_gti_sensitivity)

    # ------------------------------ Exclusions ------------------------------
    def get_excluded_ips(self):
        """
        Get the IP addresses or ranges to exclude from Web Control rating or
        blocking (e.g. '192.168.56-68.1-5', '172.16.0.0/16').
        """
        return self.__get_ips('excluded_ips')

    def set_excluded_ips(self, addresses):
        """
        Set the IP addresses or ranges to exclude from Web Control rating or
        blocking: one IPv4 or IPv6 address, CIDR subnet or range per item,
        ranges written per octet or group (192.168.56-68.1-5,
        2001-2003:db8::1; 10.0.0.1-10.0.0.9 is refused by the console).
        """
        return self.__set_ips('excluded_ips', addresses)

    excluded_ips = property(get_excluded_ips, set_excluded_ips)

    # ------------------------------ Secure Search ------------------------------
    def get_search_engine(self):
        """
        Get the default search engine of Secure Search: '0' Yahoo, '1'
        Google, '2' Bing, '3' Ask.
        """
        return self._get('SecureSearch', 'uiSecureSearchEngine')

    def set_search_engine(self, engine):
        """
        Set the default search engine of Secure Search: '0' Yahoo, '1'
        Google, '2' Bing, '3' Ask.
        """
        if str(engine) not in self.SEARCH_ENGINES:
            raise ValueError('The search engine must be within {}.'.format(
                list(self.SEARCH_ENGINES)))
        return self._set('SecureSearch', 'uiSecureSearchEngine', engine)

    search_engine = property(get_search_engine, set_search_engine)

    def check(self):
        """
        Returns the errors the console would display ("Required" fields),
        an empty list if none.
        """
        errors = []
        on = lambda setting: self.get_option(setting) == '1'
        if on('bStandDown') and on('bGatewayIPValidate') and not self.get_gateway_ips():
            errors.append("Use your organization's default gateway needs IP addresses.")
        if on('bStandDown') and on('bGatewayLandmarkValidate') and \
                not (self.get_landmark_dns() or self.get_landmark_ips()):
            errors.append('DNS name, IPS addresses, or both must be specified.')
        if on('bInformWebReporter'):
            reporter = self.get_web_reporter()
            if not (reporter['url'] and reporter['user'] and reporter['password_set']):
                errors.append('Web Reporter needs a URL, a user name and a password.')
        return errors

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        on = lambda setting: self.get_option(setting) == '1'
        row = lambda setting: [self.__CHECKBOXES[setting][1], self.md_check(self.get_option(setting))]
        sections = []
        rows = [row('bEnableWebProtection')]
        if on('bEnableWebProtection'):
            rows += [row(setting) for setting in ['bDisableUserBrowserPlugin',
                                                  'bAllowIEInExtOffMode', 'bHideToolbar']]
        sections.append(('Web Control', self.md_settings(rows)))
        rows = [row('bStandDown')]
        if on('bStandDown'):
            rows.append(row('bGatewayIPValidate'))
            if on('bGatewayIPValidate'):
                rows.append(['Default gateway IP addresses', ', '.join(self.get_gateway_ips())])
            rows.append(row('bGatewayPresenceValidate'))
            rows.append(row('bGatewayLandmarkValidate'))
            if on('bGatewayLandmarkValidate'):
                rows += [['DNS name for internal landmark', self.get_landmark_dns()],
                         ['IP addresses for internal landmark',
                          ', '.join(self.get_landmark_ips())]]
        rows.append(row('bStandDownMCPValidate'))
        sections.append(('Web Control Interlock (Windows only)', self.md_settings(rows)))
        rows = [row(setting) for setting in ['bGreenRatedSites', 'bAllowedConfiguredBlockAllowList',
                                             'bLogIFrameEvents', 'bInformWebReporter']]
        if on('bInformWebReporter'):
            # The password is never written.
            reporter = self.get_web_reporter()
            rows += [['Web Reporter URL', reporter['url']],
                     ['Web Reporter user name', reporter['user']]]
        sections.append(('Event Logging', self.md_settings(rows)))
        action = self.get_unverified_action()
        rows = [['Apply this action to sites not yet verified by Trellix GTI',
                 self.UNVERIFIED_ACTIONS.get(action, action)]]
        if action == '0':
            rows.append(row('unverifiedOverride'))
        rows += [row(setting) for setting in ['bEnableHTMLiFrames', 'bGtiFailClose',
                                              'bPhishingBlock', 'bAllowWarnAtDomainLevel',
                                              'bSiteObserve', 'bEnfFileDownloads']]
        if on('bEnfFileDownloads'):
            level = self.get_gti_sensitivity()
            rows.append(['Trellix GTI sensitivity level', self.GTI_SENSITIVITY.get(level, level)])
        sections.append(('Action Enforcement', self.md_settings(rows)))
        sections.append(('Email Annotations (Windows only)', self.md_settings(
            [row('bEnfIMEmailLinkChecking'), row('bEnfIMEmailLinkHookChecking')])))
        text = self.md_settings([row('bAllowAllPrivateUrls')])
        text += '\nSpecify IP addresses or ranges to exclude from Web Control rating or ' \
                'blocking (private IP addresses are excluded by default):\n\n'
        text += self.md_table(['IP address or range'],
                              [[address] for address in self.get_excluded_ips()], numbered=True)
        sections.append(('Exclusions', text))
        rows = [row('bEnableSecureSearch')]
        if on('bEnableSecureSearch'):
            engine = self.get_search_engine()
            rows += [['Set the default engine in supported browsers',
                      self.SEARCH_ENGINES.get(engine, engine)], row('uiSecureResults')]
        sections.append(('Secure Search', self.md_settings(rows)))
        return sections
