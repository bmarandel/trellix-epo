"""
Endpoint Security Web Control (es/wc): Options, Enforcement Messaging, Block
and Allow List, Content Actions and Browser Control policies.

wc_policies.xml is an export of the lab ePO 5.10 (productId ENDP_WP_1000)
with the "My Default" policies and three test copies changed in the console:

- "Claude - WC Options Test": toolbar hidden, web gateway interlock on
  (default gateway 10.1.1.1 and 10.1.1.2, gateway enforcement, landmark
  landmark.claude.test / 10.2.2.2), Skyhigh Client Proxy interlock, green
  rated sites and iFrame events logged, unverified sites blocked with
  green-rated downloads allowed, GTI fail close, Observe mode, sensitivity
  Medium, non browser-based email annotations off, local network not
  allowed, 2 excluded ranges, Secure Search with Google and risky links not
  blocked.
- "Claude - WC Block and Allow Test": www.claude-allowed.test and
  intranet.claude.test allowed, claude-blocked.test blocked (note "Blocked
  by test"), downloads from allowed sites Red Warn / Yellow Allow / Unrated
  Block, allowed sites take precedence.
- "Claude - WC Content Actions Test": Alcohol and Uncategorized blocked,
  Pornography unblocked, sites Red Block / Yellow Block / Unrated Warn,
  downloads Red Warn / Yellow Warn / Unrated Allow.
"""

from pathlib import Path

import pytest

from trellix_epo import (ESWCPolicies, ESWCPolicyOptions, ESWCPolicyMessaging,
                                 ESWCPolicyBlockAllowList, WCSite, ESWCPolicyContentActions,
                                 ESWCPolicyBrowserControl, RatingActions)

FIXTURE = Path(__file__).parent / 'fixtures' / 'wc_policies.xml'
ALLOW, WARN, BLOCK = RatingActions.ALLOW, RatingActions.WARN, RatingActions.BLOCK


def load(cls, name='My Default'):
    policies = ESWCPolicies()
    policies.load_from_file(str(FIXTURE))
    return cls(policies.get_policy(cls.TYPE, name))


def test_policies():
    policies = ESWCPolicies()
    policies.load_from_file(str(FIXTURE))
    assert len(policies.list()) == 8
    with pytest.raises(ValueError):
        ESWCPolicyOptions(policies.get_policy('EWC_BrowserControl', 'My Default'))


@pytest.mark.parametrize('value, actions', [
    ('98', (BLOCK, WARN, ALLOW)), ('273', (WARN, ALLOW, BLOCK)),
    ('164', (BLOCK, BLOCK, WARN)), ('82', (WARN, WARN, ALLOW))])
def test_rating_actions(value, actions):
    """
    Values saved by the console: Allow 1, Warn 2, Block 4 for Yellow (bits
    0-2), Red (bits 3-5) and Unrated (bits 6-8).
    """
    decoded = RatingActions.from_value(value)
    assert (decoded.red, decoded.yellow, decoded.unrated) == actions
    assert RatingActions(*actions).to_value() == value
    with pytest.raises(ValueError):
        RatingActions('3', ALLOW, ALLOW)


def test_options_read():
    default = load(ESWCPolicyOptions)
    assert default.web_control == '1'
    assert (default.unverified_action, default.gti_sensitivity, default.search_engine) == (
        '1', '4', '0')
    assert default.get_web_reporter() == {'enabled': '0', 'url': '', 'user': '',
                                          'password_set': False}
    assert (default.gateway_ips, default.landmark_ips, default.excluded_ips) == ([], [], [])
    assert default.check() == []

    test = load(ESWCPolicyOptions, 'Claude - WC Options Test')
    assert [test.get_option(s) for s in ['bHideToolbar', 'bStandDown', 'bGatewayIPValidate',
                                         'bGatewayPresenceValidate', 'bGatewayLandmarkValidate',
                                         'bStandDownMCPValidate', 'bSiteObserve',
                                         'unverifiedOverride', 'bEnfIMEmailLinkHookChecking',
                                         'bAllowAllPrivateUrls', 'uiSecureResults']] == \
        ['1', '1', '1', '1', '1', '1', '1', '1', '0', '0', '0']
    assert test.gateway_ips == ['10.1.1.1', '10.1.1.2']
    assert (test.landmark_dns, test.landmark_ips) == ('landmark.claude.test', ['10.2.2.2'])
    assert test.excluded_ips == ['192.168.56-68.1-5', '10.9.0.0/16']
    assert (test.unverified_action, test.gti_sensitivity, test.search_engine) == ('0', '2', '1')


def test_options_write():
    policy = load(ESWCPolicyOptions)
    stamp = policy.get_setting_value('ActionEnforcement', 'szPolicyStamp')
    policy.set_option('bStandDown', '1')
    policy.set_option('bGatewayIPValidate', '1')
    assert policy.check() == ["Use your organization's default gateway needs IP addresses."]
    policy.gateway_ips = ['10.0.0.1', '2001:db8::1']
    assert policy.check() == []
    assert policy.get_setting_value('ActionEnforcement', 'uiGatewayIPCount') == '2'
    assert policy.get_setting_value('ActionEnforcement', 'szGatewayIP_1') == '2001:db8::1'
    assert policy.get_setting_value('ActionEnforcement', 'szPolicyStamp') != stamp
    policy.excluded_ips = ['172.16.0.0/16']
    policy.unverified_action = '2'
    policy.gti_sensitivity = '3'
    policy.search_engine = '2'
    assert (policy.excluded_ips, policy.unverified_action, policy.gti_sensitivity,
            policy.search_engine) == (['172.16.0.0/16'], '2', '3', '2')
    for bad in [lambda: policy.set_excluded_ips(['10.0.0.1, 10.0.0.2']),
                lambda: policy.set_unverified_action('3'),
                lambda: policy.set_gti_sensitivity('5'),
                lambda: policy.set_option('bSiteObserve', 'on'),
                lambda: policy.set_option('noSuchOption', '1')]:
        with pytest.raises((ValueError, KeyError)):
            bad()


def test_options_web_reporter_password_not_settable():
    policy = load(ESWCPolicyOptions)
    with pytest.raises(ValueError):
        policy.set_web_reporter('1', 'https://reporter.example.com/', 'user')
    # URL and user name are kept, the reporter stays disabled.
    assert policy.get_web_reporter() == {'enabled': '0', 'url': 'https://reporter.example.com/',
                                         'user': 'user', 'password_set': False}
    policy.set_setting_value('EventLogging', 'elPassword', 'ENCRYPTED-BY-EPO')
    policy.set_web_reporter('1')
    assert policy.get_web_reporter()['enabled'] == '1'
    assert 'ENCRYPTED-BY-EPO' not in policy.to_markdown()


def test_messaging():
    policy = load(ESWCPolicyMessaging)
    assert policy.get_message('szBlock') == 'This site is blocked.'
    assert policy.get_message('szBlockFileMessage', 'fr') == 'Ce fichier est bloqué.'
    assert len(ESWCPolicyMessaging.MESSAGES) == 19
    policy.set_message('szBlock', 'Site interdit.', 'fr')
    policy.set_message_all_languages('szLogoUrl', 'https://intranet.example.com/logo.png')
    assert policy.get_message('szBlock', 'fr') == 'Site interdit.'
    assert policy.get_message('szLogoUrl', 'ja') == 'https://intranet.example.com/logo.png'
    with pytest.raises(ValueError):
        policy.set_message('szBlock', 'x' * 101)
    with pytest.raises(ValueError):
        policy.set_message('szBlock', 'x', 'xx')
    with pytest.raises(ValueError):
        policy.get_message('szNoSuchMessage')


def test_block_allow_list():
    test = load(ESWCPolicyBlockAllowList, 'Claude - WC Block and Allow Test')
    assert test.get_sites() == [WCSite('www.claude-allowed.test'),
                                WCSite('intranet.claude.test'),
                                WCSite('claude-blocked.test', WCSite.BLOCK, 'Blocked by test')]
    assert test.download_actions == RatingActions(WARN, ALLOW, BLOCK)
    assert (test.enforce_download_ratings, test.allowed_precedence) == ('1', '1')

    policy = load(ESWCPolicyBlockAllowList)
    assert policy.get_sites() == []
    assert policy.download_actions == RatingActions(BLOCK, WARN, ALLOW)
    policy.add_site(WCSite('example.com', WCSite.BLOCK, 'Not allowed'))
    policy.add_site(WCSite('bücher.example', WCSite.ALLOW))
    policy.add_site(WCSite('example.com', WCSite.ALLOW))     # replaces the pattern
    assert policy.get_sites() == [WCSite('bücher.example'), WCSite('example.com')]
    assert policy.get_setting_value('BlockAndAllowList', 'szSite0') == 'bücher.example'
    assert policy.get_setting_value('BlockAndAllowList', 'szUnicodeSite0') == 'bücher.example'
    assert policy.remove_site('example.com')
    assert not policy.remove_site('example.com')
    assert policy.get_setting_value('BlockAndAllowList', 'uiSiteCount') == '1'
    for bad in [WCSite('ab'), WCSite('*.example.com'), WCSite('a.com,b.com'),
                WCSite('example.com', '2'), WCSite('example.com', note='x' * 51)]:
        with pytest.raises(ValueError):
            policy.add_site(bad)
    policy.download_actions = RatingActions(BLOCK, BLOCK, BLOCK)
    assert policy.get_setting_value('BlockAndAllowList', 'uiSiteResourceFileDownload') == '292'


def test_content_actions():
    default = load(ESWCPolicyContentActions)
    categories = default.get_categories()
    assert len(categories) == 106 == len(ESWCPolicyContentActions.CATEGORIES)
    assert default.get_blocked_categories() == [
        'Browser Exploits', 'Malicious Downloads', 'Malicious Sites', 'Phishing', 'Pornography',
        'Potential Hacking/Computer Crime', 'Spyware/Adware/Keyloggers']
    assert categories[7]['name'] == 'Alcohol'
    assert (default.site_actions, default.download_actions) == (
        RatingActions(BLOCK, WARN, ALLOW), RatingActions(BLOCK, WARN, ALLOW))

    test = load(ESWCPolicyContentActions, 'Claude - WC Content Actions Test')
    assert test.get_blocked_categories() == [
        'Alcohol', 'Browser Exploits', 'Malicious Downloads', 'Malicious Sites', 'Phishing',
        'Potential Hacking/Computer Crime', 'Spyware/Adware/Keyloggers', 'Uncategorized']
    assert test.site_actions == RatingActions(BLOCK, BLOCK, WARN)
    assert test.download_actions == RatingActions(WARN, WARN, ALLOW)

    # The console changes of the test policy, made by the library.
    default.set_category('Alcohol', '1')
    default.set_category('149', '0')
    default.set_category('Uncategorized', '1')
    default.site_actions = RatingActions(BLOCK, BLOCK, WARN)
    default.download_actions = RatingActions(WARN, WARN, ALLOW)
    for setting in ['szActionCodes', 'uiActionUncategorized']:
        assert default.get_setting_value('ContentActions', setting) == \
            test.get_setting_value('ContentActions', setting)
    for setting in ['uiOverall', 'uiSiteResourceFileDownload']:
        assert default.get_setting_value('RatingActions', setting) == \
            test.get_setting_value('RatingActions', setting)
    with pytest.raises(ValueError):
        default.set_category('No such category', '1')
    default.set_all_categories('0')
    assert default.get_blocked_categories() == []


def test_browser_control():
    policy = load(ESWCPolicyBrowserControl)
    browsers = policy.get_browsers()
    assert set(browsers) == set(ESWCPolicyBrowserControl.UNSUPPORTED) | \
        set(ESWCPolicyBrowserControl.SUPPORTED)
    assert set(browsers.values()) == {'0'}
    policy.set_block('OPERA', '1')
    assert policy.get_block('OPERA') == '1'
    assert policy.get_setting_value('HardenSettings', 'szBrowserBlocks') == \
        '0|0|0|1|0|0|0|0|0|0|0|0|0'
    with pytest.raises(ValueError):
        policy.set_block('LYNX', '1')


def test_markdown():
    text = load(ESWCPolicyOptions, 'Claude - WC Options Test').to_markdown()
    assert 'Endpoint Security Web Control - Options policy' in text
    for heading in ['Web Control', 'Web Control Interlock (Windows only)', 'Event Logging',
                    'Action Enforcement', 'Email Annotations (Windows only)', 'Exclusions',
                    'Secure Search']:
        assert '. {}\n'.format(heading) in text
    assert '| Default gateway IP addresses | 10.1.1.1, 10.1.1.2 |' in text
    assert '| Apply this action to sites not yet verified by Trellix GTI | Block |' in text
    assert '| Allow Green-rated file downloads from not yet verified URL | Yes |' in text
    assert '| Trellix GTI sensitivity level | Medium |' in text
    assert '| 2 | 10.9.0.0/16 |' in text
    assert '| Set the default engine in supported browsers | Google |' in text

    policy = load(ESWCPolicyMessaging)
    text = policy.to_markdown()
    assert 'Settings for: English' in text
    assert '| Block message | This site is blocked. |' in text
    policy.md_languages = ['en', 'fr']
    assert '| Block message | French | Ce site est bloqué. |' in policy.to_markdown()

    text = load(ESWCPolicyBlockAllowList, 'Claude - WC Block and Allow Test').to_markdown()
    assert '| 3 | claude-blocked.test | Block | Blocked by test |' in text
    assert '| Warn | Allow | Block |' in text

    text = load(ESWCPolicyContentActions, 'Claude - WC Content Actions Test').to_markdown()
    assert '| 1 | Yes | Alcohol |' in text
    assert '| Yes | Uncategorized |' in text
    assert '| Block | Block | Warn |' in text

    text = load(ESWCPolicyBrowserControl).to_markdown()
    assert '| Safari for Windows | No |' in text
    assert '| Chromium Edge | No |' in text
