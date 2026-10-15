# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ESWCPolicyContentActions (Endpoint Security
Web Control: Content Actions).

Storage learnt from a test policy changed in the ePO 5.10 console:

- Web Category Blocking: section ContentActions, bEnableCategorization,
  uiContentBitCodes (the web category codes, comma separated, the last one
  0 = Uncategorized) and szActionCodes (one character per code, in the same
  order: '2' = Block, '0' = not blocked); uiActionUncategorized repeats the
  action of the Uncategorized category.
- Rating Actions: section RatingActions, uiOverall (sites) and
  uiSiteResourceFileDownload (file downloads), see RatingActions.
"""

from .common import ESWCPolicy


class ESWCPolicyContentActions(ESWCPolicy):
    """
    The ESWCPolicyContentActions class can be used to edit the Endpoint
    Security Web Control policy: Content Actions. Web categories are given by
    their code or console label (see CATEGORIES).
    """
    TYPE = 'EWC_ContentFiltering'
    MD_CATEGORY = 'Content Actions'
    BLOCK, NOT_BLOCKED = '2', '0'
    UNCATEGORIZED = '0'

    # Web category code -> console label (ePO 5.10, ENS Web Control 10.7).
    CATEGORIES = {
        '100': 'Art/Culture/Heritage', '101': 'Alcohol', '102': 'Anonymizers',
        '104': 'Anonymizing Utilities', '105': 'Business', '106': 'Chat',
        '108': 'Public Information', '109': 'Potential Criminal Activities', '110': 'Drugs',
        '111': 'Education/Reference', '112': 'Entertainment', '113': 'Extreme',
        '114': 'Finance/Banking', '115': 'Gambling', '116': 'Games',
        '117': 'Government/Military', '118': 'Potential Hacking/Computer Crime',
        '119': 'Health', '120': 'Humor/Comics', '121': 'Discrimination',
        '122': 'Instant Messaging', '123': 'Stock Trading', '124': 'Internet Radio/TV',
        '125': 'Job Search', '126': 'Information Security', '127': 'Dating/Social Networking',
        '128': 'Mobile Phone', '129': 'Media Downloads', '130': 'Malicious Sites',
        '131': 'Usenet News', '132': 'Nudity', '133': 'Non-Profit/Advocacy/NGO',
        '134': 'General News', '136': 'Online Shopping', '137': 'Provocative Attire',
        '138': 'P2P/File Sharing', '139': 'Politics/Opinion', '140': 'Personal Pages',
        '141': 'Portal Sites', '142': 'Remote Access', '143': 'Religion/Ideology',
        '144': 'Resource Sharing', '145': 'Search Engines', '146': 'Sports',
        '147': 'Streaming Media', '148': 'Shareware/Freeware', '149': 'Pornography',
        '150': 'Spyware/Adware/Keyloggers', '151': 'Tobacco', '152': 'Travel',
        '153': 'Violence', '154': 'Web Ads', '155': 'Weapons', '156': 'Web Mail',
        '157': 'Web Phone', '158': 'Auctions/Classifieds', '159': 'Forum/Bulletin Boards',
        '160': 'Profanity', '161': 'School Cheating Information', '162': 'Sexual Materials',
        '163': 'Gruesome Content', '164': 'Visual Search Engine',
        '165': 'Technical/Business Forums', '166': 'Gambling Related', '167': 'Messaging',
        '168': 'Game/Cartoon Violence', '169': 'Phishing', '170': 'Personal Network Storage',
        '171': 'Spam URLs', '172': 'Interactive Web Applications', '174': 'Fashion/Beauty',
        '175': 'Software/Hardware', '176': 'Potential Illegal Software',
        '177': 'Content Server', '178': 'Internet Services', '179': 'Media Sharing',
        '180': 'Incidental Nudity', '181': 'Marketing/Merchandising', '183': 'Parked Domain',
        '184': 'Pharmacy', '185': 'Restaurants', '186': 'Real Estate',
        '187': 'Recreation/Hobbies', '188': 'Blogs/Wiki', '189': 'Digital Postcards',
        '190': 'Historical Revisionism', '191': 'Technical Information',
        '192': 'Dating/Personals', '193': 'Motor Vehicles', '194': 'Professional Networking',
        '195': 'Social Networking', '196': 'Text Translators', '197': 'Web Meetings',
        '198': 'Controversial Opinions', '199': 'Residential IP Addresses',
        '200': 'Browser Exploits', '201': 'Consumer Protection', '202': 'Illegal UK',
        '203': 'Major Global Religions', '204': 'Malicious Downloads',
        '205': 'Potentially Unwanted Programs', '600': 'For Kids', '601': 'History',
        '602': 'Moderated', '603': 'Text/Spoken Only', '0': 'Uncategorized',
    }

    # ------------------------------ Web Category Blocking ------------------------------
    def get_category_blocking(self):
        """
        Get state of Enable web category blocking ('1' or '0').
        """
        return self._get('ContentActions', 'bEnableCategorization')

    def set_category_blocking(self, mode):
        """
        Set state of Enable web category blocking ('1' or '0').
        """
        return self._set_checkbox('ContentActions', 'bEnableCategorization', mode)

    category_blocking = property(get_category_blocking, set_category_blocking)

    def __codes(self):
        codes = (self._get('ContentActions', 'uiContentBitCodes') or '').split(',')
        return [code for code in codes if code != '']

    def __code(self, category):
        if str(category) in self.__codes():
            return str(category)
        for code, label in self.CATEGORIES.items():
            if label == category and code in self.__codes():
                return code
        raise ValueError('Unknown web category: {}'.format(category))

    def get_categories(self):
        """
        Get the web categories, blocked first (as in the console), then by
        name: a list of dicts {'code', 'name', 'block' ('1' or '0')}.
        """
        actions = self._get('ContentActions', 'szActionCodes') or ''
        categories = [{'code': code, 'name': self.CATEGORIES.get(code, code),
                       'block': '1' if index < len(actions) and actions[index] == self.BLOCK
                                else '0'}
                      for index, code in enumerate(self.__codes())]
        return sorted(categories, key=lambda c: (c['block'] != '1', c['name'].lower()))

    def get_blocked_categories(self):
        """
        Get the names of the blocked web categories.
        """
        return [category['name'] for category in self.get_categories()
                if category['block'] == '1']

    def set_category(self, category, block):
        """
        Block ('1') or unblock ('0') a web category given by its code (e.g.
        '149') or console label (e.g. 'Pornography').
        """
        if str(block) not in ['0', '1']:
            raise ValueError('Block must be "1" or "0".')
        code = self.__code(category)
        codes = self.__codes()
        actions = list((self._get('ContentActions', 'szActionCodes') or '').ljust(
            len(codes), self.NOT_BLOCKED))
        action = self.BLOCK if str(block) == '1' else self.NOT_BLOCKED
        actions[codes.index(code)] = action
        if code == self.UNCATEGORIZED:
            self._set('ContentActions', 'uiActionUncategorized', action)
        return self._set('ContentActions', 'szActionCodes', ''.join(actions))

    def set_all_categories(self, block):
        """
        Block or unblock all the web categories (console "Block All" /
        "Unblock All").
        """
        for code in self.__codes():
            self.set_category(code, block)
        return True

    # ------------------------------ Rating Actions ------------------------------
    def get_site_actions(self):
        """
        Get the rating actions for sites (RatingActions).
        """
        return self._get_rating('RatingActions', 'uiOverall')

    def set_site_actions(self, actions):
        """
        Set the rating actions for sites (RatingActions).
        """
        return self._set_rating('RatingActions', 'uiOverall', actions)

    site_actions = property(get_site_actions, set_site_actions)

    def get_download_actions(self):
        """
        Get the rating actions for file downloads (RatingActions), applied
        only when "Enable file scanning for file downloads" is enabled in the
        Options policy.
        """
        return self._get_rating('RatingActions', 'uiSiteResourceFileDownload')

    def set_download_actions(self, actions):
        """
        Set the rating actions for file downloads (RatingActions).
        """
        return self._set_rating('RatingActions', 'uiSiteResourceFileDownload', actions)

    download_actions = property(get_download_actions, set_download_actions)

    # ------------------------------ Markdown export ------------------------------
    def md_sections(self):
        """
        Returns the policy content as a list of (heading, markdown) tuples,
        in the order of the ePO console (see Policy.to_markdown).
        """
        text = self.md_settings([['Enable web category blocking',
                                  self.md_check(self.get_category_blocking())]])
        if self.get_category_blocking() == '1':
            text += '\nRating Actions also apply to sites in unblocked web categories.\n\n'
            text += self.md_table(['Block', 'Web Category'], [
                [self.md_check(category['block']), category['name']]
                for category in self.get_categories()], numbered=True)
        rating = 'Green-rated sites and downloads automatically have an action of Allow.\n\n'
        rating += '### Rating actions for sites\n\n' + self._md_rating(self.get_site_actions())
        rating += '\n### Rating actions for file downloads (Windows only)\n\n'
        rating += 'These rating actions are applicable only when "Enable file scanning for ' \
                  'file downloads" is enabled in the Options policy.\n\n'
        rating += self._md_rating(self.get_download_actions())
        return [('Web Category Blocking', text), ('Rating Actions', rating)]
