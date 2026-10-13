"""
The examples of mcafee_epo_policies.validators (a valid and an invalid value
for each check, in doctest format) and of its regular expressions.
"""

import doctest

from mcafee_epo_policies import validators
from mcafee_epo_policies.validators import (ENS_USER_NAME, EP_SID, EP_USER_NAME, EP_GROUP_NAME,
                                            EP_HOSTNAME, EP_REGISTRY, EP_EXPERT_RULE_NAME)


def test_docstring_examples():
    result = doctest.testmod(validators)
    assert result.attempted >= 58 and result.failed == 0


def test_regex_examples():
    for pattern, valid, invalid in [
            (ENS_USER_NAME, 'CORP\\jdoe', 'jdoe'),
            (EP_SID, 'S-1-5-32-544', 'S-1-5'),
            (EP_USER_NAME, 'CORP.LOCAL\\j doe', 'j;doe'),
            (EP_USER_NAME, 'jdoe', 'a\\b\\c'),
            (EP_GROUP_NAME, 'Domain Users', 'CORP\\Domain Users'),
            (EP_HOSTNAME, 'web-*.corp?', 'web_01'),
            (EP_REGISTRY, 'HKLM\\Software\\Contoso*', 'HKEY_LOCAL\\Software'),
            (EP_EXPERT_RULE_NAME, 'Règle (test): a_b-c.d/e', 'Rule;1')]:
        assert pattern.fullmatch(valid), (pattern.pattern, valid)
        assert not pattern.fullmatch(invalid), (pattern.pattern, invalid)
