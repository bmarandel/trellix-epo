#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
on_access_scan.py

Example for the trellix_epo package: load an ENS Threat Prevention
On-Access Scan policy, read a few settings, add a folder exclusion, and
save the result.

Usage:
    python3 on_access_scan.py <policy.xml>
"""

import sys

from trellix_epo import ESTPPolicyOnAccessScan, OASExclusionList, Gti


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 on_access_scan.py <policy.xml>', file=sys.stderr)
        return 1

    policy = ESTPPolicyOnAccessScan()
    policy.load_from_file(sys.argv[1])

    print('Policy "{}" from server {}'.format(policy.get_name(), policy.get_epo_server()))
    print('  On-Access Scan enabled: {}'.format(policy.on_access_scan))
    print('  McAfee GTI level: {}'.format(policy.gti_level))

    # Raise GTI sensitivity, as an example edit.
    policy.gti_level = Gti.HIGH

    # Add a folder exclusion, reusing the policy's existing exclusion list.
    exclusions = OASExclusionList(policy.get_exclusion_list())
    exclusions.add_folder('C:\\ProgramData\\MyApp\\', on_write=True, on_read=True,
                          with_subfolders=True, notes='Added by on_access_scan.py example')
    policy.set_exclusion_list(exclusions.excl_list)

    policy.save_to_file('oas_updated.xml')
    print('  -> saved to oas_updated.xml')
    return 0


if __name__ == '__main__':
    sys.exit(main())
