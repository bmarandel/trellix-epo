#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
on_demand_scan.py

Example for the trellix_epo package: load an ENS Threat Prevention
On-Demand Scan policy, adjust the Full Scan locations and exclusions, and
save the result.

Usage:
    python3 on_demand_scan.py <policy.xml>
"""

import sys

from trellix_epo import ESTPPolicyOnDemandScan, ODSLocationList, ODSExclusionList


def main():
    if len(sys.argv) != 2:
        print('Usage: python3 on_demand_scan.py <policy.xml>', file=sys.stderr)
        return 1

    policy = ESTPPolicyOnDemandScan()
    policy.load_from_file(sys.argv[1])

    print('Policy "{}" from server {}'.format(policy.get_name(), policy.get_epo_server()))

    locations = ODSLocationList(policy.fs_locations)
    print(locations)

    # Add a folder to the Full Scan locations, as an example edit.
    locations.add_file_or_folder('D:\\Shares\\Finance\\')
    policy.fs_locations = locations.loc_list

    exclusions = ODSExclusionList(policy.fs_exclusion_list)
    exclusions.add_file_type('tmp', on_write=True, on_read=True,
                             notes='Added by on_demand_scan.py example')
    policy.fs_exclusion_list = exclusions.excl_list

    policy.save_to_file('ods_updated.xml')
    print('  -> saved to ods_updated.xml')
    return 0


if __name__ == '__main__':
    sys.exit(main())
