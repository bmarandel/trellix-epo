#!/usr/bin/env python3
# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
set-proc-exclusions.py

Example for the trellix_epo package.

Given an ENS Threat Prevention On-Access Scan policy exported from ePO (used
here as a template) and a plain text file listing processes, this adds each
process to the policy's Process Settings as "Low Risk", makes sure the
policy is configured to use per-risk-level settings, and makes sure the Low
Risk profile is set to skip scanning entirely. The result is written to a
new policy file, ready to be re-imported into ePO.

Usage:
    python3 set-proc-exclusions.py <template.xml> <process_list.txt>

The process list is a plain text file, one entry per line. Each line may be:
  - a bare file name, e.g. "acme.exe"
  - a full path (Windows or POSIX separators), e.g. "C:\\foo\\bar\\toto.exe"
    or "C:/foo/bar/toto.exe" - only the file name is kept
  - blank (ignored)
Only entries ending in ".exe" (case-insensitive) are kept; anything else
(e.g. a .bat file) is skipped and reported.

The output is written next to the template, named after it with
"_with_exclusions" inserted before the extension, e.g. "policy.xml" ->
"policy_with_exclusions.xml".
"""

import argparse
import os
import sys

from trellix_epo import ESTPPolicyOnAccessScan, OASProcessList, State


def read_process_names(list_file_path):
    """
    Read a text file of process entries (bare file names or full paths, one
    per line, blank lines ignored) and return a tuple:
    (list of .exe file names, list of non-.exe entries that were skipped).
    """
    process_names = []
    skipped_entries = []
    with open(list_file_path, 'r') as text_file:
        for line in text_file:
            entry = line.strip()
            if not entry:
                continue
            # Accept both '/' and '\' path separators and keep only the
            # file name, whether the line was a bare name or a full path.
            file_name = entry.replace('\\', '/').rsplit('/', 1)[-1]
            if file_name.lower().endswith('.exe'):
                process_names.append(file_name)
            else:
                skipped_entries.append(entry)
    return process_names, skipped_entries


def build_output_path(template_path):
    """
    Return the output path: the template's file name with "_with_exclusions"
    inserted before its extension, in the same directory as the template.
    """
    directory, file_name = os.path.split(template_path)
    base_name, extension = os.path.splitext(file_name)
    return os.path.join(directory, '{}_with_exclusions{}'.format(base_name, extension))


def main():
    parser = argparse.ArgumentParser(
        description='Add a list of processes as "Low Risk" to an ENS Threat '
                    'Prevention On-Access Scan policy, and configure the Low '
                    'Risk profile to skip scanning entirely.')
    parser.add_argument('template', help='On-Access Scan policy XML file used as a template')
    parser.add_argument('process_list', help='Text file listing process names or full paths')
    args = parser.parse_args()

    try:
        policy = ESTPPolicyOnAccessScan()
        policy.load_from_file(args.template)
    except (FileNotFoundError, ValueError) as error:
        print('Error loading template "{}": {}'.format(args.template, error), file=sys.stderr)
        return 1

    try:
        process_names, skipped_entries = read_process_names(args.process_list)
    except FileNotFoundError as error:
        print('Error reading process list "{}": {}'.format(args.process_list, error),
              file=sys.stderr)
        return 1

    proc_list = OASProcessList(policy.get_process_list())
    added, already_present = 0, 0
    for process_name in process_names:
        if proc_list.add_low_risk(process_name):
            added += 1
        else:
            already_present += 1
    policy.set_process_list(proc_list.proc_list)

    # "Configure different settings for High Risk and Low Risk processes"
    policy.use_standard_settings_only = State.DISABLED

    # Low Risk profile - "Do not scan when reading from or writing to disk"
    policy.when_to_scan_lr = '0'

    output_path = build_output_path(args.template)
    policy.save_to_file(output_path)

    print('Read {} .exe process name(s) from "{}".'.format(len(process_names), args.process_list))
    if skipped_entries:
        print('Skipped {} non-.exe entry/entries: {}'.format(
            len(skipped_entries), ', '.join(skipped_entries)))
    print('Added {} as Low Risk, {} already present (skipped).'.format(added, already_present))
    print('"Configure different settings for High Risk and Low Risk processes": enabled.')
    print('Low Risk profile "Do not scan when reading from or writing to disk": enabled.')
    print('Saved to "{}".'.format(output_path))
    return 0


if __name__ == '__main__':
    sys.exit(main())
