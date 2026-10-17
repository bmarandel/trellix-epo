# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2019 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines the class ExclusionList for On-Access and On-Demand policies.
"""

from ...validators import (check_int, check_length, is_ens_path, is_ens_exclusion_file_type,
                           is_ens_file_types)


def check_file_type_list(extensions, label='Specified file types'):
    """
    Raise ValueError if the console refuses a list of file types of "What
    to scan", as stored: comma separated extensions, ":::" for "All files
    with no extension" (On-Access Scan, On-Demand Scan). The typed text
    (without :::) has 3000 characters at most and follows is_ens_file_types.
    """
    typed = ','.join(item for item in str(extensions).split(',') if item != ':::')
    check_length(label, typed, 3000)
    if not is_ens_file_types(typed):
        raise ValueError('{}: invalid file types {!r} (none of / " | < > \\ * :, not only '
                         '?).'.format(label, typed))
    return extensions


def check_exclusion_path(path):
    """
    Raise ValueError if the console refuses the path of a scan exclusion
    (IsValidExclusionPattern: 258 characters, a Linux or Mac path starting
    with / or an ENS path, see trellix_epo.validators.is_ens_path).
    """
    check_length('Exclusion path', path, 258, required=True)
    if not (path.startswith('/') or is_ens_path(path)):
        raise ValueError('Invalid exclusion path: {!r}'.format(path))
    return path


def check_exclusion_rows(rows, notes_max=None):
    """
    Raise ValueError if the console refuses a row of an exclusion list as
    stored [what, when, value, notes]: what '3' (path, see
    check_exclusion_path), '4' (file type), '0' / '2' (minimum age in days,
    1-9999); notes of notes_max characters at most (On-Demand Scan: 256, the
    On-Access Scan dialog has no limit). Returns the rows.
    """
    for row in rows:
        what, _, value, notes = (list(row) + ['', '', '', ''])[:4]
        if what == '3':
            check_exclusion_path(value)
        elif what == '4':
            check_length('Exclusion file type', value, 100, required=True)
            if not is_ens_exclusion_file_type(value):
                raise ValueError('Invalid exclusion file type: {!r}'.format(value))
        elif what in ('0', '2'):
            check_int('Minimum age in days', value, 1, 9999)
        if notes_max is not None:
            check_length('Exclusion notes', notes, notes_max)
        if '|' in notes:
            raise ValueError('Exclusion notes cannot contain "|": {!r}'.format(notes))
    return rows


class ExclusionList:
    """
    The ExclusionList class can be used to edit the list of exclusion.
    What to exclude:
    '0': File age, changed with Minimum age in days
    '1': ? (not used or deprecated)
    '2': File age, created with Minimum age in days
    '3': File name or path (can include * or ? wildcards)
    '4': File type (can include the ? wildcard)

    When to excluded:
    1: On Write
    2: On Read
    4: Also exclude subfolders
    -> The final value is and addition of all options

    Name: File name or path, extension or days.

    Notes: Notes of the exclusion
    """

    def __init__(self, exclusion_list=None):
        self.excl_list = exclusion_list if exclusion_list is not None else []

    def __repr__(self):
        return '<ExclusionList which contains {} exclusion(s)>'.format(len(self.excl_list))

    def __define_item__(self, action, value):
        item = ''
        if action == '0':
            item = 'Modified {} or more days ago'.format(value)
        elif action == '2':
            item = 'Created {} or more days ago'.format(value)
        elif action == '3':
            item = value
        elif action == '4':
            item = 'All files of type {}'.format(value)
        else:
            item = 'Unknown item'
        return item

    def __define_rights__(self, int_rights, action):
        rights = int_rights-4
        if rights >= 0:
            sub = True
        else:
            rights = rights+4
            sub = False
        rights = rights-2
        if rights >=0:
            read = True
        else:
            rights = rights+2
            read = False
        rights = rights-1
        write = bool(rights >= 0)

        if read and write:
            when = 'Read & Write'
        elif write:
            when = 'Write'
        else:
            when = 'Read'

        if action != '3':
            subfolder = '--'
        else:
            if sub:
                subfolder = 'Yes'
            else:
                subfolder = 'No'

        return (subfolder, when)

    def __compute_rights__(self, write, read, subfolder=False):
        rights = 0
        if write:
            rights = rights+1
        if read:
            rights = rights+2
        if subfolder:
            rights = rights+4
        return rights

    def md_rows(self):
        """
        Returns the exclusions as rows for a Markdown table, with the console
        columns: Item, Exclude Subfolders, Read/Write, Notes.
        """
        rows = []
        for what, when, value, *notes in self.excl_list:
            # A note containing "|" (the storage separator) is split by ePO.
            subfolder, read_write = self.__define_rights__(int(when), what)
            rows.append([self.__define_item__(what, value), subfolder, read_write,
                         '|'.join(notes)])
        return rows

    def __add_excl__(self, what, int_when, value, notes):
        if what not in ['0', '2', '3', '4']:
            raise ValueError('What to excluded value must be within ["0", "2", "3", "4"].')
        if int_when < 0 or int_when > 7:
            raise ValueError('When to excluded value must be within [0-7].')
        exclusion = []
        exclusion.append(what)
        exclusion.append(str(int_when))
        exclusion.append(value)
        exclusion.append(notes)
        self.excl_list.append(exclusion)
        return True

    def __contains_excl__(self, what, value):
        search = [row for row in self.excl_list if row[0] == what and row[2] == value]
        return len(search) >= 1

    def __remove__(self, what, value):
        table = [row for row in self.excl_list if not (row[0] == what and row[2] == value)]
        self.excl_list = table
        return True

    def add_folder(self, folder_path, on_write=True, on_read=True, with_subfolders=False, notes=''):
        """
        Add a folder exclusion
        """
        check_exclusion_path(folder_path)
        if folder_path[len(folder_path)-1] not in '\\/':
            raise ValueError('Path must be ended by "\\".')
        rights = self.__compute_rights__(on_write, on_read, with_subfolders)
        return self.__add_excl__('3', rights, folder_path, notes)

    def add_file_name(self, file_name_path, on_write=True, on_read=True, notes=''):
        """
        Add a file name exclusion
        """
        check_exclusion_path(file_name_path)
        if file_name_path[len(file_name_path)-1] in '\\/':
            raise ValueError('Path must not be ended by "\\".')
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('3', rights, file_name_path, notes)

    def add_file_type(self, file_extension, on_write=True, on_read=True, notes=''):
        """
        Add a file type exclusion (extension without dot, ':::' for files
        without extension; 100 characters max)
        """
        check_length('Exclusion file type', file_extension, 100, required=True)
        if not is_ens_exclusion_file_type(file_extension):
            raise ValueError('Invalid exclusion file type: {!r}'.format(file_extension))
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('4', rights, file_extension, notes)

    def add_file_modified(self, int_days=7, on_write=True, on_read=True, notes=''):
        """
        Add a file exclusion based on its last modified date
        """
        int_days = check_int('Minimum age in days', int_days, 1, 9999)
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('0', rights, str(int_days), notes)

    def add_file_created(self, int_days=7, on_write=True, on_read=True, notes=''):
        """
        Add a file exclusiopn based on its created date
        """
        int_days = check_int('Minimum age in days', int_days, 1, 9999)
        rights = self.__compute_rights__(on_write, on_read)
        return self.__add_excl__('2', rights, str(int_days), notes)

    def contains_folder(self, folder_path):
        """
        Returns True if a folder is excluded
        """
        return self.__contains_excl__('3', folder_path)

    def contains_file_name(self, file_name_path):
        """
        Returns True if a file name is excluded
        """
        return self.__contains_excl__('3', file_name_path)

    def contains_file_type(self, file_extension):
        """
        Returns True if a file extension is excluded
        """
        return self.__contains_excl__('4', file_extension)

    def contains_file_modified(self, int_days):
        """
        Returns True is a file is excluded based on its last modified date
        """
        return self.__contains_excl__('0', str(int_days))

    def contains_file_created(self, int_days):
        """
        Returns True is a file is excluded based on its created date
        """
        return self.__contains_excl__('2', str(int_days))

    def remove_folder(self, folder_path):
        """
        Remove a folder exclusion
        """
        return self.__remove__('3', folder_path)

    def remove_file_name(self, file_name_path):
        """
        Remove a file name exclusion
        """
        return self.__remove__('3', file_name_path)

    def remove_file_type(self, file_extension):
        """
        Remove a file extension exclusion
        """
        return self.__remove__('4', file_extension)

    def remove_file_modified(self, int_days):
        """
        Remove a file exclusion based on its last modified date
        """
        return self.__remove__('0', str(int_days))

    def remove_file_created(self, int_days):
        """
        Remove a file exclusion based on its created date
        """
        return self.__remove__('2', str(int_days))
