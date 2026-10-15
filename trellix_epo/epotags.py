# -*- coding: utf-8 -*-
################################################################################
# Copyright (c) 2026 Benjamin Marandel - All Rights Reserved.
################################################################################

"""
This module defines EPOTags and EPOTagGroups, the tag operations of
EPOClient (epo.tags, epo.tags.groups): one method per task, by tag and
group names, over the Web API commands that the console uses separately
(system.findTag, system.exportTag, system.importTag, system.applyTag,
system.clearTag, system.excludeTag, system.runTagCriteria,
ComputerMgmt.*Tag*, core.executeQuery on EPOTag / EPOLeafNode).

    epo.tags.create(Tag('OFF', 'Systems that get the OFF policies', group='Policy Management'))
    epo.tags.apply('OFF', ['W10ENTB01', 'W2022CORE'])
    epo.tags.systems('OFF')        # {'tagged': [...], 'excluded': [...]}

Server behaviours handled here (checked on ePO 5.10 Update 7):
- there is no command to create or edit a tag: save() imports a tag file
  (system.importTag). The import matches the tags by name without case,
  ignores an existing tag without force, and answers "true" even when it
  did nothing: save() reads the tag back and raises EPOError if it is not
  what was sent;
- the group of the import file is a group name (the first one found when
  several groups have it) and an update without it moves the tag back to
  "My Tags": save() places the tag with ComputerMgmt.moveTagsToTagGroup
  and the group id;
- a tag can't be renamed (the import of another name creates a tag);
- system.runTagCriteria takes the tag id; with reset it also removes the
  manual additions and exclusions;
- ComputerMgmt.deleteTagGroup asks deleteTags=true even for an empty group:
  groups.delete() checks itself that the group is empty.
"""

from .epo import EPOError
from .tags import TagList, ROOT_GROUP

# Console rules of a tag group name (ComputerMgmt.createTagGroup): forbidden
# characters (the rename also refuses the comma) and depth of the tree.
GROUP_NAME_FORBIDDEN = '\\/"[]:|<>+=;?*@'
MAX_GROUP_DEPTH = 5


def _names(systems):
    """
    Returns the "names" parameter of the system.*Tag commands: names, IP
    addresses or ids, given as a list or as one text.

    >>> _names(['W10ENTB01', 4]), _names('W2022CORE')
    ('W10ENTB01,4', 'W2022CORE')
    >>> _names([])
    Traceback (most recent call last):
    ValueError: At least one system is required.
    """
    items = [systems] if isinstance(systems, (str, int)) else list(systems)
    items = [str(item).strip() for item in items if str(item).strip()]
    if not items:
        raise ValueError('At least one system is required.')
    return ','.join(items)


class EPOTagGroups():
    """
    The tag groups of ePO, by path under "My Tags" (e.g. 'Policy
    Management/OFF tags'; '' is "My Tags").
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo

    def list(self):
        """
        Returns the tag groups: dictionaries with id, name, parent_id and
        path ('' for "My Tags"), sorted by path.
        """
        groups = {g['tagGroupId']: g for g in self.epo.call('ComputerMgmt.listAllTagGroups')}

        def path(group_id):
            group = groups[group_id]
            if group['immediateParentId'] not in groups:
                return ''
            parent = path(group['immediateParentId'])
            return '{}/{}'.format(parent, group['groupName']) if parent else group['groupName']
        result = [{'id': g['tagGroupId'], 'name': g['groupName'],
                   'parent_id': g['immediateParentId'], 'path': path(g['tagGroupId'])}
                  for g in groups.values()]
        return sorted(result, key=lambda g: g['path'].lower())

    @staticmethod
    def normalize(path):
        """
        Returns a group path without the "My Tags" root and the blanks
        around the names.

        >>> EPOTagGroups.normalize(' My Tags / Policy Management ')
        'Policy Management'
        """
        names = [name.strip() for name in (path or '').split('/') if name.strip()]
        if names and names[0].lower() == ROOT_GROUP.lower():
            names = names[1:]
        return '/'.join(names)

    def get(self, path):
        """
        Returns the group of a path (case ignored, as ePO does), or None.
        """
        path = self.normalize(path).lower()
        for group in self.list():
            if group['path'].lower() == path:
                return group
        return None

    @staticmethod
    def check_name(name):
        """
        Checks a group name as ePO does.

        :raise: ValueError: Empty name or forbidden character.

        >>> EPOTagGroups.check_name('OFF tags')
        >>> EPOTagGroups.check_name('A;B')
        Traceback (most recent call last):
        ValueError: Tag group name "A;B": the characters \\/"[]:|<>+=;?*@ are not allowed.
        """
        if not name or not name.strip():
            raise ValueError('A tag group name is required.')
        if any(char in GROUP_NAME_FORBIDDEN for char in name):
            raise ValueError('Tag group name "{}": the characters {} are not allowed.'
                             .format(name, GROUP_NAME_FORBIDDEN))

    def create(self, path):
        """
        Creates a group and the missing groups of its path, and returns it.
        An existing group is returned unchanged.

        :raise: ValueError: Invalid name, or a tree deeper than 5 levels.
        """
        names = self.normalize(path).split('/')
        if len(names) + 1 > MAX_GROUP_DEPTH:
            raise ValueError('Tag group "{}": the tree is limited to {} levels.'
                             .format(path, MAX_GROUP_DEPTH))
        parent = self.get('')
        for index, name in enumerate(names):
            self.check_name(name)
            group = self.get('/'.join(names[:index + 1]))
            if group is None:
                self.epo.call('ComputerMgmt.createTagGroup', parent['id'], name)
                group = self.get('/'.join(names[:index + 1]))
            parent = group
        return parent

    def rename(self, path, new_name):
        """
        Renames a group (the comma is also refused) and returns it.
        """
        self.check_name(new_name)
        if ',' in new_name:
            raise ValueError('Tag group name "{}": the comma is not allowed.'.format(new_name))
        group = self.__require(path)
        self.epo.call('ComputerMgmt.renameTagGroup', group['id'], new_name)
        parent = path.rsplit('/', 1)[0] if '/' in self.normalize(path) else ''
        return self.get('{}/{}'.format(parent, new_name) if parent else new_name)

    def delete(self, path, delete_tags=False):
        """
        Deletes a group and returns the server message.

        :param: delete_tags: Also delete its subgroups and their tags; without
                             it a group that has a tag or a subgroup is
                             refused. (The server asks deleteTags=true even
                             for an empty group: the check is done here.)
        :raise: ValueError: Unknown group, "My Tags", or a group not empty
                            without delete_tags.
        """
        group = self.__require(path)
        if not delete_tags:
            subgroups = [g['path'] for g in self.list()
                         if g['path'].lower().startswith(group['path'].lower() + '/')]
            tags = self.epo.query('EPOTag', '(select EPOTag.Name)',
                                  '(eq EPOTagGroup.TagGroupId {})'.format(group['id']))
            if subgroups or tags:
                raise ValueError('Tag group "{}" has {} tag(s) and {} subgroup(s): use '
                                 'delete_tags=True to delete them too.'
                                 .format(path, len(tags), len(subgroups)))
        return self.epo.call('ComputerMgmt.deleteTagGroup', group['id'], deleteTags=True)

    def __require(self, path):
        """
        Returns the group of a path other than "My Tags".

        :raise: ValueError: Unknown group, or "My Tags".
        """
        group = self.get(path)
        if group is None:
            raise ValueError('Unknown tag group "{}".'.format(path))
        if not group['path']:
            raise ValueError('"{}" is the root group: it can\'t be changed.'.format(ROOT_GROUP))
        return group


class EPOTags():
    """
    The tags of ePO, by name: read, create or update, delete, set on
    systems, run their criteria. The tag groups are in self.groups.
    """

    def __init__(self, epo):
        """
        :param: epo: The EPOClient.
        """
        self.epo = epo
        self.groups = EPOTagGroups(epo)

    # ------------------------------ Read ------------------------------
    def list(self):
        """
        Returns all the tags (Tag objects) with their criteria, group path,
        type ('manual' or 'mixed'), number of systems and usage count.
        """
        tags = TagList(self.epo.call('system.exportTag', output='terse').strip())
        rows = self.epo.query('EPOTag', '(select EPOTag.Name EPOTagGroup.TagGroupId '
                                        'EPOTagType.TagType EPOTagUsage.AssignedSystems '
                                        'EPOTagUsage.UsageCount EPOTag.CreatedBy '
                                        'EPOTag.ModifiedOn)')
        info = {row['EPOTag.Name'].lower(): row for row in rows}
        # The export gives the group name only (the first group found when
        # several have it): the query gives the group id, hence the path.
        paths = {group['id']: group['path'] for group in self.groups.list()}
        for tag in tags:
            row = info.get(tag.name.lower(), {})
            tag.group = paths.get(row.get('EPOTagGroup.TagGroupId'), '')
            tag.tag_type = row.get('EPOTagType.TagType')
            tag.assigned_systems = row.get('EPOTagUsage.AssignedSystems')
            tag.usage_count = row.get('EPOTagUsage.UsageCount')
            tag.created_by = row.get('EPOTag.CreatedBy')
            tag.modified_on = row.get('EPOTag.ModifiedOn')
        return list(tags)

    def get(self, name):
        """
        Returns the tag of this name (case ignored), or None.
        """
        for tag in self.list():
            if tag.name.lower() == name.strip().lower():
                return tag
        return None

    def exists(self, name):
        """
        Returns True if a tag has this name (case ignored).
        """
        return self.__find(name) is not None

    def __find(self, name):
        """
        Returns the system.findTag entry of a tag name (case ignored), or
        None.
        """
        for entry in self.epo.call('system.findTag', name):
            if entry['tagName'].lower() == name.strip().lower():
                return entry
        return None

    def __require(self, name):
        """
        Returns the id of a tag name.

        :raise: ValueError: Unknown tag.
        """
        entry = self.__find(name)
        if entry is None:
            raise ValueError('Unknown tag "{}".'.format(name))
        return entry['tagId']

    # ------------------------------ Write ------------------------------
    def save(self, tag):
        """
        Creates the tag, or updates the tag of the same name (case ignored):
        notes, criteria, evaluation and group. Returns the tag read back.

        :raise: ValueError: Invalid tag, or unknown group.
        :raise: EPOError: The server didn't save the tag as sent.
        """
        tag.check()
        group = self.groups.get(tag.group)
        if group is None:
            raise ValueError('Unknown tag group "{}" (create it with epo.tags.groups.create()).'
                             .format(tag.group))
        tags = TagList()
        tags.tags.append(tag)
        self.epo.call('system.importTag', force=True,
                      files={'uploadFile': ('tags.xml', tags.get_xml_content())})
        entry = self.__find(tag.name)
        if entry is None:
            raise EPOError('system.importTag', 'tag "{}" not saved by the server.'.format(tag.name))
        self.epo.call('ComputerMgmt.moveTagsToTagGroup', entry['tagId'], group['id'])
        saved = self.get(tag.name)
        expected = tag.criteria.to_squid() if tag.criteria else ''
        actual = saved.criteria.to_squid() if saved.criteria else ''
        if (saved.notes, actual, saved.evaluate_on_asci, saved.group.lower()) != \
                (tag.notes, expected, tag.evaluate_on_asci, group['path'].lower()):
            raise EPOError('system.importTag', 'tag "{}" saved with other values: {!r}'
                           .format(tag.name, saved))
        return saved

    def create(self, tag):
        """
        Creates a tag (see save()).

        :raise: ValueError: A tag already has this name (case ignored).
        """
        if self.exists(tag.name):
            raise ValueError('A tag named "{}" already exists.'.format(tag.name))
        return self.save(tag)

    def update(self, tag):
        """
        Updates an existing tag (see save()); its name can't change (ePO has
        no rename).

        :raise: ValueError: No tag has this name.
        """
        self.__require(tag.name)
        return self.save(tag)

    def delete(self, names, force=False):
        """
        Deletes tags and returns the server message. ePO refuses a tag used
        by a policy assignment rule, a client task assignment or a server
        task unless force is True.

        :param: names: A tag name or a list of names.
        """
        names = [names] if isinstance(names, str) else list(names)
        ids = ','.join(str(self.__require(name)) for name in names)
        return self.epo.call('ComputerMgmt.deleteTag', ids, forceDelete='Y' if force else None)

    def move(self, names, group):
        """
        Moves tags to a group (path) and returns the server message.
        """
        names = [names] if isinstance(names, str) else list(names)
        target = self.groups.get(group)
        if target is None:
            raise ValueError('Unknown tag group "{}".'.format(group))
        ids = ','.join(str(self.__require(name)) for name in names)
        return self.epo.call('ComputerMgmt.moveTagsToTagGroup', ids, target['id'])['message']

    # ------------------------------ Systems ------------------------------
    def systems(self, name):
        """
        Returns the systems of a tag: {'tagged': [names], 'excluded':
        [names]} (excluded: removed by hand from a criteria tag).
        """
        tag_id = self.__require(name)
        result = {}
        for key, operator in (('tagged', 'hasTag'), ('excluded', 'hasTagExcluded')):
            rows = self.epo.query('EPOLeafNode', '(select EPOLeafNode.NodeName)',
                                  '({} EPOLeafNode.AppliedTags {})'.format(operator, tag_id))
            result[key] = sorted(row['EPOLeafNode.NodeName'] for row in rows)
        return result

    def apply(self, name, systems):
        """
        Sets a tag on systems (names, IP addresses or ids) and returns the
        number of systems changed (the ones already tagged and the unknown
        ones are not counted).
        """
        tag_id = self.__require(name)
        return int(self.epo.call('system.applyTag', names=_names(systems), tagID=tag_id))

    def exclude(self, name, systems):
        """
        Excludes systems from a tag (they don't get it from its criteria) and
        returns the number of systems changed.
        """
        tag_id = self.__require(name)
        return int(self.epo.call('system.excludeTag', names=_names(systems), tagID=tag_id))

    def clear(self, name, systems):
        """
        Removes a tag from systems (also its exclusion) and returns the
        number of systems changed.
        """
        tag_id = self.__require(name)
        return int(self.epo.call('system.clearTag', names=_names(systems), tagID=tag_id))

    def clear_all(self, systems):
        """
        Removes all the tags of systems and returns the number of systems
        changed.
        """
        return int(self.epo.call('system.clearTag', names=_names(systems), all=True))

    def run_criteria(self, name, reset=False):
        """
        Evaluates the criteria of a tag on all the managed systems and returns
        the number of systems affected.

        :param: reset: Also remove the manual additions and exclusions first
                       (checked on the lab, unlike the command help says).
        """
        tag_id = self.__require(name)
        answer = self.epo.call('system.runTagCriteria', tag_id, resetTaggedSystems=reset or None)
        return int(answer['Number Of Systems Affected'])
