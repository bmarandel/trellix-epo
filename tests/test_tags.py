"""
ePO tags: the tag model (trellix_epo.tags), the property catalog
(trellix_epo.tagcatalog) and the tag operations of EPOClient
(trellix_epo.epotags), without a server.

tags_export.xml: system.exportTag of the ePO 5.10 Update 7 lab (Agent
Handlers removed): the default tags, "OFF" (manual tag of the user) and the
"Claude - ..." tags made on the lab to learn the format:
- "Claude - Tag Console 1": saved in the console, criteria typed in the
  builder (OS Platform Server or Workstation, Free Disk Space > 10 GB, boot
  time not within 2 weeks, Is Laptop No, IP address in 192.168.100.0/24);
- "Claude - Tag Console 2" to "6": saved with the console save action and
  the criteria of every value kind (sizes, durations, dates, IPv4/IPv6
  addresses, ranges, subnets and lists, versions, languages, quotes);
- "Claude - Tag Import ...": imported with system.importTag;
- "Claude - Lib OFF" and "Claude - Lib Criteria": saved by EPOClient.tags
  and opened in the console (criteria shown as written).
"""

import datetime
import doctest
import re
import urllib.parse
from pathlib import Path

import pytest

from trellix_epo import tags as tags_module, epotags as epotags_module
from trellix_epo import tagcatalog as cat
from trellix_epo import EPOClient, EPOError, Tag, TagCriteria, TagCondition, TagProperty, TagList
from trellix_epo.tags import RawCriteria, version2_number

FIXTURE = Path(__file__).parent / 'fixtures' / 'tags_export.xml'


def squid(text):
    """
    Returns a SQUID text with single spaces (the server adds some).
    """
    return re.sub(r'\s+', ' ', text).strip()


def export():
    return FIXTURE.read_text(encoding='utf-8')


def test_docstring_examples():
    for module, count in [(tags_module, 34), (epotags_module, 5)]:
        result = doctest.testmod(module)
        assert result.attempted >= count and result.failed == 0


def test_catalog():
    assert len(cat.PROPERTIES) == 120 and len({p[0] for p in cat.PROPERTIES}) == 120
    assert all(p[3] in cat.KINDS for p in cat.PROPERTIES)
    assert all(op in cat.OPERATORS for kind in cat.KINDS.values() for op in kind['operators'])
    assert len(cat.LANGUAGES) == 130 and cat.LANGUAGES['040c'] == 'French (France)'
    assert TagProperty.get('Agent Properties: Product Version (Fast)').key == \
        'EPOProdPropsView_EPOAGENT.verProductVersion'
    for name in ['Product Version', 'Nope']:
        with pytest.raises(ValueError):
            TagProperty.get(name)


def test_export_round_trip():
    """Every criteria of the lab export is read and written back unchanged."""
    import xml.etree.ElementTree as et
    root = et.fromstring(export().encode('utf-8'))
    tags = TagList(export())
    assert len(tags.tags) == 25
    for element, tag in zip(root.findall('EPOTag'), tags):
        assert not isinstance(tag.criteria, RawCriteria), tag.name
        written = tag.criteria.to_squid() if tag.criteria else ''
        assert squid(written) == squid(element.get('criteria')), tag.name


def test_console_conversions():
    """The values typed in the console give the SQUID the server stored."""
    tags = TagList(export())
    console = tags.get('Claude - Tag Console 1')
    criteria = TagCriteria().add('OS Platform', 'eq', 'Server').add('OS Platform', 'Equals',
                                                                    'Workstation')
    criteria.set_grouping('OS Platform', 'or')
    criteria.add('Free Disk Space', 'Greater than', '10 GB')
    criteria.add('Last System Boot Time', 'Is not within the last', '2 weeks')
    criteria.add('Is Laptop', 'eq', 'No')
    criteria.add('IP address', 'in_ipv6_subnet', '192.168.100.0/24')
    assert criteria == console.criteria
    assert console.evaluate_on_asci and console.group == 'Policy Management'
    # The other kinds, saved with the console save action.
    two = tags.get('Claude - Tag Console 2').criteria
    expected = TagCriteria([
        ('CPU Speed (MHz)', 'ge', 2000), ('Free Memory', 'lt', '512 MB'),
        ('IP4 Address (deprecated)', 'between', '10.0.0.1-10.0.0.9'),
        ('Last System Boot Time', 'newerThanAbsolute',
         datetime.datetime(2026, 10, 13, 6, 30, tzinfo=datetime.timezone.utc)),
        ('EPOProdPropsView_EPOAGENT.productversion', 'version_ge', '5.8.0'),
        ('EPOProdPropsView_EPOAGENT.verProductVersion', 'version2_ge', '5.8'),
        ('Default Language', 'eq', 'French (France)'), ('System Name', 'like', 'W2022*'),
        ('Custom 1', 'isBlank'), ('Custom 2', 'contains', 'SQL'),
        ('Management Type', 'ne', 'Trellix Agent'),
        ('Subnet Mask', 'match_any', '255.255.255.0, ffff::')])
    assert expected == two
    four = tags.get('Claude - Tag Console 4').criteria
    assert four == TagCriteria([
        ('Last System Boot Time', 'newerThanFull', '3 months'),
        ('IP4 Address (deprecated)', 'eq', '10.0.0.5'), ('IP address', 'eq', 'fd00::5'),
        ('Subnet Mask', 'in_ipv6_subnet', 'fd00::/64'), ('Free Memory', 'gt', '100 KB')])
    six = tags.get('Claude - Tag Console 6').criteria
    assert [c.value for c in six][:4] == ['1 quarter', '1 year', '1 day', '1 hour']


def test_condition_limits():
    TagCondition('Custom 1', 'eq', 'x' * 100)
    TagCondition('Domain Name', 'eq', 'x' * 255)
    TagCondition('Free Disk Space', 'gt', '999 TB')
    for args in [('Custom 1', 'eq', 'x' * 101), ('Domain Name', 'eq', 'x' * 256),
                 ('Custom 1', 'gt', 'x'), ('Custom 1', 'isBlank', 'x'), ('Custom 1', 'eq', None),
                 ('Free Disk Space', 'gt', '1000 TB'), ('Free Disk Space', 'gt', '10 KB'),
                 ('Free Memory', 'gt', '1000000000000 KB'),
                 ('CPU Speed (MHz)', 'gt', '12345678901'),
                 ('Last System Boot Time', 'olderThan', '10000 days'),
                 ('Last System Boot Time', 'olderThan', '2 fortnights'),
                 ('IP4 Address (deprecated)', 'eq', 'fd00::1'), ('IP address', 'eq', '10.0.0.256'),
                 ('IP address', 'in_ipv6_subnet', '10.0.0.0'), ('IP address', 'match_any', ''),
                 ('IP address', 'match_any', ['10.0.0.1'] * 300),
                 ('Is Laptop', 'eq', 'Maybe'), ('Default Language', 'eq', 'Klingon'),
                 ('Agent Properties: Product Version', 'version_ge', '5.x'),
                 ('Agent Properties: Product Version (Fast)', 'version2_ge', '5.1000')]:
        with pytest.raises(ValueError):
            TagCondition(*args)
    assert version2_number('5.8.6.185') == '5008000006000185'


def test_tag_xml():
    tag = Tag('Claude - New', 'Notes é', [('Is 64-bit OS', 'eq', 'Yes')], True, 'Group A')
    xml = TagList()
    xml.tags.append(tag)
    content = xml.get_xml_content()
    assert b'&#233;' in content and b'id="0"' in content and b'whereclause=""' in content
    assert b'family="EPO"' in content and b'executeonasci="true"' in content
    assert b'taggroup' not in content          # the group is set after the import
    back = TagList(content).get('claude - new')
    assert back.criteria == tag.criteria and back.notes == 'Notes é'
    for bad in [Tag(''), Tag('x' * 51), Tag('x', group='Deployment Tags/x')]:
        with pytest.raises(ValueError):
            bad.check()


# ------------------------------ Server operations ------------------------------
GROUPS = ('[{"tagGroupId": 1, "groupName": "My Tags", "immediateParentId": -1}, '
          '{"tagGroupId": 3, "groupName": "Policy Management", "immediateParentId": 1}, '
          '{"tagGroupId": 2, "groupName": "Deployment Tags", "immediateParentId": 1}, '
          '{"tagGroupId": 5, "groupName": "Claude Group A", "immediateParentId": 3}, '
          '{"tagGroupId": 4, "groupName": "Claude Group A", "immediateParentId": 1}]')


class FakeServer(EPOClient):
    """
    EPOClient whose server answers by command: answers[command] is a list
    of raw answers used in order (the last one is kept).
    """

    def __init__(self, answers):
        """
        :param: answers: {command: [raw answers]}.
        """
        super(FakeServer, self).__init__('https://epo.example.com:8443', 'admin', 'secret')
        self.answers = answers
        self.requests = []

    def _send(self, request):
        """
        Records (command, fields or multipart body) and returns the next
        answer of the command.
        """
        command = urllib.parse.urlsplit(request.full_url).path.split('/remote/')[1]
        if request.get_header('Content-type').startswith('multipart/'):
            fields = request.data
        else:
            fields = dict(urllib.parse.parse_qsl(request.data.decode('utf-8')))
        self.requests.append((command, fields))
        answers = self.answers[command]
        return answers.pop(0) if len(answers) > 1 else answers[0]


def test_groups():
    epo = FakeServer({'ComputerMgmt.listAllTagGroups': ['OK:\r\n' + GROUPS]})
    paths = [g['path'] for g in epo.tags.groups.list()]
    assert paths == ['', 'Claude Group A', 'Deployment Tags', 'Policy Management',
                     'Policy Management/Claude Group A']
    assert epo.tags.groups.get('My Tags/policy management/CLAUDE GROUP A')['id'] == 5
    with pytest.raises(ValueError):
        epo.tags.groups.create('A/B/C/D/E')
    with pytest.raises(ValueError):
        epo.tags.groups.delete('My Tags')


def test_group_delete():
    epo = FakeServer({'ComputerMgmt.listAllTagGroups': ['OK:\r\n' + GROUPS],
                      'core.executeQuery': ['OK:\r\n[]', 'OK:\r\n[{"EPOTag.Name": "OFF"}]',
                                            'OK:\r\n[]'],
                      'ComputerMgmt.deleteTagGroup': ['OK:\r\nSuccessfully deleted tag group.']})
    with pytest.raises(ValueError):             # has a subgroup
        epo.tags.groups.delete('Policy Management')
    with pytest.raises(ValueError):             # has a tag
        epo.tags.groups.delete('Claude Group A')
    assert epo.tags.groups.delete('Claude Group A').startswith('Successfully')
    assert epo.requests[-1] == ('ComputerMgmt.deleteTagGroup',
                                {'param1': '4', 'deleteTags': 'true'})


def test_save_moves_and_checks():
    criteria = '( where ( eq EPOComputerProperties.Vdi 1 ) )'
    exported = ('OK:\r\n<epo:EPOTagSchema xmlns:epo="mcafee-epo-policyassignmentrule">'
                '<EPOTag name="Claude - T" id="30" notes="n" uniquekey="null" family="EPO" '
                'criteria="{}" whereclause="" executeonasci="false" taggroup="Claude Group A">'
                '</EPOTag></epo:EPOTagSchema>').format(criteria)
    epo = FakeServer({
        'ComputerMgmt.listAllTagGroups': ['OK:\r\n' + GROUPS],
        'system.importTag': ['OK:\r\ntrue'],
        'system.findTag': ['OK:\r\n[{"tagId": 30, "tagName": "Claude - T", "tagNotes": "n"}]'],
        'ComputerMgmt.moveTagsToTagGroup': ['OK:\r\n{"message": "moved", "status": true}'],
        'system.exportTag': [exported],
        'core.executeQuery': ['OK:\r\n[{"EPOTag.Name": "Claude - T", "EPOTagGroup.TagGroupId": 5, '
                              '"EPOTagType.TagType": "criteria"}]']})
    tag = Tag('Claude - T', 'n', [('VDI', 'eq', 'Yes')], group='Policy Management/Claude Group A')
    saved = epo.tags.save(tag)
    assert saved.group == 'Policy Management/Claude Group A' and saved.tag_type == 'criteria'
    commands = [r[0] for r in epo.requests]
    assert commands.index('system.importTag') < commands.index('ComputerMgmt.moveTagsToTagGroup')
    move = [r[1] for r in epo.requests if r[0] == 'ComputerMgmt.moveTagsToTagGroup'][0]
    assert move == {'param1': '30', 'param2': '5'}          # by group id, not by name
    upload = [r[1] for r in epo.requests if r[0] == 'system.importTag'][0]
    assert b'name="force"\r\n\r\ntrue' in upload and b'name="uploadFile"' in upload
    # Saved with other values (e.g. ignored by the server): EPOError.
    tag.notes = 'other'
    with pytest.raises(EPOError):
        epo.tags.save(tag)


def test_systems_operations():
    epo = FakeServer({
        'system.findTag': ['OK:\r\n[{"tagId": 8, "tagName": "OFF", "tagNotes": ""}]'],
        'system.applyTag': ['OK:\r\n2'], 'system.clearTag': ['OK:\r\n1'],
        'system.runTagCriteria': ['OK:\r\n{"Number Of Systems Affected": "3"}'],
        'core.executeQuery': ['OK:\r\n[{"EPOLeafNode.NodeName": "W10ENTB01"}]', 'OK:\r\n[]']})
    assert epo.tags.apply('off', ['W10ENTB01', 'W2022CORE']) == 2
    assert epo.requests[-1] == ('system.applyTag', {'names': 'W10ENTB01,W2022CORE', 'tagID': '8'})
    assert epo.tags.clear('OFF', 'W10ENTB01') == 1
    assert epo.tags.run_criteria('OFF', reset=True) == 3
    assert epo.requests[-1][1] == {'param1': '8', 'resetTaggedSystems': 'true'}
    assert epo.tags.systems('OFF') == {'tagged': ['W10ENTB01'], 'excluded': []}
    with pytest.raises(ValueError):
        epo.tags.apply('Unknown', 'W10ENTB01')
