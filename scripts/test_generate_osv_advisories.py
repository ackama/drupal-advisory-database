import typing

import pytest

from generate_osv_advisories import build_credits, parse_version_constraint
from typings import osv


def version_constraint_fixtures() -> list[tuple[str, list[osv.Event], list[str]]]:
  return typing.cast(
    list[tuple[str, list[osv.Event], list[str]]],
    [
      # nothing in, nothing out
      ('', [], ['constraint is empty']),
      # vuln is present in every version
      ('*', [{'introduced': '0'}], []),
      # vuln is present in every version since 1.0.0(-stable)
      ('>=1.0.0', [{'introduced': '1.0.0'}], []),
      ('>= 1.0.0', [{'introduced': '1.0.0'}], []),
      ('>=  1.0.0', [{'introduced': '1.0.0'}], []),
      ('>=   1.0.0', [{'introduced': '1.0.0'}], []),
      # vuln is present in every version since 1.0(.0-stable)
      ('>=1.0', [{'introduced': '1.0.0'}], []),
      (' >=1.0', [{'introduced': '1.0.0'}], []),
      (' >= 1.0', [{'introduced': '1.0.0'}], []),
      ('  >= 1.0', [{'introduced': '1.0.0'}], []),
      # vuln is present in every version since 1.0(.0-stable) up to 2.0(.0-stable)
      ('>=1.0 <2.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('>=1.0  <2.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('>=1.0   <2.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('>= 1.0   < 2.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      # vuln is present in every version since 1.0(.0-stable) up to 1.1(.0-stable)
      ('>=1.0 <1.1', [{'introduced': '1.0.0'}, {'fixed': '1.1.0'}], []),
      # vuln is present in every version from 1.0(.0-stable), and fixed in 1.1(.0-stable)
      ('>=1.0 <1.1', [{'introduced': '1.0.0'}, {'fixed': '1.1.0'}], []),
      ('1.0.*', [{'introduced': '1.0.0'}, {'fixed': '1.1.0'}], []),
      # vuln is present in every version from 1.2(.0-stable), and fixed in 1.3(.0-stable)
      ('>=1.2 <1.3', [{'introduced': '1.2.0'}, {'fixed': '1.3.0'}], []),
      ('1.2.*', [{'introduced': '1.2.0'}, {'fixed': '1.3.0'}], []),
      # vuln is present in every version from 1(.0.0-stable), and fixed in 2(.0.0-stable)
      ('>=1 <2', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('1.*', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      # vuln is only present in 1.0.0(-stable)
      ('1.0.0', [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}], []),
      ('1.0.0 ', [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}], []),
      (' 1.0.0', [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}], []),
      (' 1.0.0 ', [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}], []),
      ('  1.0.0 ', [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}], []),
      ('1.0.0-stable', [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}], []),
      (
        '1.0.0-beta2',
        [{'introduced': '1.0.0-beta2'}, {'last_affected': '1.0.0-beta2'}],
        [],
      ),
      (
        '1.0.0beta2',
        [{'introduced': '1.0.0beta2'}, {'last_affected': '1.0.0beta2'}],
        [],
      ),
      ('1.0.0-dev', [{'introduced': '1.0.0-dev'}, {'last_affected': '1.0.0-dev'}], []),
      # vuln has been present since initial release, and was fixed in 1.0.0(-stable)
      ('<1.0.0', [{'introduced': '0'}, {'fixed': '1.0.0'}], []),
      # vuln has been present since initial release, and was fixed after 1.0.0(-stable)
      ('<=1.0.0', [{'introduced': '0'}, {'last_affected': '1.0.0'}], []),
      # vuln was introduced in 1.1.0(-stable), and was fixed in 1.1.1(-stable)
      ('>=1.1.0 <1.1.1', [{'introduced': '1.1.0'}, {'fixed': '1.1.1'}], []),
      # vuln was introduced in 1.1.0(-stable), and was fixed in 1.2.0(-stable)
      ('>=1.1.0 <1.2.0', [{'introduced': '1.1.0'}, {'fixed': '1.2.0'}], []),
      # vuln was introduced in 1.1.0(-stable), and present up to 1.2.0(-stable)
      ('>=1.1.0 <=1.2.0', [{'introduced': '1.1.0'}, {'last_affected': '1.2.0'}], []),
      # some real-world examples
      # vuln was introduced after version 1.0.0(-stable) and fixed in 1.0.2(-stable)
      # (this implies that the vuln was introduced in version 1.0.1-stable)
      (
        '>1.0.0 <1.0.2',
        [{'introduced': '1.0.1'}, {'fixed': '1.0.2'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      (
        '>1.0.0-dev <1.0.2',
        [{'introduced': '1.0.0-dev1'}, {'fixed': '1.0.2'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      (
        '>1.0.0-dev1 <1.0.2',
        [{'introduced': '1.0.0-dev2'}, {'fixed': '1.0.2'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      (
        '>1.0.0-beta2 <1.0.2',
        [{'introduced': '1.0.0-beta3'}, {'fixed': '1.0.2'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      ('>=7.0 <7.86', [{'introduced': '7.0.0'}, {'fixed': '7.86.0'}], []),
      (
        '>7.0 <7.86',
        [{'introduced': '7.0.1'}, {'fixed': '7.86.0'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      ('>=7.0 <=7.86', [{'introduced': '7.0.0'}, {'last_affected': '7.86.0'}], []),
      (
        '>7.0 <=7.86',
        [{'introduced': '7.0.1'}, {'last_affected': '7.86.0'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      ('<2.0.4', [{'introduced': '0'}, {'fixed': '2.0.4'}], []),
      ('<2.0.4dev', [{'introduced': '0'}, {'fixed': '2.0.4dev'}], []),
      ('<=2.0.4', [{'introduced': '0'}, {'last_affected': '2.0.4'}], []),
      ('<=2.0.4stable', [{'introduced': '0'}, {'last_affected': '2.0.4stable'}], []),
      ('>=2.0.4', [{'introduced': '2.0.4'}], []),
      # vuln was introduced in 1.1.0-alpha and fixed in 1.1.0-beta3
      (
        '>=1.1.0-dev <1.1.0-beta3',
        [{'introduced': '1.1.0-dev'}, {'fixed': '1.1.0-beta3'}],
        [],
      ),
      # vuln was introduced in 1.1.0-alpha and fixed in 1.1.0-beta3
      (
        '>=1.1.0-alpha <1.1.0-beta3',
        [{'introduced': '1.1.0-alpha'}, {'fixed': '1.1.0-beta3'}],
        [],
      ),
      # vuln was introduced in 7.0(.0-stable) and fixed in 7.57(.0-stable)
      ('>=7.0 <7.57', [{'introduced': '7.0.0'}, {'fixed': '7.57.0'}], []),
      # vuln was introduced in version 1.2.0(-stable), and fixed in 2.0.0(-stable)
      ('>=1.2 <2.0.0', [{'introduced': '1.2.0'}, {'fixed': '2.0.0'}], []),
      ('~1.2', [{'introduced': '1.2.0'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 1.2.3(-stable), and fixed in 1.3.0(-stable)
      ('>=1.2.3 <1.3.0', [{'introduced': '1.2.3'}, {'fixed': '1.3.0'}], []),
      ('~1.2.3', [{'introduced': '1.2.3'}, {'fixed': '1.3.0'}], []),
      # vuln was introduced in version 1.0(.0-stable), and fixed in 2.0.0(-stable)
      # (this is an exception to how ~ works, to guard against major version jumps)
      ('>=1.0 <2.0.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('~1.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('~1', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 1.2.3(-stable), and fixed in 2.0.0(-stable)
      ('>=1.2.3 <2.0.0', [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}], []),
      ('^1.2.3', [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 1.3(.0-stable), and fixed in 2.0.0(-stable)
      ('>=1.3 <2.0.0', [{'introduced': '1.3.0'}, {'fixed': '2.0.0'}], []),
      ('^1.3', [{'introduced': '1.3.0'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 1.0(.0-stable), and fixed in 2.0.0(-stable)
      ('>=1.0.0 <2.0.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('^1.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 1.0.3(-stable), and fixed in 2.0.0(-stable)
      ('>=1.0.3 <2.0.0', [{'introduced': '1.0.3'}, {'fixed': '2.0.0'}], []),
      ('^1.0.3', [{'introduced': '1.0.3'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 1.(.0.0-stable), and fixed in 2.0.0(-stable)
      ('>=1 <2.0.0', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      ('^1', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 0.3.0(-stable), and fixed in 0.4.0(-stable)
      # (this is an exception to how ^ works, since 0.x versions can have breaking changes)
      ('>=0.3.0 <0.4.0', [{'introduced': '0.3.0'}, {'fixed': '0.4.0'}], []),
      ('^0.3.0', [{'introduced': '0.3.0'}, {'fixed': '0.4.0'}], []),
      ('^0.3', [{'introduced': '0.3.0'}, {'fixed': '0.4.0'}], []),
      # vuln was introduced in version 0.0.3(-stable), and fixed in 0.0.4(-stable)
      # (this is an exception to how ^ works, since 0.x versions can have breaking changes)
      ('>=0.0.3 <0.0.4', [{'introduced': '0.0.3'}, {'fixed': '0.0.4'}], []),
      ('^0.0.3', [{'introduced': '0.0.3'}, {'fixed': '0.0.4'}], []),
      # technically invalid constraints
      # leading zeros
      (
        '1.00.00',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '>=1.01.00',
        [{'introduced': '1.1.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '>=1.01 <02.0.0',
        [{'introduced': '1.1.0'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '>=1.0.01 <2.0.0',
        [{'introduced': '1.0.1'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '>=1.0.00001 <2.0.0',
        [{'introduced': '1.0.1'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '>=1.0.000100 <2.0.0',
        [{'introduced': '1.0.100'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '~1.02',
        [{'introduced': '1.2.0'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '~1.02.03',
        [{'introduced': '1.2.3'}, {'fixed': '1.3.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '~01',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^1.02.3',
        [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^1.003',
        [{'introduced': '1.3.0'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^001.000',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^1.0.003',
        [{'introduced': '1.0.3'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^0001',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^0000.3.0000',
        [{'introduced': '0.3.0'}, {'fixed': '0.4.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^0.0003.0',
        [{'introduced': '0.3.0'}, {'fixed': '0.4.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^0.003',
        [{'introduced': '0.3.0'}, {'fixed': '0.4.0'}],
        ['components should not be prefixed with leading zeros'],
      ),
      (
        '^0.000.3',
        [{'introduced': '0.0.3'}, {'fixed': '0.0.4'}],
        ['components should not be prefixed with leading zeros'],
      ),
      # exact versions
      (
        '1',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        ['exact versions should not omit components'],
      ),
      (
        '1.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        ['exact versions should not omit components'],
      ),
      (
        '1-dev',
        [{'introduced': '1.0.0-dev'}, {'last_affected': '1.0.0-dev'}],
        ['exact versions should not omit components'],
      ),
      (
        '1.0.0 1.2.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        ['exact versions should not be paired with other parts'],
      ),
      (
        '1.0.0 1.2.0 2.0.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        ['exact versions should not be paired with other parts'],
      ),
      (
        '1.0 1.2.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        [
          'exact versions should not omit components',
          'exact versions should not be paired with other parts',
        ],
      ),
      # = is not an operator, but we treat it like the exact operator
      (
        '=1.0.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        ['the = operator is not real, and will be treated as an exact version'],
      ),
      (
        '=1',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        [
          'the = operator is not real, and will be treated as an exact version',
          'exact versions should not omit components',
        ],
      ),
      (
        '=1.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        [
          'the = operator is not real, and will be treated as an exact version',
          'exact versions should not omit components',
        ],
      ),
      (
        '=1-dev',
        [{'introduced': '1.0.0-dev'}, {'last_affected': '1.0.0-dev'}],
        [
          'the = operator is not real, and will be treated as an exact version',
          'exact versions should not omit components',
        ],
      ),
      (
        '=1.0.0 1.2.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        [
          'the = operator is not real, and will be treated as an exact version',
          'exact versions should not be paired with other parts',
        ],
      ),
      (
        '=1.0.0 1.2.0 2.0.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        [
          'the = operator is not real, and will be treated as an exact version',
          'exact versions should not be paired with other parts',
        ],
      ),
      (
        '=1.0 1.2.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        [
          'the = operator is not real, and will be treated as an exact version',
          'exact versions should not omit components',
          'exact versions should not be paired with other parts',
        ],
      ),
      (
        '=1.0 =1.2.0',
        [{'introduced': '1.0.0'}, {'last_affected': '1.0.0'}],
        [
          'the = operator is not real, and will be treated as an exact version',
          'exact versions should not omit components',
          'exact versions should not be paired with other parts',
        ],
      ),
      # * operator
      (
        '1.* <= 2.0',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        ['the * operator should not be paired with a second part'],
      ),
      *[
        (
          f'{operator}1.*',
          [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
          ['the * operator should not be mixed with other operators'],
        )
        for operator in ('>', '>=', '<', '<=', '^', '~')
      ],
      (
        '1.*.0',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        ['the * operator should be the last component of the version'],
      ),
      (
        '1.*.*',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        ['the * operator should be the last component of the version'],
      ),
      (
        '1.*.0 <= 2.0.0',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        [
          'the * operator should not be paired with a second part',
          'the * operator should be the last component of the version',
        ],
      ),
      (
        '1.*-beta1',
        [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}],
        ['the * operator should not be mixed with a stability suffix'],
      ),
      # ~ operator
      (
        '~1.2 <=1.2.3',
        [{'introduced': '1.2.0'}, {'fixed': '2.0.0'}],
        ['the ~ operator should not be paired with a second part'],
      ),
      (
        '~1.2 <=1.2.3 >= 2.0.0',
        [{'introduced': '1.2.0'}, {'fixed': '2.0.0'}],
        ['the ~ operator should not be paired with a second part'],
      ),
      # ^ operator
      (
        '^1.2.3 <1.3.0',
        [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}],
        ['the ^ operator should not be paired with a second part'],
      ),
      (
        '^1.2.3 <1.3.0 >= 2.0.0',
        [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}],
        ['the ^ operator should not be paired with a second part'],
      ),
      # more than two parts
      (
        '>=1.2.3 <2.0.0 >3.0.0',
        [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}],
        ['there should not be more than two parts in a version constraint'],
      ),
      (
        '>=1.2.3 <2.0.0 >3.0.0 <=3.5.0',
        [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}],
        ['there should not be more than two parts in a version constraint'],
      ),
      # invalid operators for the second part
      *[
        (
          f'<1.0.0 {operator}1.2.0',
          [{'introduced': '0'}, {'fixed': '1.0.0'}],
          ['the < operator should not be paired with other parts'],
        )
        for operator in ('', '>', '>=', '<', '<=', '^', '~')
      ],
      *[
        (
          f'<=1.0.0 {operator}1.2.0',
          [{'introduced': '0'}, {'last_affected': '1.0.0'}],
          ['the <= operator should not be paired with other parts'],
        )
        for operator in ('', '>', '>=', '<', '<=', '^', '~')
      ],
      *[
        (
          f'>=1.0.0 {operator}1.2.0',
          [{'introduced': '1.0.0'}],
          [f'the {operator} operator should not be used for the second part'],
        )
        for operator in ('>', '>=', '^', '~')
      ],
      # invalid constraint order
      (
        '>=1.1.0 <1.1.0-beta3',
        [{'introduced': '1.1.0-dev'}, {'fixed': '1.1.0-beta3'}],
        ['stability does not make sense, using -dev instead'],
      ),
      (
        '>=1.1.0-beta <1.1.0-alpha',
        [{'introduced': '1.1.0-dev'}, {'fixed': '1.1.0-alpha'}],
        ['stability does not make sense, using -dev instead'],
      ),
    ],
  )


@pytest.mark.parametrize('constraint,events,warnings', version_constraint_fixtures())
def test_parse_version_constraint(
  constraint: str, events: list[osv.Event], warnings: list[str]
) -> None:
  assert parse_version_constraint(constraint) == (events, warnings)


def credits_fixtures() -> list[tuple[str, list[osv.Credit]]]:
  return [
    (
      'Bobby Joe',
      [osv.Credit(name='Bobby Joe')],
    ),
    (
      'Bobby Joe of the Drupal Security Team',
      [osv.Credit(name='Bobby Joe of the Drupal Security Team')],
    ),
    (
      '<a href="https://www.drupal.org/user/3813415" rel="nofollow">Alice McFee</a>',
      [osv.Credit(name='Alice McFee')],
    ),
    (
      '<a href="https://www.drupal.org/u/3813415" rel="nofollow">Alice McFee</a>',
      [osv.Credit(name='Alice McFee')],
    ),
    (
      '<a href="https://www.drupal.org/u/3813415" rel="nofollow">Alice McFee   </a>',
      [osv.Credit(name='Alice McFee')],
    ),
    (
      '<a href="https://www.drupal.org/u/g-rath" rel="nofollow">Bob McBob</a>',
      [osv.Credit(name='Bob McBob')],
    ),
    (
      '<a href="https://www.drupal.org/u/g-rath" rel="nofollow"> Bob McBob </a>',
      [osv.Credit(name='Bob McBob')],
    ),
    (
      '<li>Ted McBoss</li>',
      [osv.Credit(name='Ted McBoss')],
    ),
    (
      '<li>The amazing Jane Deli of the Drupal Security Team</li>',
      [osv.Credit(name='The amazing Jane Deli of the Drupal Security Team')],
    ),
    (
      '<li>The amazing <a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a> of the Drupal Security Team</li>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">  Ted McBoss</a></li>',
      [osv.Credit(name='Ted McBoss')],
    ),
    (
      '<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Ted McBoss</a> of the Drupal Security Team</li>',
      [osv.Credit(name='Ted McBoss')],
    ),
    (
      '<ul>Jane Deli</ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul><li>Jane Deli</li></ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul><a href="https://www.drupal.org/user/3813415" rel="nofollow">Jane Deli</a></ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul><li><a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a></li></ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul><li><a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a> Provisional Security Team member</li></ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul><li>The amazing <a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a> of the Drupal Security Team</li></ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul> <li> <a href="https://www.drupal.org/u/3813415" rel="nofollow"> Jane Deli </a> Provisional Security Team member </li> </ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul>\n<li><a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a></li>\n</ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<ul>\n<li><a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a></li>\n</ul>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<p><a href="/u/g-rath" rel="nofollow">Alice McFee</a> </p>',
      [osv.Credit(name='Alice McFee')],
    ),
    (
      '<p><a href="/user/3813415" rel="nofollow"> Jane Deli</a> of the Drupal Security Team</p>',
      [osv.Credit(name='Jane Deli')],
    ),
    (
      '<h2>Reported by</h2>\n<ul>\n<li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Ted McBoss </a></li>\n</ul>',
      [osv.Credit(name='Ted McBoss')],
    ),
    (
      '<h3>Access Bypass:</h3>\n<ul>\n<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Ted McBoss</a></li>\n\n</ul>',
      [osv.Credit(name='Ted McBoss')],
    ),
    # multiple reporters
    (
      '<ul><li>Jane Deli</li><li>Alice McFee</li></ul>',
      [
        osv.Credit(name='Alice McFee'),
        osv.Credit(name='Jane Deli'),
      ],
    ),
    (
      '<ul>\n<li>Jane Deli</li>\n<li>Alice McFee</li></ul>',
      [
        osv.Credit(name='Alice McFee'),
        osv.Credit(name='Jane Deli'),
      ],
    ),
    (
      '<ul>\n<li><a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a></li><li><a href="/user/3813415" rel="nofollow">Ted McBoss</a></li></ul>',
      [
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    (
      '<ul>\n<li><a href="https://www.drupal.org/u/3813415" rel="nofollow">Jane Deli</a></li><li>Ted McBoss</li></ul>',
      [
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    (
      '<h3>Access Bypass:</h3><ul><li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Alice M</a></li><li>Ted McBoss</a></li></ul><h3>Cross Site Scripting:</h3><ul><li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Jane Deli</a></li></ul>',
      [
        osv.Credit(name='Alice M'),
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    (
      '<h3>Access Bypass:</h3><ul><li>Alice M</li><li>Ted McBoss</a></li></ul><h3>Cross Site Scripting:</h3><ul><li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Jane Deli</a></li></ul>',
      [
        osv.Credit(name='Alice M'),
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    (
      '<h3>Access Bypass:</h3>\n<ul>\n<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Alice M</a></li>\n<li>Ted McBoss</a></li>\n</ul>\n<h3>Cross Site Scripting:</h3>\n<ul>\n<li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Jane Deli</a></li>\n</ul>',
      [
        osv.Credit(name='Alice M'),
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    (
      '<h3>Access Bypass:</h3>\n\n<ul>\n<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Alice M</a></li>\n<li>Ted McBoss</a></li>\n</ul>\n\n\n\n\n<h3>Cross Site Scripting:</h3>\n\n<ul>\n<li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Jane Deli</a></li>\n</ul>',
      [
        osv.Credit(name='Alice M'),
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    # duplicates
    (
      '<ul>\n<li>Jane Deli</li>\n<li>Jane Deli</li></ul>',
      [
        osv.Credit(name='Jane Deli'),
      ],
    ),
    (
      '<ul>\n<li>Jane Deli</li>\n<li>Alice McFee</li><li>Jane Deli</li></ul>',
      [
        osv.Credit(name='Alice McFee'),
        osv.Credit(name='Jane Deli'),
      ],
    ),
    (
      '<ul>\n<li>Jane Deli</li>\n<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Jane Deli</a></li></ul>',
      [
        osv.Credit(name='Jane Deli'),
      ],
    ),
    (
      '<h3>Access Bypass:</h3>\n<ul>\n<li>Jane Deli</li>\n<li>Ted McBoss</a></li>\n</ul>\n<h3>Cross Site Scripting:</h3>\n<ul>\n<li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Jane Deli</a></li>\n</ul>',
      [
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    (
      '<h3>Access Bypass:</h3>\n<ul>\n<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Jane Deli</a></li>\n<li>Ted McBoss</a></li>\n</ul>\n<h3>Cross Site Scripting:</h3>\n<ul>\n<li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Jane Deli</a></li>\n</ul>',
      [
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    (
      '<h3>Access Bypass:</h3>\n<ul>\n<li><a href="https://www.drupal.org/user/3813415" rel="nofollow">Jane Deli</a></li>\n<li>Ted McBoss</a></li>\n</ul>\n<h3>Cross Site Scripting:</h3>\n<ul>\n<li><a href="https://www.drupal.org/u/g-rath" rel="nofollow">Jane Deli</a> of the Drupal Security Team</li>\n</ul>',
      [
        osv.Credit(name='Jane Deli'),
        osv.Credit(name='Ted McBoss'),
      ],
    ),
    # ???
    (
      '<p>Disclosed publicly.</p>',
      [
        osv.Credit(name='Disclosed publicly.'),
      ],
    ),
  ]


@pytest.mark.parametrize('reported_by_value,expected_credits', credits_fixtures())
def test_build_credits(
  reported_by_value: str, expected_credits: list[osv.Credit]
) -> None:
  assert build_credits({'format': '1', 'value': reported_by_value}) == expected_credits
