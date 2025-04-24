import typing

import pytest

from generate_osv_advisories import parse_version_constraint
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
        [{'introduced': '1.0.1-dev'}, {'fixed': '1.0.2-stable'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      (
        '>1.0.0-dev <1.0.2',
        [{'introduced': '1.0.0-dev1'}, {'fixed': '1.0.2'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      (
        '>1.0.0-beta2 <1.0.2',
        [{'introduced': '1.0.0-beta3'}, {'fixed': '1.0.2'}],
        ['the > operator should be avoided as it does not provide a concrete version'],
      ),
      ('<2.0.4', [{'introduced': '0'}, {'fixed': '2.0.4'}], []),
      ('<2.0.4dev', [{'introduced': '0'}, {'fixed': '2.0.4dev'}], []),
      ('<=2.0.4', [{'introduced': '0'}, {'last_affected': '2.0.4'}], []),
      ('<=2.0.4stable', [{'introduced': '0'}, {'last_affected': '2.0.4stable'}], []),
      ('>=2.0.4', [{'introduced': '2.0.4'}], []),
      # vuln was introduced in 1.1.0-dev and fixed in 1.1.0-beta3
      # todo: this should create a warning, as it's invalid
      (
        '>=1.1.0 <1.1.0-beta3',
        [{'introduced': '1.1.0'}, {'fixed': '1.1.0-beta3'}],
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
      ('~1', [{'introduced': '1.0.0'}, {'fixed': '2.0.0'}], []),
      # vuln was introduced in version 1.2.3(-stable), and fixed in 2.0.0(-stable)
      ('>=1.2.3 <2.0.0', [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}], []),
      ('^1.2.3', [{'introduced': '1.2.3'}, {'fixed': '2.0.0'}], []),
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
    ],
  )


@pytest.mark.parametrize('constraint,events,warnings', version_constraint_fixtures())
def test_parse_version_constraint(
  constraint: str, events: list[osv.Event], warnings: list[str]
) -> None:
  assert parse_version_constraint(constraint) == (events, warnings)
