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
      # vuln is present in every version since 1.0.0-dev
      ('>=1.0.0', [{'introduced': '1.0.0-dev'}], []),
      ('>= 1.0.0', [{'introduced': '1.0.0-dev'}], []),
      ('>=  1.0.0', [{'introduced': '1.0.0-dev'}], []),
      ('>=   1.0.0', [{'introduced': '1.0.0-dev'}], []),
      # vuln is present in every version since 1.0(.0-dev)
      ('>=1.0', [{'introduced': '1.0.0-dev'}], []),
      (' >=1.0', [{'introduced': '1.0.0-dev'}], []),
      (' >= 1.0', [{'introduced': '1.0.0-dev'}], []),
      ('  >= 1.0', [{'introduced': '1.0.0-dev'}], []),
      # vuln is present in every version since 1.0(.0-dev) up to 2.0(.0-dev)
      ('>=1.0 <2.0', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      ('>=1.0  <2.0', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      ('>=1.0   <2.0', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      ('>= 1.0   < 2.0', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      # vuln is present in every version since 1.0(.0-dev) up to 1.1(.0-dev)
      (
        '>=1.0 <1.1',
        [
          {'introduced': '1.0.0-dev'},
          {'fixed': '1.1.0-dev'},
        ],
        [],
      ),
      # vuln is present in every version from 1.0(.0-dev), and fixed in 1.1(.0-dev)
      # todo: wildcard seems to be implicitly only allowed for the patch version
      ('>=1.0 <1.1', [{'introduced': '1.0.0-dev'}, {'fixed': '1.1.0-dev'}], []),
      ('1.0.*', [{'introduced': '1.0.0-dev'}, {'fixed': '1.1.0-dev'}], []),
      # vuln is present in every version from 1(.0.0-dev), and fixed in 2(.0.0-dev)
      ('>=1 <2', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      ('1.*', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      # vuln is only present in 1.0.0(-stable)
      (
        '1.0.0',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        [],
      ),
      (
        '1.0.0 ',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        [],
      ),
      (
        ' 1.0.0',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        [],
      ),
      (
        ' 1.0.0 ',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        [],
      ),
      (
        '  1.0.0 ',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        [],
      ),
      (
        '1.0.0-stable',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        [],
      ),
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
      # vuln has been present since initial release, and was fixed in 1.0.0(-dev)
      ('<1.0.0', [{'introduced': '0'}, {'fixed': '1.0.0-dev'}], []),
      # vuln has been present since initial release, and was fixed after 1.0.0(-stable)
      ('<=1.0.0', [{'introduced': '0'}, {'last_affected': '1.0.0-stable'}], []),
      # vuln was introduced in 1.1.0(-dev), and was fixed in 1.1.1(-dev)
      ('>=1.1.0 <1.1.1', [{'introduced': '1.1.0-dev'}, {'fixed': '1.1.1-dev'}], []),
      # vuln was introduced in 1.1.0(-dev), and was fixed in 1.2.0(-dev)
      ('>=1.1.0 <1.2.0', [{'introduced': '1.1.0-dev'}, {'fixed': '1.2.0-dev'}], []),
      # vuln was introduced in 1.1.0(-dev), and present up to 1.2.0(-stable)
      (
        '>=1.1.0 <=1.2.0',
        [{'introduced': '1.1.0-dev'}, {'last_affected': '1.2.0-stable'}],
        [],
      ),
      # some real-world examples
      # vuln was introduced after version 1.0.0(-stable) and fixed in 1.0.2(-dev)
      # (this implies that the vuln was introduced in version 1.0.1-dev)
      # todo: we should avoid the ">" operator as it is less accurate than ">=",
      #   since the latter indicates a version that is guaranteed to exist
      #   regexp: /affected_versions": ">[^=]/
      ('>1.0.0 <1.0.2', [{'introduced': '1.0.1-dev'}, {'fixed': '1.0.2-dev'}], []),
      ('>1.0.0-dev <1.0.2', [{'introduced': '1.0.0-dev1'}, {'fixed': '1.0.2-dev'}], []),
      (
        '>1.0.0-beta2 <1.0.2',
        [{'introduced': '1.0.0-beta3'}, {'fixed': '1.0.2-dev'}],
        [],
      ),
      ('<2.0.4', [{'introduced': '0'}, {'fixed': '2.0.4-dev'}], []),
      ('<2.0.4dev', [{'introduced': '0'}, {'fixed': '2.0.4dev'}], []),
      ('<=2.0.4', [{'introduced': '0'}, {'last_affected': '2.0.4-stable'}], []),
      ('<=2.0.4stable', [{'introduced': '0'}, {'last_affected': '2.0.4stable'}], []),
      ('>=2.0.4', [{'introduced': '2.0.4-dev'}], []),
      # vuln was introduced in 1.1.0-dev and fixed in 1.1.0-beta3
      # todo: if we assume that a lack of stability always implies "-stable" regardless
      #   of the operator (rather than sometimes "-dev"), then constraints like this
      #   will need to change to explicitly define their constraint i.e. >=1.1.0-dev
      (
        '>=1.1.0 <1.1.0-beta3',
        [
          {'introduced': '1.1.0-dev'},
          {'fixed': '1.1.0-beta3'},
        ],
        [],
      ),
      # vuln was introduced in 7.0(.0-dev) and fixed in 7.57(.0-dev)
      (
        '>=7.0 <7.57',
        [
          {'introduced': '7.0.0-dev'},
          {'fixed': '7.57.0-dev'},
        ],
        [],
      ),
      # vuln was introduced in version 1.2.0(-dev), and fixed in 2.0.0(-dev)
      ('>=1.2 <2.0.0', [{'introduced': '1.2.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      ('~1.2', [{'introduced': '1.2.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      # vuln was introduced in version 1.2.3(-dev), and fixed in 1.3.0(-dev)
      ('>=1.2.3 <1.3.0', [{'introduced': '1.2.3-dev'}, {'fixed': '1.3.0-dev'}], []),
      ('~1.2.3', [{'introduced': '1.2.3-dev'}, {'fixed': '1.3.0-dev'}], []),
      # vuln was introduced in version 1.0(.0-dev), and fixed in 2.0.0(-dev)
      # (this is an exception to how ~ works, to guard against major version jumps)
      ('>=1.0 <2.0.0', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      ('~1', [{'introduced': '1.0.0-dev'}, {'fixed': '2.0.0-dev'}], []),
      # vuln was introduced in version 1.2.3(-dev), and fixed in 2.0.0(-dev)
      ('>=1.2.3 <2.0.0', [{'introduced': '1.2.3-dev'}, {'fixed': '2.0.0-dev'}], []),
      ('^1.2.3', [{'introduced': '1.2.3-dev'}, {'fixed': '2.0.0-dev'}], []),
      # vuln was introduced in version 0.3.0(-dev), and fixed in 0.4.0(-dev)
      # (this is an exception to how ^ works, since 0.x versions can have breaking changes)
      ('>=0.3.0 <0.4.0', [{'introduced': '0.3.0-dev'}, {'fixed': '0.4.0-dev'}], []),
      ('^0.3.0', [{'introduced': '0.3.0-dev'}, {'fixed': '0.4.0-dev'}], []),
      ('^0.3', [{'introduced': '0.3.0-dev'}, {'fixed': '0.4.0-dev'}], []),
      # vuln was introduced in version 0.0.3(-dev), and fixed in 0.0.4(-dev)
      # (this is an exception to how ^ works, since 0.x versions can have breaking changes)
      ('>=0.0.3 <0.0.4', [{'introduced': '0.0.3-dev'}, {'fixed': '0.0.4-dev'}], []),
      ('^0.0.3', [{'introduced': '0.0.3-dev'}, {'fixed': '0.0.4-dev'}], []),
      # technically invalid constraints
      # exact versions
      (
        '1',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        ['exact versions should not omit components'],
      ),
      (
        '1.0',
        [{'introduced': '1.0.0-stable'}, {'last_affected': '1.0.0-stable'}],
        ['exact versions should not omit components'],
      ),
      (
        '1-dev',
        [{'introduced': '1.0.0-dev'}, {'last_affected': '1.0.0-dev'}],
        ['exact versions should not omit components'],
      ),
      # ~ operator
      (
        '~1.2 <=1.2.3',
        [{'introduced': '1.2.0-dev'}, {'fixed': '2.0.0-dev'}],
        ['the ~ operator should not be paired with a second part'],
      ),
      (
        '~1.2 <=1.2.3 >= 2.0.0',
        [{'introduced': '1.2.0-dev'}, {'fixed': '2.0.0-dev'}],
        ['the ~ operator should not be paired with a second part'],
      ),
      # ^ operator
      (
        '^1.2.3 <1.3.0',
        [{'introduced': '1.2.3-dev'}, {'fixed': '2.0.0-dev'}],
        ['the ^ operator should not be paired with a second part'],
      ),
      (
        '^1.2.3 <1.3.0 >= 2.0.0',
        [{'introduced': '1.2.3-dev'}, {'fixed': '2.0.0-dev'}],
        ['the ^ operator should not be paired with a second part'],
      ),
    ],
  )


@pytest.mark.parametrize('constraint,events,warnings', version_constraint_fixtures())
def test_parse_version_constraint(
  constraint: str, events: list[osv.Event], warnings: list[str]
) -> None:
  assert parse_version_constraint(constraint) == (events, warnings)
