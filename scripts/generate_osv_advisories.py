#!/usr/bin/env python

"""
Generates OSV advisories from Drupal SA advisories stored on disk as JSON.

The advisories should be downloaded using the `scripts/download_sa_advisories.py`
"""

import json
import os
import re
import typing
from datetime import datetime

import requests
import semver
from markdownify import markdownify

from typings import drupal, osv

osv_dir_name = 'advisories'


def fetch_drupal_node(nid: str) -> drupal.Node:
  """
  Fetches a node from drupal.org by its id
  """
  sa_file = f'cache/nodes/{nid}.json'

  try:
    with open(sa_file) as f:
      return typing.cast(drupal.Node, json.load(f))
  except FileNotFoundError as e:
    os.makedirs('cache/nodes', exist_ok=True)
    print(f' *- fetching https://www.drupal.org/api-d7/node/{nid}.json')
    resp = requests.get(f'https://www.drupal.org/api-d7/node/{nid}.json')

    if resp.status_code == 200:
      node: drupal.Node = resp.json()

      with open(sa_file, 'w') as f:
        json.dump(node, f)
        f.write('\n')
      return node
    raise Exception(
      f'unexpected response when fetching node {nid}: {resp.status_code}'
    ) from e


def expand_version(version: str) -> str:
  # this means "all possible versions"
  if version == '0':
    return version
  parts = version.split('-')
  build = f'-{parts[1]}' if len(parts) == 2 else ''
  components = parts[0].split('.')
  while len(components) < 3:
    components.append('0')
  return '.'.join(components) + build


class ComposerVersionConstraintPart:
  def __init__(self, part: str):
    result = re.match(
      r'^(?P<operator>[<>]=?|=|[~^])?(?P<major>\d+)(?:\.(?P<minor>\d+|\*))?(?:\.(?P<patch>\d+|\*))?(?P<stability>.+)?$',
      part,
    )

    if result is None:
      # todo: ensure this is handled appropriately
      raise Exception(f'"{part}" is not a valid version constraint')

    self.operator: str = result.group('operator') or ''
    self.first_component: str | None = result.group('major')
    self.second_component: str | None = result.group('minor')
    self.third_component: str | None = result.group('patch')
    self.stability: str = result.group('stability') or ''

    # prefer representing stable implicitly
    if self.stability == '-stable':
      self.stability = ''

  def next_version(self, part: str) -> str:
    next_version = str(semver.Version.parse(str(self)).next_version(part))

    # semver.Version does not seem to increment the prerelease version if it does
    # not have a number already, so we've got to add that manually
    #
    # todo: this is possibly a bug in the semver library, though also it might be
    #  something we should warn on?
    #  see https://github.com/python-semver/python-semver/issues/369
    if (
      part == 'prerelease'
      and self.stability != ''
      and not self.stability[-1:].isdigit()
    ):
      next_version += '1'
    return next_version

  def __str__(self) -> str:
    first_component = int(self.first_component or '0')
    second_component = int(self.second_component or '0')
    third_component = int(self.third_component or '0')

    return f'{first_component}.{second_component}.{third_component}{self.stability}'


def weigh_stability(stability: str) -> int:
  """
  Weighs the given stability based on the order specified in
  https://getcomposer.org/doc/04-schema.md#version
  """
  stability = stability.removeprefix('-')

  if stability.startswith('RC'):
    return 3

  # the '#' is used when a version is pointed at a VSC repository
  # and takes priority over patch versions but not anything else
  for i, start in enumerate(['p', '#', 'rc', 'b', 'a', 'dev']):
    if stability.startswith(start):
      return i
  return 0


# noinspection PyDefaultArgument
def parse_version_constraint(
  constraint: str,
  extra_warnings: typing.Sequence[str] = [],
) -> tuple[list[osv.Event], list[str]]:
  """
  Parses a version constraint into a series of events that express what versions
  are and are not affected by the advisory the constraint was sourced from,
  along with any warnings about the constraints validity
  """
  constraint = re.sub(r'([<>]=?) +', r'\1', re.sub(r' +', ' ', constraint.strip()))

  # todo: make sure this doesn't generate an empty range?
  if constraint == '':
    return [], ['constraint is empty']

  if constraint == '*':
    return [typing.cast(osv.Event, {'introduced': '0'})], []

  events: list[osv.Event] = []
  warnings: list[str] = list(extra_warnings)
  parts = [ComposerVersionConstraintPart(part) for part in constraint.split()]

  for part in parts:
    if part.operator == '=':
      part.operator = ''
      warnings.append(
        'the = operator is not real, and will be treated as an exact version'
      )
    for component in [
      part.first_component or '',
      part.second_component or '',
      part.third_component or '',
    ]:
      if len(component) > 1 and component.startswith('0'):
        warnings.append('components should not be prefixed with leading zeros')

  # https://getcomposer.org/doc/articles/versions.md#wildcard-version-range-
  if parts[0].second_component == '*' or parts[0].third_component == '*':
    if len(parts) > 1:
      warnings.append('the * operator should not be paired with a second part')
    if parts[0].operator != '':
      warnings.append('the * operator should not be mixed with other operators')
    # todo: this is probably true, though the docs don't come close to mentioning it
    #  it might be worth trying to double check, but for now it should be safe to do
    if parts[0].stability != '':
      warnings.append('the * operator should not be mixed with a stability suffix')

    lower = parts[0].first_component or '0'
    if parts[0].second_component == '*':
      if parts[0].third_component is not None:
        warnings.append('the * operator should be the last component of the version')
      lower += '.0'
      upper = str(int(parts[0].first_component or '0') + 1)
    else:
      lower += f'.{parts[0].second_component}'
      upper = (
        f'{parts[0].first_component or "0"}.{int(parts[0].second_component or "0") + 1}'
      )

    return parse_version_constraint(f'>={lower} <{upper}', warnings)

  # https://getcomposer.org/doc/articles/versions.md#tilde-version-range-
  if parts[0].operator == '~':
    if len(parts) > 1:
      warnings.append('the ~ operator should not be paired with a second part')

    upper = str(
      parts[0].next_version(
        'major'  # bump the major version, unless we're dealing with a x.y.z version
        if parts[0].third_component is None
        else 'minor'  # else bump the minor version
      )
    )
    return parse_version_constraint(f'>={parts[0]} <{upper}', warnings)

  # https://getcomposer.org/doc/articles/versions.md#caret-version-range-
  if parts[0].operator == '^':
    if len(parts) > 1:
      warnings.append('the ^ operator should not be paired with a second part')

    upper = str(
      parts[0].next_version(
        'major'  # bump the major version, unless we're dealing with a 0.x version
        if int(parts[0].first_component or '0') != 0
        else 'minor'  # else bump the minor version, unless we're dealing with a 0.0.x version
        if int(parts[0].second_component or '0') != 0
        else 'patch'  # else bump the patch version
      )
    )

    return parse_version_constraint(f'>={parts[0]} <{upper}', warnings)

  # determine the first event, which will be an "introduced"
  introduced = str(parts[0])
  if parts[0].operator == '<' or parts[0].operator == '<=':
    introduced = '0'
  elif parts[0].operator == '>':
    warnings.append(
      'the > operator should be avoided as it does not provide a concrete version'
    )
    introduced = parts[0].next_version(
      'patch' if parts[0].stability == '' else 'prerelease'
    )
  events.append({'introduced': introduced})

  # determine the second event, which will be either "fixed" or "last_affected"
  if parts[0].operator == '' or parts[0].operator.startswith('<'):
    if parts[0].operator == '' and (
      parts[0].first_component is None
      or parts[0].second_component is None
      or parts[0].third_component is None
    ):
      warnings.append('exact versions should not omit components')

    if len(parts) > 1:
      operator = (
        'exact versions'
        if parts[0].operator == ''
        else f'the {parts[0].operator} operator'
      )
      warnings.append(f'{operator} should not be paired with other parts')

    if parts[0].operator == '<':
      events.append({'fixed': str(parts[0])})
    else:
      events.append({'last_affected': str(parts[0])})
  elif len(parts) > 1:
    if len(parts) > 2:
      warnings.append('there should not be more than two parts in a version constraint')

    if (
      parts[1].operator.startswith('<')
      and parts[0].operator.startswith('>')
      and weigh_stability(parts[0].stability) < weigh_stability(parts[1].stability)
    ):
      parts[0].stability = '-dev'
      events[0]['introduced'] = str(parts[0])
      warnings.append('stability does not make sense, using -dev instead')

    if parts[1].operator == '<':
      events.append({'fixed': str(parts[1])})
    elif parts[1].operator == '<=':
      events.append({'last_affected': str(parts[1])})
    else:
      warnings.append(
        f'the {parts[1].operator} operator should not be used for the second part'
      )

  return events, list(dict.fromkeys(warnings))


def build_affected_range(constraint: str) -> osv.Range:
  events, _warnings = parse_version_constraint(constraint)

  return {
    'type': 'ECOSYSTEM',
    'events': events,
    'database_specific': {'constraint': constraint},
  }


def build_affected_ranges(sa_advisory: drupal.Advisory) -> list[osv.Range]:
  if sa_advisory['field_affected_versions'] is None:
    raise Exception(
      'field_affected_versions must be present to determine affected ranges'
    )

  return [
    build_affected_range(constraint.strip())
    for constraint in sa_advisory['field_affected_versions'].split('||')
  ]


def get_credits_from_sa(credits: drupal.RichTextField) -> list[osv.Credit]:
  credit_list: list[osv.Credit] = []

  # Sanity checks.
  if len(credits) == 0 or 'value' not in credits:
    return credit_list
  # The credits['value'] is a sting with an ordered list of credits.
  # A credit is a link to the user's profile on drupal.org with the user's name as the link text.
  for credit in (
    credits['value'].replace('<ul>', '').replace('</ul>', '').strip().split('<li>')
  ):
    credit = credit.replace('</li>', '').strip()
    if '<a' in credit:
      href = credit.split('href="')[1].split('"')[0]
      name = credit.split('">')[1].split('</a>')[0]
      credit_list.append({'name': name, 'contact': [href]})

  return credit_list


def composer_package(project: drupal.Project) -> str:
  project_type = 'drupal'
  project_name = project['field_project_machine_name']
  if project_name == 'drupal':
    project_name = 'core'
  return f'{project_type}/{project_name}'


def build_osv_advisory(
  sa_id: str,
  sa_advisory: drupal.Advisory,
) -> osv.Vulnerability | None:
  """
  Builds a representation of the given Drupal SA advisory in OSV format
  """

  # we expect that the downloader has excluded PSA type entries, but
  # we still guard against them here just in case one slips through
  if sa_advisory['field_is_psa'] == '1':
    print(' \\- skipping as it is a psa? (this should not happen)')
    return None

  # there's not really much we can do if there isn't an affected version
  # todo: since build_affected_ranges throws if this isn't present, it might
  #  make more sense to use that, with a custom exception class
  if sa_advisory['field_affected_versions'] is None:
    print(' \\- skipping as we do not have any affected versions')
    return None

  osv_advisory: osv.Vulnerability = {
    'schema_version': '1.3.0',
    'id': f'OSV-{sa_id}',
    'modified': datetime.fromtimestamp(int(sa_advisory['changed'])).strftime(
      '%Y-%m-%dT%H:%M:%S.000Z'
    ),
    'published': datetime.fromtimestamp(int(sa_advisory['created'])).strftime(
      '%Y-%m-%dT%H:%M:%S.000Z'
    ),
    'aliases': sa_advisory['field_sa_cve'],
    'related': [],
    'summary': '',
    'details': markdownify(sa_advisory['field_sa_description']['value']),
    'affected': [
      {
        # todo: figure out if we need a dedicated ecosystem i.e. Drupal, Drupal8, etc
        'package': {'ecosystem': 'Packagist', 'name': ''},
        # todo: figure out how to map field_sa_criticality to severity
        #  https://ossf.github.io/osv-schema/#severitytype-field
        #  https://www.drupal.org/drupal-security-team/security-risk-levels-defined
        #  https://www.nist.gov/news-events/news/2012/07/software-features-and-inherent-risks-nists-guide-rating-software
        'severity': [],
        'ranges': build_affected_ranges(sa_advisory),
        'database_specific': {
          'affected_versions': sa_advisory['field_affected_versions']
        },
      }
    ],
    'references': [{'type': 'WEB', 'url': sa_advisory['url']}],
    'credits': get_credits_from_sa(sa_advisory['field_sa_reported_by']),
  }
  project = typing.cast(
    drupal.Project, fetch_drupal_node(sa_advisory['field_project']['id'])
  )

  osv_advisory['affected'][0]['package']['name'] = composer_package(project)

  return osv_advisory


def fetch_affected_packages(osv_advisory: osv.Vulnerability) -> list[str]:
  return [affected['package']['name'] for affected in osv_advisory['affected']]


def generate_osv_advisories() -> None:
  for file in os.scandir('cache/advisories'):
    if not file.is_file() or not file.name.endswith('.json'):
      continue

    with open(file.path) as f:
      sa_advisory: drupal.Advisory = json.load(f)
    print(f'processing {sa_advisory["url"]}')
    sa_id = file.name.removesuffix('.json')
    osv_advisory = build_osv_advisory(sa_id, sa_advisory)

    if osv_advisory is None:
      continue

    affected_packages = fetch_affected_packages(osv_advisory)

    if len(affected_packages) == 0:
      raise Exception('osv advisory has no affected packages')

    for affected_package in affected_packages:
      name = affected_package.removeprefix('drupal/')
      os.makedirs(f'advisories/{name}', exist_ok=True)
      # todo: drop the osv- and keep the uppercasing
      file_name = f'osv-{sa_id.lower()}'
      with open(f'advisories/{name}/{file_name}.json', 'w') as f:
        json.dump(osv_advisory, f, indent=2)
        f.write('\n')


if __name__ == '__main__':
  generate_osv_advisories()
