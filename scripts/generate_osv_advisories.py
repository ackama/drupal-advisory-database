#!/usr/bin/env python

"""
Generates OSV advisories from Drupal SA advisories stored on disk as JSON.

The advisories should be downloaded using the `scripts/download_sa_advisories.py`
"""

import json
import os
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


def parse_version_constraint(versions: str) -> tuple[list[osv.Event], list[str]]:
  """
  Parses a version constraint into a series of events that express what versions
  are and are not affected by the advisory the constraint was sourced from,
  along with any warnings about the constraints validity
  """
  events: list[osv.Event] = []
  # split version on space and append the first element to the affected list after removing any > or >= characters.
  versions = (
    versions.replace('>=', '')
    .replace('>', '')
    .replace('< ', '<')
    .replace('= ', '=')
    .strip()
  )
  parts = [part.strip() for part in versions.split()]
  introduced = parts[0]
  if introduced[0] == '<':
    introduced = '0'
  introduced = introduced.replace('*', '0')
  events.append({'introduced': expand_version(introduced)})
  if len(parts) > 1:
    # It looks like Core does not have field_fixed_in populated. Add a
    # fixed version from this string if we can.
    fixed = parts[1].replace('<', '').replace('=', '').strip()
    events.append({'fixed': expand_version(fixed)})
  elif parts[0][0] == '<':
    events.append({'fixed': expand_version(parts[0][1:])})

  return events, []


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

  ranges = [
    build_affected_range(constraint.strip())
    for constraint in sa_advisory['field_affected_versions'].split('||')
  ]

  return sorted(
    ranges,
    key=lambda ran: (event_to_semver_for_sorting(ran['events'][0])),
  )


def event_to_semver_for_sorting(event: osv.Event) -> semver.Version:
  version = '0.0.0'
  if 'introduced' in event:
    version = event['introduced']
  elif 'fixed' in event:
    version = event['fixed']
  return semver.Version.parse(semver_for_sorting(version))


def semver_for_sorting(semver: typing.Any) -> str:
  decrement_semver = False
  if semver == '':
    return ''
  # Check if the semver string starts with a '<' character.
  if semver[0] == '<':
    decrement_semver = True
    semver = semver[1:]
  semver = semver.strip().split('.')
  # sanity check the length of the introduced value.
  while len(semver) < 3:
    semver.append('0')

  for i in range(3):
    if semver[i].isnumeric():
      semver[i] = int(semver[i])
    else:
      semver[i] = 0

  if decrement_semver:
    if semver[2] > 0:
      semver[2] -= 1
    elif semver[1] > 0:
      semver[1] -= 1

  semver_major = semver[0]
  semver_minor = semver[1]
  semver_patch = semver[2]
  return f'{semver_major}.{semver_minor}.{semver_patch}'


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
