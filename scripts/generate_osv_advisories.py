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

from typings import drupal, osv

osv_dir_name = 'advisories'
# Not all fields pass the schema test as there are elements that are not yet present in the OSV schema.
full_proposed_entry = False


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
  if version == '0' or '-' in version:
    return version
  components = version.split('.')
  while len(components) < 3:
    components.append('0')
  return '.'.join(components)


# parse the affected versions string into a list of affected versions given a string like '>=3.0.0 <3.44.0 || >=4.0.0 <4.0.19'
def parse_affected_versions(affected_versions: str) -> list[osv.Event]:
  affected: list[osv.Event] = []
  for versions in affected_versions.split(' || '):
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
    affected.append({'introduced': expand_version(introduced)})
    if len(parts) > 1:
      # It looks like Core does not have field_fixed_in populated. Add a
      # fixed version from this string if we can.
      fixed = parts[1].replace('<', '').replace('=', '').strip()
      affected.append({'fixed': expand_version(fixed)})
    elif parts[0][0] == '<':
      affected.append({'fixed': expand_version(parts[0][1:])})

  return affected


def fake_ecosystem(osv_advisory: osv.Vulnerability) -> osv.Vulnerability:
  if not full_proposed_entry:
    # Fake the package.ecosystem so a schema validator doesn't complain.
    for affected in osv_advisory['affected']:
      affected['package']['ecosystem'] = 'Packagist'
    # Fake the ID so it passes the schema validation.
    osv_advisory['id'] = f'OSV-{osv_advisory["id"]}'
  return osv_advisory


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


def sort_affected_versions(affected_versions: list[osv.Event]) -> list[osv.Event]:
  sorted_versions = {}
  return_values = []
  for affected in affected_versions:
    if 'introduced' in affected:
      sorted_versions[semver_for_sorting(affected['introduced'])] = affected
    if 'fixed' in affected:
      sorted_versions[semver_for_sorting(affected['fixed'])] = affected

  # sort the dict by the keys assuming the keys are semver strings.
  sorted_versions = dict(
    sorted(sorted_versions.items(), key=lambda item: semver.parse_version_info(item[0]))
  )
  for key in sorted_versions:
    return_values.append(sorted_versions[key])

  return return_values


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
  if sa_advisory['field_affected_versions'] is None:
    print(' \\- skipping as we do not have any affected versions')
    return None

  osv_advisory: osv.Vulnerability = {
    'schema_version': '1.3.0',
    'id': sa_id,
    'modified': datetime.fromtimestamp(int(sa_advisory['changed'])).strftime(
      '%Y-%m-%dT%H:%M:%S.000Z'
    ),
    'published': datetime.fromtimestamp(int(sa_advisory['created'])).strftime(
      '%Y-%m-%dT%H:%M:%S.000Z'
    ),
    'aliases': sa_advisory['field_sa_cve'],
    'related': [],
    'summary': '',
    'details': sa_advisory['field_sa_description']['value'],
    'affected': [
      {
        'package': {'ecosystem': 'Drupal', 'name': ''},
        'severity': [{'type': 'NIST_CMSS', 'score': ''}],
        'ranges': [
          {
            'type': 'ECOSYSTEM',
            'events': [],
          }
        ],
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

  # TODO: Add the severity to the OSV entry.
  # https://ossf.github.io/osv-schema/#severitytype-field
  # https://www.drupal.org/drupal-security-team/security-risk-levels-defined
  # https://www.nist.gov/news-events/news/2012/07/software-features-and-inherent-risks-nists-guide-rating-software
  if full_proposed_entry:
    osv_advisory['affected'][0]['severity'][0]['score'] = sa_advisory[
      'field_sa_criticality'
    ]
  else:
    osv_advisory['affected'][0]['severity'] = []

  osv_advisory['affected'][0]['package']['name'] = composer_package(project)

  affected_versions = parse_affected_versions(sa_advisory['field_affected_versions'])
  affected_versions = sort_affected_versions(affected_versions)
  for event in affected_versions:
    osv_advisory['affected'][0]['ranges'][0]['events'].append(event)

  fake_ecosystem(osv_advisory)

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


generate_osv_advisories()
