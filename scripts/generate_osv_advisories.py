#!/usr/bin/env python

"""
Generates OSV advisories from Drupal SA advisories stored on disk as JSON.

The advisories should be downloaded using the `scripts/download_sa_advisories.py`
"""

import json
import os
from datetime import datetime

import requests
import semver

from typings import drupal, osv

osv_dir_name = 'advisories'
# Not all fields pass the schema test as there are elements that are not yet present in the OSV schema.
full_proposed_entry = False


def osv_template(sa_id: str) -> osv.Vulnerability:
  """
  Builds a dict representing an osv with some initial fields prefilled
  """
  return {
    'schema_version': '1.3.0',
    'id': '',
    'modified': '',
    'published': '',
    'aliases': [],
    'related': [],
    'summary': '',
    'details': '',
    'affected': [
      {
        'package': {'ecosystem': 'Drupal', 'name': ''},
        'severity': [{'type': 'NIST_CMSS', 'score': ''}],
        'ranges': [
          {
            'type': 'ECOSYSTEM',
            'events': [
              # {
              #     "introduced": cve['containers']['cna']['affected'][0]['versions'][0]['version']
              # },
              # {
              #     "fixed": cve['containers']['cna']['affected'][0]['versions'][0]['version']
              # }
            ],
          }
        ],
      }
    ],
    'references': [
      # {
      #     "type": "WEB",
      #     "url": ''
      # }
    ],
    'credits': [],
  }


def fetch_url_to_file(url, file_path):
  if os.path.exists(file_path):
    # print(f"File {file_path} already exists. Skipping fetch.")
    return

  response = requests.get(url)
  if response.status_code == 200:
    with open(file_path, 'wb') as file:
      file.write(response.content)
    print(f'Content fetched from {url} and written to {file_path}')
  else:
    print(f'Failed to fetch content from {url}. Status code: {response.status_code}')


# Fetch a node from drupal.org
def get_node(nid: str, type) -> drupal.ApiResponse:
  dir = 'files'
  if not os.path.exists('files'):
    os.mkdir(dir)
  sa_url = f'https://www.drupal.org/api-d7/node.json?nid={nid}'
  sa_file = f'{dir}/{type}-{nid}.json'
  fetch_url_to_file(sa_url, sa_file)
  return json.loads(open(sa_file).read())


# Fetch the project node from drupal.org
def get_project_entry(nid: str) -> drupal.ApiResponse[drupal.ProjectModule]:
  return get_node(nid, 'project_module')


# Fetch the Project Release node from drupal.org
def get_fixed_in_entry(nid: str) -> drupal.ApiResponse[drupal.ProjectRelease]:
  return get_node(nid, 'project_release')


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
    introduced = versions.split()[0].strip()
    if introduced[0] == '<':
      introduced = '0.0.0'
    introduced = introduced.replace('*', '0')
    affected.append({'introduced': introduced})
    if len(versions.split()) > 1:
      # It looks like Core does not have field_fixed_in populated. Add a
      # fixed version from this string if we can.
      fixed = versions.split()[1].replace('<', '').replace('=', '').strip()
      affected.append({'fixed': fixed})
  return affected


def fake_ecosystem(osv_entry: osv.Vulnerability):
  if not full_proposed_entry:
    # Fake the package.ecosystem so a schema validator doesn't complain.
    for affected in osv_entry['affected']:
      affected['package']['ecosystem'] = 'Packagist'
    # Fake the ID so it passes the schema validation.
    osv_entry['id'] = f'OSV-{osv_entry["id"]}'
  return osv_entry


def add_fixed_in_versions(
  affected_versions: list[osv.Event],
  fixed_in_json: list[drupal.ApiResponse[drupal.ProjectRelease]],
):
  for fixed_in in fixed_in_json:
    for fixed_version in fixed_in['list']:
      fixed_major = fixed_version['field_release_version_major']
      fixed_minor = fixed_version['field_release_version_minor']
      fixed_patch = fixed_version['field_release_version_patch'] or '0'
      fixed_in_semver = f'{fixed_major}.{fixed_minor}.{fixed_patch}'
      affected_versions.append({'fixed': fixed_in_semver})
  return affected_versions


def semver_for_sorting(semver):
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


def sort_affected_versions(affected_versions: list[osv.Event]):
  sorted_versions = {}
  return_values = []
  for affected in affected_versions:
    if 'introduced' in affected.keys():
      sorted_versions[semver_for_sorting(affected['introduced'])] = affected
    if 'fixed' in affected.keys():
      sorted_versions[semver_for_sorting(affected['fixed'])] = affected

  # sort the dict by the keys assuming the keys are semver strings.
  sorted_versions = dict(
    sorted(sorted_versions.items(), key=lambda item: semver.parse_version_info(item[0]))
  )
  for key in sorted_versions.keys():
    return_values.append(sorted_versions[key])

  return return_values


def get_credits_from_sa(credits):
  credit_list = []

  # Sanity checks.
  if len(credits) == 0 or 'value' not in credits.keys():
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


def composer_package(project_json: drupal.ApiResponse[drupal.ProjectModule]) -> str:
  project_type = 'drupal'
  project_name = project_json['list'][0]['field_project_machine_name']
  if project_name == 'drupal':
    project_name = 'core'
  return f'{project_type}/{project_name}'


def build_osv_advisory(
  sa_id: str,
  sa_json: drupal.Advisory,
) -> osv.Vulnerability | None:
  """
  Builds a representation of the given Drupal SA advisory in OSV format
  """

  # we expect that the downloader has excluded PSA type entries, but
  # we still guard against them here just in case one slips through
  if sa_json['field_is_psa'] == '1':
    # todo: warn that we somehow got a psa type here
    print(f'Skipping PSA: {sa_json["title"]}')
    return None

  # there's not really much we can do if there isn't an affected version
  if sa_json['field_affected_versions'] is None:
    print(f'Skipping SA without affected versions: {sa_json["title"]}')
    print(f'SA URL: {sa_json["url"]}')
    return None

  osv_entry: osv.Vulnerability = osv_template(sa_id)
  project_json: drupal.ApiResponse[drupal.ProjectModule] | None = None
  fixed_in_json: list[drupal.ApiResponse[drupal.ProjectRelease]] = []

  if sa_json['field_project']['id'] != '0':
    project_json = get_project_entry(sa_json['field_project']['id'])

  if len(sa_json['field_fixed_in']) > 0:
    for fixed_in in sa_json['field_fixed_in']:
      fixed_in_json.append(get_fixed_in_entry(fixed_in['id']))

  if 'field_sa_reported_by' in sa_json.keys():
    osv_entry['credits'] = get_credits_from_sa(sa_json['field_sa_reported_by'])

  osv_entry['id'] = f'{sa_id}'

  # TODO: Add the severity to the OSV entry.
  # https://ossf.github.io/osv-schema/#severitytype-field
  # https://www.drupal.org/drupal-security-team/security-risk-levels-defined
  # https://www.nist.gov/news-events/news/2012/07/software-features-and-inherent-risks-nists-guide-rating-software
  if full_proposed_entry:
    osv_entry['affected'][0]['severity'][0]['score'] = sa_json['field_sa_criticality']
  else:
    osv_entry['affected'][0]['severity'] = []

  osv_entry['affected'][0]['package']['name'] = composer_package(project_json)
  osv_entry['published'] = datetime.fromtimestamp(int(sa_json['created'])).strftime(
    '%Y-%m-%dT%H:%M:%S.000Z'
  )
  osv_entry['modified'] = datetime.fromtimestamp(int(sa_json['changed'])).strftime(
    '%Y-%m-%dT%H:%M:%S.000Z'
  )

  affected_versions = parse_affected_versions(sa_json['field_affected_versions'])
  affected_versions = add_fixed_in_versions(affected_versions, fixed_in_json)
  affected_versions = sort_affected_versions(affected_versions)
  if len(affected_versions) > 0:
    for affected in affected_versions:
      for [event, version] in affected.items():
        osv_entry['affected'][0]['ranges'][0]['events'].append({event: version})

  if len(sa_json['field_sa_cve']) > 0:
    for cve in sa_json['field_sa_cve']:
      osv_entry['aliases'].append(cve)

  osv_entry['details'] = sa_json['field_sa_description']['value']
  osv_entry['references'].append({'type': 'WEB', 'url': sa_json['url']})

  fake_ecosystem(osv_entry)

  return osv_entry


def fetch_affected_packages(osv_advisory: dict) -> list[str]:
  return [affected['package']['name'] for affected in osv_advisory['affected']]


def generate_osv_advisories():
  for file in os.scandir('cache/advisories'):
    if not file.is_file() or not file.name.endswith('.json'):
      continue

    print(f'processing {file.path}')

    data = open(file.path, 'r').read()
    sa_advisory = json.loads(data)
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
      open(f'advisories/{name}/{file_name}.json', 'w').write(
        json.dumps(osv_advisory, indent=2)
      )


generate_osv_advisories()
