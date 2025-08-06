#!/usr/bin/env python

"""
Downloads Drupal SA advisories using the REST API.

By default, only advisories that have been modified since the
most recent changed time out of all the existing SA advisories
"""

import json
import os
import typing

import requests

from typings import drupal
from user_agent import user_agent


def get_most_recent_changed_timestamp() -> int:
  """
  Determines the timestamp of the most recently changed SA advisory
  """
  most_recent_changed = 0
  try:
    for file in os.scandir('cache/advisories'):
      if not file.is_file() or not file.name.endswith('.json'):
        continue
      with open(file.path) as f:
        advisory = typing.cast(drupal.Advisory, json.load(f))
        changed = int(advisory['changed'])
        if changed > most_recent_changed or most_recent_changed == 0:
          most_recent_changed = changed
  except FileNotFoundError:
    pass
  return most_recent_changed


def determine_sa_id(advisory: drupal.Advisory) -> str:
  return advisory['url'].split('/')[-1].upper()


def download_sa_advisories_from_rest_api(last_modified_timestamp: int) -> None:
  """
  Downloads the Drupal SA advisories that have been modified since the given
  timestamp using the REST API, storing them on disk as JSON files
  """
  os.makedirs('cache/advisories', exist_ok=True)

  print(f'fetching sa advisories modified after {last_modified_timestamp}')
  url = 'https://www.drupal.org/api-d7/node.json?type=sa&sort=changed&direction=DESC&field_is_psa=0'
  while url != '':
    print(f'fetching {url}')
    response = requests.get(url, headers={'user-agent': user_agent})
    if response.status_code != 200:
      print(f'X API responded {response.status_code}')
      break
    data: drupal.ApiResponse[drupal.Advisory] = response.json()
    for item in data['list']:
      changed = int(item['changed'])
      if changed <= last_modified_timestamp:
        # We have reached the last modified entry.
        url = ''
        break
      advisory_id = determine_sa_id(item)
      print(
        f' |- updating cache/advisories/{advisory_id}.json as {item["url"]} has changed'
      )
      with open(f'cache/advisories/{advisory_id}.json', 'w') as f:
        json.dump(item, f)
        f.write('\n')
    print(' \\- finished processing page')
    if 'next' in data and data['next'] != '':
      url = data['next'].replace('api-d7/node?', 'api-d7/node.json?')
  print('finished processing new and updated advisories')


most_recent_changed_time = get_most_recent_changed_timestamp()
download_sa_advisories_from_rest_api(most_recent_changed_time)
