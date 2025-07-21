#!/usr/bin/env python

"""
Downloads Drupal SA advisories using the Composer security advisory API.

By default, only advisories that have been modified since the
most recent changed time out of all the existing SA advisories
"""

import json
import os

import requests

from typings import composer
from user_agent import user_agent


def get_most_recent_changed_timestamp() -> int:
  """
  Determines the timestamp of the most recently changed SA advisory
  """
  most_recent_changed = 0
  try:
    for file in os.scandir('cache/composer'):
      if not file.is_file() or not file.name.endswith('.json'):
        continue
      changed = file.stat().st_mtime_ns
      if changed > most_recent_changed or most_recent_changed == 0:
        most_recent_changed = changed
  except FileNotFoundError:
    pass
  return most_recent_changed


def determine_sa_id(advisory: composer.Advisory) -> str:
  return advisory['advisoryId']


def download_sa_advisories_from_composer(last_modified_timestamp: int) -> None:
  """
  Downloads the Drupal SA advisories that have been modified since the given
  timestamp using the Composer repository API, storing them on disk as JSON files
  """
  os.makedirs('cache/composer', exist_ok=True)

  print(f'fetching sa advisories modified after {last_modified_timestamp}')
  url = f'https://packages.drupal.org/8/security-advisories/?updatedSince={last_modified_timestamp}'
  print(f'fetching {url}')

  response = requests.get(url, headers={'user-agent': user_agent})

  if response.status_code != 200:
    print(f'X API responded {response.status_code}')
    exit(1)

  data: composer.SecurityAdvisoriesResponse = response.json()

  all_advisories = data['advisories']

  if not isinstance(all_advisories, dict):
    all_advisories = {}

  for advisories in all_advisories.values():
    for item in advisories:
      advisory_id = determine_sa_id(item)
      print(
        f' |- updating cache/composer/{advisory_id}.json as {item["link"]} has changed'
      )
      with open(f'cache/composer/{advisory_id}.json', 'w') as f:
        json.dump(item, f)
        f.write('\n')
  print('finished processing new and updated advisories')


most_recent_changed_time = get_most_recent_changed_timestamp()
download_sa_advisories_from_composer(most_recent_changed_time)
