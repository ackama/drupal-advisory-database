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

osv_dir_name = 'advisories'
cache_dir_name = 'cache/advisories'


def get_most_recent_changed_timestamp() -> int:
  """
  Determines the timestamp of the most recently changed SA advisory
  """
  most_recent_changed = 0
  for file in os.scandir(cache_dir_name):
    if not file.is_file() or not file.name.endswith('.json'):
      continue
    with open(file.path) as f:
      advisory = typing.cast(drupal.Advisory, json.load(f))
      changed = int(advisory['changed'])
      if changed > most_recent_changed or most_recent_changed == 0:
        most_recent_changed = changed
  return most_recent_changed


def determine_sa_id(advisory: drupal.Advisory) -> str:
  return advisory['url'].split('/')[-1].upper()


def download_sa_advisories_from_rest_api(last_modified_timestamp: int):
  """
  Downloads the Drupal SA advisories that have been modified since the given
  timestamp using the REST API, storing them on disk as JSON files
  """
  os.makedirs(cache_dir_name, exist_ok=True)

  url = 'https://www.drupal.org/api-d7/node.json?type=sa&sort=changed&direction=DESC&field_is_psa=0'
  fetch_again = True
  while fetch_again:
    print(f'Fetching {url}')
    response = requests.get(url)
    print(f'Status code: {response.status_code}')
    if response.status_code == 200:
      data: drupal.ApiResponse = response.json()
      for item in data['list']:
        changed = int(item['changed'])
        if changed > last_modified_timestamp:
          advisory_id = determine_sa_id(item)
          with open(f'{cache_dir_name}/{advisory_id}.json', 'w') as f:
            json.dump(item, f)
        else:
          # We have reached the last modified entry.
          fetch_again = False
      if 'next' in data and data['next'] != '':
        url = data['next'].replace('api-d7/node?', 'api-d7/node.json?')
      else:
        print('No more pages to fetch.')
        fetch_again = False
    else:
      print(f'Failed to fetch data from {url}. Status code: {response.status_code}')
      fetch_again = False


last_modified_timestamp = get_most_recent_changed_timestamp()
download_sa_advisories_from_rest_api(last_modified_timestamp)
