#!/usr/bin/env python

"""
Downloads Drupal SA advisories using the REST API.

By default, only advisories that have been modified since the
most recent modification to an OSV advisory will be downloaded
"""

import json
import os
import time
from datetime import datetime

import requests

from typings import drupal

osv_dir_name = 'advisories'
cache_dir_name = 'cache/advisories'


def datetime_to_timestamp(date_str: str) -> int:
  return int(
    time.mktime(datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ').timetuple())
  )


def get_last_osv_modified_timestamp() -> int:
  """
  Determines the timestamp of the most recently modified OSV advisory
  """
  highest_modified = 0
  for root, _, files in os.walk(osv_dir_name):
    for file in files:
      if file.endswith('.json'):
        # Load the contents of the file into a dictionary.
        osv = json.loads(open(os.path.join(root, file)).read())
        modified = datetime_to_timestamp(osv['modified'])
        if modified > highest_modified or highest_modified == 0:
          highest_modified = modified
  return highest_modified


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
          open(f'{cache_dir_name}/{advisory_id}.json', 'w').write(json.dumps(item))
        else:
          # We have reached the last modified entry.
          fetch_again = False
      if 'next' in data.keys() and data['next'] != '':
        url = data['next'].replace('api-d7/node?', 'api-d7/node.json?')
      else:
        print('No more pages to fetch.')
        fetch_again = False
    else:
      print(f'Failed to fetch data from {url}. Status code: {response.status_code}')
      fetch_again = False


last_modified_timestamp = get_last_osv_modified_timestamp()
download_sa_advisories_from_rest_api(last_modified_timestamp)
