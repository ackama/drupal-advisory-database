#!/usr/bin/env python

"""
Precaches the Drupal nodes used by SA advisories,
to help reduce the pressure on the drupal.org api
"""

import json
import os
import typing
from itertools import batched

import requests

from typings import drupal


def fetch_drupal_nodes(nids: list[str]) -> list[drupal.Node]:
  """
  Fetches a node from drupal.org by its id
  """
  url = 'https://www.drupal.org/api-d7/node.json?'

  for nid in nids:
    url += f'nid[]={nid}&'

  resp = requests.get(url)

  if resp.status_code == 200:
    items = typing.cast(drupal.ApiResponse, resp.json())['list']

    if len(items) != len(nids):
      raise Exception(f'API returned {len(items)} nodes but expected {len(nids)}')
    return items
  raise Exception(f'unexpected response when fetching nodes {nids}: {resp.status_code}')


def fetch_and_cache_drupal_nodes():
  """
  Ensures all the drupal.org nodes used by the downloaded advisories are cached
  locally, using the bulk collection api endpoint to retrieve them 50 at a time
  """
  ids = set()

  os.makedirs('cache/nodes', exist_ok=True)

  for file in os.scandir('cache/advisories'):
    if not file.is_file() or not file.name.endswith('.json'):
      continue

    with open(file.path) as f:
      sa_advisory = json.load(f)
    ids.add(sa_advisory['field_project']['id'])

    for fixed_in in sa_advisory['field_fixed_in']:
      ids.add(fixed_in['id'])

  for i, batch in enumerate(batched(ids, 50, strict=False)):
    print(f'fetching {len(batch)} nodes ({len(ids) - i * 50 - len(batch)} remaining)')
    for node in fetch_drupal_nodes(list(batch)):
      print(f' |- writing cache/nodes/{node["nid"]}.json')
      with open(f'cache/nodes/{node["nid"]}.json', 'w') as f:
        json.dump(node, f)
        f.write('\n')


fetch_and_cache_drupal_nodes()
