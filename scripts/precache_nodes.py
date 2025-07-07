#!/usr/bin/env python

"""
Precaches the Drupal nodes used by SA advisories,
to help reduce the pressure on the drupal.org api
"""

import json
import os
import time
import typing
from itertools import batched

import requests

import utils
from typings import drupal
from user_agent import user_agent


def fetch_drupal_nodes(nids: list[str], retry: bool = True) -> list[drupal.Node]:
  """
  Fetches a node from drupal.org by its id
  """
  url = 'https://www.drupal.org/api-d7/node.json?'

  for nid in nids:
    url += f'nid[]={nid}&'

  resp = requests.get(url, headers={'user-agent': user_agent})

  if retry and resp.status_code == 429:
    seconds = int(resp.headers.get('Retry-After', 0))
    print(f' |* (waiting {seconds} seconds before retrying)')
    time.sleep(seconds)

    return fetch_drupal_nodes(nids, retry=False)

  if resp.status_code == 200:
    items = typing.cast(drupal.ApiResponse[drupal.Node], resp.json())['list']

    if len(items) != len(nids):
      raise Exception(f'API returned {len(items)} nodes but expected {len(nids)}')
    return items
  raise Exception(f'unexpected {resp.status_code} response when fetching nodes {nids}')


def fetch_and_cache_drupal_nodes() -> None:
  """
  Ensures all the drupal.org nodes used by the downloaded advisories are cached
  locally, using the bulk collection api endpoint to retrieve them 50 at a time
  """
  ids = set[str]()

  os.makedirs('cache/nodes', exist_ok=True)

  for file in os.scandir('cache/advisories'):
    if not file.is_file() or not file.name.endswith('.json'):
      continue

    sa_advisory = utils.load_sa_advisory(file.path)

    if sa_advisory['field_project'] is not None:
      ids.add(sa_advisory['field_project']['id'])

  for i, batch in enumerate(batched(ids, 50, strict=False)):
    print(f'fetching {len(batch)} nodes ({len(ids) - i * 50 - len(batch)} remaining)')
    for node in fetch_drupal_nodes(list(batch)):
      print(f' |- writing cache/nodes/{node["nid"]}.json')
      with open(f'cache/nodes/{node["nid"]}.json', 'w') as f:
        json.dump(node, f)
        f.write('\n')


fetch_and_cache_drupal_nodes()
