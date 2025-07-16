#!/usr/bin/env python

import json
import os
import typing
from textwrap import indent

import jsonschema

from typings import osv

report_valid = False

with open('schema.json') as f:
  schema = json.load(f)
  jsonschema.Draft202012Validator.check_schema(schema)
  validator = jsonschema.Draft202012Validator(schema)

total = 0
passed = 0


def load_advisory_data(path_to_advisory: str) -> osv.Vulnerability:
  with open(path_to_advisory) as fi:
    return typing.cast(osv.Vulnerability, json.load(fi))


def has_database_specific_warnings(vuln: osv.Vulnerability) -> bool:
  if len(vuln.get('database_specific', {}).get('warnings', [])) > 0:
    return True

  for affected in vuln['affected']:
    if len(affected.get('database_specific', {}).get('warnings', [])) > 0:
      return True
    for ran in affected['ranges']:
      if len(ran.get('database_specific', {}).get('warnings', [])) > 0:
        return True
  return False


for dirpath, _, filenames in os.walk('advisories'):
  for filename in filenames:
    advisory_filepath = os.path.join(dirpath, filename)
    total += 1

    try:
      data = load_advisory_data(advisory_filepath)

      validator.validate(data)

      if has_database_specific_warnings(data):
        if 'CI' in os.environ:
          print(
            f'::warning file={advisory_filepath},line=1::has warnings that should be reviewed and patched if possible'
          )
        print(f'⚠️ {advisory_filepath} is valid with warnings')
      elif report_valid:
        print(f'✅ {advisory_filepath} is valid')
      passed += 1
    except (json.JSONDecodeError, jsonschema.ValidationError) as err:
      print(f'❌ {advisory_filepath} is invalid')
      print(indent(str(err), prefix='    '))

print(f'ℹ️ validated {total} advisories, with {total - passed} invalid')

if total != passed:
  exit(1)
