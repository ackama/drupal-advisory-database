#!/usr/bin/env python

import json
import os
from textwrap import indent

import jsonschema

report_valid = False

with open('schema.json') as f:
  schema = json.load(f)
  jsonschema.Draft202012Validator.check_schema(schema)
  validator = jsonschema.Draft202012Validator(schema)

total = 0
passed = 0

for dirpath, _, filenames in os.walk('advisories'):
  for filename in filenames:
    advisory = os.path.join(dirpath, filename)
    total += 1

    try:
      with open(advisory) as f:
        validator.validate(json.load(f))
      if report_valid:
        print(f'✅ {advisory} is valid')
      passed += 1
    except (json.JSONDecodeError, jsonschema.ValidationError) as err:
      print(f'❌ {advisory} is invalid')
      print(indent(str(err), prefix='    '))

print(f'ℹ️ validated {total} advisories, with {total - passed} invalid')

if total != passed:
  exit(1)
