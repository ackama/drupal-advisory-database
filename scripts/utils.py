import json

from typings import drupal


def load_sa_advisory(file_path: str) -> drupal.Advisory:
  """
  Loads a Drupal advisory from a json file stored on disk, making some adjustments
  in the process to make it easier to work with
  """
  with open(file_path) as f:
    raw_advisory: drupal.AdvisoryRaw = json.load(f)

  # noinspection PyTypeChecker
  # https://youtrack.jetbrains.com/issue/PY-58714/False-positive-TypedDict-has-missing-key-when-using-unpacking
  sa_advisory: drupal.Advisory = {
    **raw_advisory,
    'field_project': None,
    'field_sa_reported_by': {'format': '1', 'value': ''},
    'field_sa_description': {'format': '1', 'value': ''},
  }

  if isinstance(raw_advisory['field_project'], dict):
    sa_advisory['field_project'] = raw_advisory['field_project']

  if isinstance(raw_advisory['field_sa_reported_by'], dict):
    sa_advisory['field_sa_reported_by'] = raw_advisory['field_sa_reported_by']

  if isinstance(raw_advisory['field_sa_description'], dict):
    sa_advisory['field_sa_description'] = raw_advisory['field_sa_description']

  return sa_advisory
