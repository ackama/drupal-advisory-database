# Drupal Advisory Database

A community-driven database of known security vulnerabilities in Drupal packages
sourced from [drupal.org](https://www.drupal.org/security) using the
[OSV](https://ossf.github.io/osv-schema/) format.

The data is primarily sourced using the drupal.org
[REST API](https://www.drupal.org/drupalorg/docs/apis/rest-and-other-apis).

## Using this database

This database can be used by any tool that supports ingesting OSV advisories.

If you are using [`osv-detector`](https://github.com/G-Rath/osv-detector), you
can configure this database as an
[extra database](https://github.com/G-Rath/osv-detector?tab=readme-ov-file#extra-databases)

## Updating the advisories

Advisories are managed through a series of Python scripts that live in the
`scripts` directory - to use these, you need to install the dependencies listed
in `pyproject.toml` using
[`poetry`](https://python-poetry.org/docs/#installation).

```shell
# 1. download the Drupal SA advisories from drupal.org
poetry run scripts/download_sa_advisories.py

# 2. download nodes from drupal.org related to the advisories
# (this is not required, but will significantly improve performance of the next step)
poetry run scripts/precache_nodes.py

# 3. generate the OSV advisories based on the Drupal advisories
poetry run scripts/generate_osv_advisories.py
```
